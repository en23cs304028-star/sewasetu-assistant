# -*- coding: utf-8 -*-
"""
mcp/officer.py: Block Officer MCP tools (5 tools)
Designed for queue triage, verification, decision making, and SLA monitoring.
"""

import os
from datetime import datetime, timedelta

import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
import services

SLA_DAYS = 15


def queue_summary(block=None):
    """Summarizes queue health, backlog, and deemed-approval urgency."""
    conn = services.get_db()
    cur = conn.cursor()

    where_block = " WHERE block = %s" if block else ""
    params = (block,) if block else ()

    # Status counts
    cur.execute("SELECT status, count(*) FROM applications" + where_block + " GROUP BY status", params)
    status_counts = dict(cur.fetchall())

    # SLA metrics for PENDING
    cur.execute(
        "SELECT id, application_no, submitted_at FROM applications "
        "WHERE status = 'PENDING'" + (" AND block = %s" if block else "") + " ORDER BY submitted_at ASC",
        params
    )
    pending_rows = cur.fetchall()

    oldest_days = 0
    urgent_count = 0  # within 48h of 15-day deemed approval cutoff
    now = datetime.now()

    for app_id, app_no, sub_at in pending_rows:
        if sub_at:
            age_days = (now - sub_at).days
            if age_days > oldest_days:
                oldest_days = age_days
            if age_days >= 13:  # 13+ days old is nearing 15-day statutory deemed approval
                urgent_count += 1

    cur.close()
    conn.close()

    return {
        "status": "success",
        "block_filter": block or "All Blocks",
        "total_pending": status_counts.get("PENDING", 0),
        "total_approved": status_counts.get("APPROVED", 0),
        "total_deemed_approved": status_counts.get("DEEMED_APPROVED", 0),
        "total_rejected": status_counts.get("REJECTED", 0),
        "total_withdrawn": status_counts.get("WITHDRAWN", 0),
        "oldest_pending_days": oldest_days,
        "nearing_deemed_approval_cutoff_count": urgent_count,
        "sla_statutory_limit_days": SLA_DAYS
    }


def list_applications(status="PENDING", block=None, order_by="oldest_first", page=1, limit=20):
    """Lists applications with pagination and urgency sorting."""
    conn = services.get_db()
    cur = conn.cursor()

    conditions = ["status = %s"]
    params = [status]
    if block:
        conditions.append("block = %s")
        params.append(block)

    where_clause = " WHERE " + " AND ".join(conditions)
    sort_order = "ASC" if order_by == "oldest_first" else "DESC"

    offset = (max(1, page) - 1) * limit
    params.extend([limit, offset])

    cur.execute(
        "SELECT id, application_no, applicant_name, village, block, submitted_at, status "
        "FROM applications" + where_clause +
        (" ORDER BY submitted_at %s LIMIT %%s OFFSET %%s" % sort_order),
        params
    )
    rows = cur.fetchall()

    now = datetime.now()
    results = []
    for r in rows:
        app_id, app_no, name, village, blk, sub_at, st = r
        days_pending = (now - sub_at).days if sub_at else 0
        sla_remaining = max(0, SLA_DAYS - days_pending)
        results.append({
            "id": app_id,
            "application_no": app_no,
            "applicant_name": name,
            "village": village,
            "block": blk,
            "submitted_at": sub_at.strftime("%d/%m/%Y") if sub_at else None,
            "days_pending": days_pending,
            "sla_remaining_days": sla_remaining,
            "urgent": days_pending >= 13
        })

    cur.close()
    conn.close()

    return {
        "status": "success",
        "page": page,
        "limit": limit,
        "count": len(results),
        "applications": results
    }


def get_application(app_id):
    """Returns complete dossier for an application including documents, audit trail, and flags."""
    conn = services.get_db()
    cur = conn.cursor()

    cur.execute(
        """SELECT id, application_no, applicant_name, mobile, dob, gender, marital_status,
                  husband_name, village, block, bank_account, ifsc, doc_path, status,
                  submitted_at, decided_at, decided_by
           FROM applications WHERE id = %s""",
        (app_id,)
    )
    row = cur.fetchone()
    if not row:
        cur.close()
        conn.close()
        return {"status": "error", "error": "Application #%s not found" % app_id}

    (aid, app_no, name, mobile, dob, gender, marital, h_name, village, block,
     bank_acc, ifsc, doc_path, status, sub_at, dec_at, dec_by) = row

    # Fetch audit trail
    cur.execute(
        "SELECT at, action, actor, note FROM audit_log WHERE application_id = %s ORDER BY at ASC",
        (app_id,)
    )
    audit_rows = cur.fetchall()
    audit_trail = [
        {
            "timestamp": at.strftime("%d/%m/%Y %H:%M:%S") if at else "",
            "action": act,
            "actor": actor,
            "note": note or ""
        }
        for at, act, actor, note in audit_rows
    ]

    # Check informational duplicate bank account flag
    cur.execute(
        "SELECT id, application_no, applicant_name FROM applications "
        "WHERE bank_account = %s AND id != %s AND status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED')",
        (bank_acc, app_id)
    )
    dup_banks = cur.fetchall()
    flags = []
    if dup_banks:
        flags.append({
            "type": "INFO_DUPLICATE_BANK_ACCOUNT",
            "message": "Bank account is also associated with %d other active application(s): %s" % (
                len(dup_banks), ", ".join(d[1] for d in dup_banks)
            )
        })

    cur.close()
    conn.close()

    age = None
    if dob:
        age = services.age_on(dob, datetime.now().date())

    return {
        "status": "success",
        "id": aid,
        "application_no": app_no,
        "applicant_name": name,
        "mobile": mobile,
        "date_of_birth": dob.strftime("%d/%m/%Y") if dob else None,
        "calculated_age": age,
        "gender": gender,
        "marital_status": marital,
        "husband_name": h_name,
        "village": village,
        "block": block,
        "bank_account": bank_acc,
        "ifsc": ifsc,
        "document_path": doc_path,
        "document_present": bool(doc_path and os.path.exists(doc_path)),
        "current_status": status,
        "submitted_at": sub_at.strftime("%d/%m/%Y %H:%M") if sub_at else None,
        "decided_at": dec_at.strftime("%d/%m/%Y %H:%M") if dec_at else None,
        "decided_by": dec_by,
        "informational_flags": flags,
        "audit_trail": audit_trail
    }


def approve_application(app_id, officer_username, note=""):
    """Approves a PENDING application, recording the officer in audit log."""
    conn = services.get_db()
    cur = conn.cursor()
    actor = "officer:%s" % (officer_username or "admin")
    audit_note = (note or "").strip()

    ok, msg, app_no = services.decide_application(cur, app_id, "APPROVED", actor, audit_note)
    if ok:
        conn.commit()
    else:
        conn.rollback()
    cur.close()
    conn.close()

    return {
        "status": "approved" if ok else "error",
        "application_id": app_id,
        "application_no": app_no,
        "message": msg
    }


def reject_application(app_id, officer_username, reason):
    """Rejects a PENDING application. A specific reason is mandatory."""
    if not (reason or "").strip():
        return {
            "status": "error",
            "error": "A specific reason is mandatory when rejecting an application.",
            "field": "reason"
        }

    conn = services.get_db()
    cur = conn.cursor()
    actor = "officer:%s" % (officer_username or "admin")
    audit_note = reason.strip()

    ok, msg, app_no = services.decide_application(cur, app_id, "REJECTED", actor, audit_note)
    if ok:
        conn.commit()
    else:
        conn.rollback()
    cur.close()
    conn.close()

    return {
        "status": "rejected" if ok else "error",
        "application_id": app_id,
        "application_no": app_no,
        "message": msg
    }
