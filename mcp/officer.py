# -*- coding: utf-8 -*-
"""
mcp/officer.py: Block Officer MCP tools (5 tools)
Designed for queue triage, verification, decision making, and SLA monitoring.
"""

import os
import re
import secrets
import hashlib
from datetime import datetime, timedelta

import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
try:
    import services
except ImportError:
    from app import services

SLA_DAYS = 15


def neutralize_untrusted(text, maxlen=100):
    """
    Strips NUL and ASCII control characters, neutralizes angle brackets (< and >),
    and wraps user-controlled input in explicit delimiters.
    """
    if text is None:
        return ""
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(text)).strip()[:maxlen]
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return f"<untrusted_user_input>{s}</untrusted_user_input>"


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
    """Lists applications with pagination and urgency sorting. Citizen free-text fields are delimited."""
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
        "SELECT id, application_no, applicant_name, village, block, submitted_at, status, bank_account, ifsc "
        "FROM applications" + where_clause +
        (" ORDER BY submitted_at %s LIMIT %%s OFFSET %%s" % sort_order),
        params
    )
    rows = cur.fetchall()

    now = datetime.now()
    results = []
    for r in rows:
        app_id, app_no, name, village, blk, sub_at, st, bank_acc, ifsc = r
        days_pending = (now - sub_at).days if sub_at else 0
        sla_remaining = max(0, SLA_DAYS - days_pending)
        results.append({
            "id": app_id,
            "application_no": app_no,
            "applicant_name": neutralize_untrusted(name, 100),
            "village": neutralize_untrusted(village, 100),
            "block": blk,
            "bank_account": ("XXXX-XXXX-" + str(bank_acc)[-4:]) if (bank_acc and len(str(bank_acc)) >= 4) else "XXXX",
            "ifsc": (str(ifsc)[:4] + "XXXXXXX") if ifsc else "XXXX",
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
    """Returns complete dossier for an application including documents, audit trail, and flags.
    Free-text citizen inputs are delimited in untrusted_citizen_data; bank details are masked to last 4 digits.
    """
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
            "note": neutralize_untrusted(note, 500) if note else ""
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

    masked_bank = ("XXXX-XXXX-" + str(bank_acc)[-4:]) if (bank_acc and len(str(bank_acc)) >= 4) else "XXXX"
    masked_ifsc = (str(ifsc)[:4] + "XXXXXXX") if ifsc else "XXXX"

    clean_name = neutralize_untrusted(name, 100)
    clean_village = neutralize_untrusted(village, 100)
    clean_h_name = neutralize_untrusted(h_name, 100) if h_name else None
    clean_block = re.sub(r"[\x00-\x1f\x7f]", "", str(block or "")).strip()[:100]

    untrusted_citizen_data = {
        "applicant_name": clean_name,
        "village": clean_village,
        "husband_name": clean_h_name,
        "block": clean_block
    }

    return {
        "status": "success",
        "id": aid,
        "application_no": app_no,
        "untrusted_citizen_data": untrusted_citizen_data,
        "applicant_name": clean_name,
        "mobile": mobile,
        "date_of_birth": dob.strftime("%d/%m/%Y") if dob else None,
        "calculated_age": age,
        "gender": gender,
        "marital_status": marital,
        "husband_name": clean_h_name,
        "village": clean_village,
        "block": clean_block,
        "bank_account": masked_bank,
        "ifsc": masked_ifsc,
        "document_path": doc_path,
        "document_present": bool(doc_path and os.path.exists(doc_path)),
        "current_status": status,
        "submitted_at": sub_at.strftime("%d/%m/%Y %H:%M") if sub_at else None,
        "decided_at": dec_at.strftime("%d/%m/%Y %H:%M") if dec_at else None,
        "decided_by": dec_by,
        "informational_flags": flags,
        "audit_trail": audit_trail
    }


def _decide_two_step(decision, app_id, officer_username, note_or_reason="", confirmation_token=None):
    """
    Executes two-step decision flow for officer tool calls:
    - Step 1 (no token): Validates application is PENDING, generates 5-minute single-use token in PostgreSQL,
      and returns confirmation summary. Changes nothing.
    - Step 2 (with token): Validates token against Postgres with row lock (FOR UPDATE), checks 30/min rate limit,
      atomically executes decision, marks token used, and records in audit log.
    """
    actor = "officer:%s" % (officer_username or "admin")
    conn = services.get_db()
    cur = conn.cursor()

    try:
        # Check application existence and status
        cur.execute("SELECT application_no, applicant_name, village, block, status FROM applications WHERE id = %s", (app_id,))
        app_row = cur.fetchone()
        if not app_row:
            cur.close()
            conn.close()
            return {"status": "error", "error": "Application #%s not found." % app_id, "message": "Application #%s not found." % app_id}

        app_no, name, village, block, current_status = app_row
        if current_status != "PENDING":
            cur.close()
            conn.close()
            return {
                "status": "error",
                "error": "Application %s is already decided (current status: %s)." % (app_no, current_status),
                "message": "Application %s is already decided (current status: %s)." % (app_no, current_status)
            }

        # Step 1: No confirmation token provided -> generate token and return summary
        if not confirmation_token:
            token = "conf_" + secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
            expires_at = datetime.now() + timedelta(minutes=5)
            sanitized_note = services.sanitize(note_or_reason, maxlen=500)

            cur.execute(
                """INSERT INTO confirmation_tokens
                   (token_hash, application_id, decision, officer_subject, reason, created_at, expires_at)
                   VALUES (%s, %s, %s, %s, %s, NOW(), %s)""",
                (token_hash, app_id, decision, actor, sanitized_note, expires_at)
            )
            conn.commit()
            cur.close()
            conn.close()

            field_name = "note" if decision == "APPROVED" else "reason"
            return {
                "status": "confirmation_required",
                "message": f"Confirmation required to {decision.lower()} application {app_no}. Please review the summary, confirm with the officer, and re-call with confirmation_token.",
                "application_id": app_id,
                "application_no": app_no,
                "decision": decision,
                "applicant_name": name,
                "village": village,
                "block": block,
                field_name: sanitized_note,
                "confirmation_token": token,
                "expires_in_seconds": 300
            }

        # Step 2: Confirmation token provided -> validate and execute
        # Rate limit decisions per officer: 30 per minute
        allowed, retry_after = services.check_rate_limit(conn, f"officer_decisions:{officer_username}", max_attempts=30, window_seconds=60)
        if not allowed:
            cur.close()
            conn.close()
            return {
                "status": "error",
                "error": f"Rate limit exceeded: maximum 30 decisions per minute per officer. Retry after {max(1, retry_after)} seconds."
            }

        token_hash = hashlib.sha256(confirmation_token.strip().encode("ascii")).hexdigest()
        cur.execute(
            """SELECT application_id, decision, officer_subject, reason, expires_at, used_at
               FROM confirmation_tokens
               WHERE token_hash = %s
               FOR UPDATE""",
            (token_hash,)
        )
        tok_row = cur.fetchone()
        if not tok_row:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": "Invalid confirmation_token."}

        t_app_id, t_dec, t_actor, t_reason, t_expires, t_used = tok_row
        if t_used is not None:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": "confirmation_token has already been used."}

        now = datetime.now()
        if t_expires.tzinfo is not None:
            now = datetime.now(t_expires.tzinfo)
        if now > t_expires:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": "confirmation_token has expired (5-minute TTL)."}

        if t_app_id != app_id:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": "confirmation_token does not match application_id."}

        if t_dec != decision:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": f"confirmation_token was issued for decision {t_dec}, not {decision}."}

        if t_actor != actor:
            conn.rollback()
            cur.close()
            conn.close()
            return {"status": "error", "error": "confirmation_token was issued to a different officer."}

        # Atomically mark token as used
        cur.execute("UPDATE confirmation_tokens SET used_at = NOW() WHERE token_hash = %s", (token_hash,))

        # Execute decision
        sanitized_note = services.sanitize(note_or_reason or t_reason or "", maxlen=500)
        ok, msg, app_no = services.decide_application(cur, app_id, decision, actor, sanitized_note)
        if ok:
            conn.commit()
            status_val = "approved" if decision == "APPROVED" else "rejected"
            res = {
                "status": status_val,
                "application_id": app_id,
                "application_no": app_no,
                "message": msg
            }
        else:
            conn.rollback()
            res = {
                "status": "error",
                "application_id": app_id,
                "application_no": app_no,
                "message": msg
            }
        cur.close()
        conn.close()
        return res

    except Exception as e:
        conn.rollback()
        cur.close()
        conn.close()
        raise e


def approve_application(app_id, officer_username, note="", confirmation_token=None):
    """Approves a PENDING application in two steps.
    Step 1 (no token): returns summary + single-use confirmation_token (5m TTL).
    Step 2 (with token): executes decision atomically, writing audit log.
    """
    return _decide_two_step("APPROVED", app_id, officer_username, note, confirmation_token)


def reject_application(app_id, officer_username, reason, confirmation_token=None):
    """Rejects a PENDING application in two steps. A specific reason is mandatory.
    Step 1 (no token): returns summary + single-use confirmation_token (5m TTL).
    Step 2 (with token): executes decision atomically, writing audit log.
    """
    if not (reason or "").strip():
        return {
            "status": "error",
            "error": "A specific reason is mandatory when rejecting an application.",
            "field": "reason"
        }
    return _decide_two_step("REJECTED", app_id, officer_username, reason, confirmation_token)
