# -*- coding: utf-8 -*-
"""
mcp/citizen.py: Citizen MCP tools (6 tools)
Tailored for a small model with limited turn budget, kiosk/shared phone safety,
and server-side confirmation tokens.
"""

import os
import time
import base64
import secrets
from datetime import datetime

# Import services from app
import sys
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
import services
from auth import revoke_citizen_session

# Deprecated in-memory store retained as empty dict for test setUp backward-compatibility
DRAFTS = {}


def get_scheme_info():
    """Returns official scheme eligibility criteria, deadlines, and benefits."""
    info = services.get_scheme_info()
    return {
        "status": "success",
        "scheme_name": "Indira Gandhi National Old Age Pension Scheme (Purvanchal)",
        "minimum_age": info["min_age"],
        "statutory_sla_days": info["sla_days"],
        "application_deadline": info["scheme_deadline"],
        "hours_left_to_apply": info["hours_left"],
        "is_window_open": info["is_open"],
        "monthly_pension_amount_inr": info["monthly_pension_amount_inr"],
        "eligible_blocks": info["blocks"],
        "required_documents": info["required_documents"],
        "declaration_text": "I hereby declare that all information provided is true and correct, and I do not receive any other statutory pension."
    }


def get_my_status(mobile):
    """Retrieves current application status and next steps for the signed-in citizen."""
    conn = services.get_db()
    cur = conn.cursor()
    cur.execute(
        """SELECT id, application_no, applicant_name, village, block, bank_account, ifsc, status, submitted_at, decided_at
           FROM applications WHERE mobile = %s ORDER BY submitted_at DESC LIMIT 1""",
        (mobile,)
    )
    row = cur.fetchone()
    cur.close()
    conn.close()

    if not row:
        return {
            "status": "not_found",
            "message": "No application found for your registered mobile number.",
            "message_hi": "Aapke mobile number par koi aavedan darj nahi hai.",
            "next_step": "You can prepare and submit a new pension application."
        }

    app_id, app_no, name, village, block, bank_acc, ifsc, app_status, submitted_at, decided_at = row
    masked_bank = "XXXX" + bank_acc[-4:] if len(bank_acc) >= 4 else bank_acc

    sla_info = ""
    if app_status == "PENDING" and submitted_at:
        days_passed = (datetime.now() - submitted_at).days
        remaining_days = max(0, 15 - days_passed)
        sla_info = "%d days remaining within 15-day statutory SLA." % remaining_days

    messages = {
        "PENDING": ("Your application is under review by the Block Development Officer. %s" % sla_info,
                    "Aapka aavedan Block Adhikari ke paas vicharadhin hai."),
        "APPROVED": ("Your pension application has been approved by the Department.",
                     "Aapka pension aavedan sweekar kar liya gaya hai."),
        "DEEMED_APPROVED": ("Approved automatically under the statutory 15-day Right to Public Services Act guarantee.",
                            "RTPS adhiniyam ke tehat aavedan swatah manjoor ho gaya hai."),
        "REJECTED": ("Your application was not approved. You can see the reason in portal or re-apply.",
                     "Aapka aavedan asweekar kar diya gaya hai. Aap naya aavedan kar sakte hain."),
        "WITHDRAWN": ("This application was withdrawn. You may submit a fresh application anytime.",
                      "Yeh aavedan vapas le liya gaya tha. Aap naya aavedan kar sakte hain.")
    }
    desc_en, desc_hi = messages.get(app_status, ("Status: %s" % app_status, "Sthiti: %s" % app_status))

    return {
        "status": "success",
        "application_number": app_no,
        "applicant_name": name,
        "current_status": app_status,
        "village": village,
        "block": block,
        "bank_account_masked": masked_bank,
        "submitted_on": submitted_at.strftime("%d/%m/%Y") if submitted_at else None,
        "explanation": desc_en,
        "explanation_hi": desc_hi,
        "can_withdraw": app_status == "PENDING"
    }


def prepare_application(mobile, applicant_name, dob, gender, marital_status, husband_name,
                        village, block, bank_account, ifsc, document_filename=None, document_base64=None):
    """
    Validates form data and age proof in dry-run mode.
    On success: persists draft to Postgres and returns preview, draft_id, payload_hash, and confirmation_token.
    Valid for 30 minutes. Single-use and cryptographically bound to exact application data.
    The assistant must read the preview and declaration aloud to the citizen before calling submit_application.
    """
    cfg = services.load_config()

    # Save document if provided
    doc_path = ""
    if document_base64:
        try:
            content = base64.b64decode(document_base64)
            if len(content) > 5 * 1024 * 1024:
                return {
                    "status": "error",
                    "error": "Document exceeds maximum allowed size of 5 MB.",
                    "error_hi": "Dastavez 5 MB se bada nahi hona chahiye.",
                    "field": "document_base64"
                }
            upload_dir = cfg.get("app", "upload_dir", fallback="/var/sewasetu/uploads")
            try:
                os.makedirs(upload_dir, exist_ok=True)
            except OSError:
                upload_dir = os.path.join(BASE_DIR, "app", "uploads")
                os.makedirs(upload_dir, exist_ok=True)
            fname = (document_filename or "age_proof.jpg").lower()
            ext = fname.rsplit(".", 1)[-1]
            if ext not in ("pdf", "jpg", "jpeg", "png"):
                return {
                    "status": "error",
                    "error": "Document format must be JPG, PNG or PDF.",
                    "error_hi": "Dastavez keval JPG, PNG ya PDF format mein hona chahiye.",
                    "field": "document_filename"
                }
            doc_path = os.path.join(upload_dir, "%s_%s" % (mobile, fname))
            with open(doc_path, "wb") as f:
                f.write(content)
        except Exception as e:
            return {
                "status": "error",
                "error": "Could not decode document: %s" % e,
                "error_hi": "Dastavez upload karne mein truti aayi."
            }

    data = {
        "applicant_name": applicant_name,
        "dob": dob,
        "gender": gender,
        "marital_status": marital_status,
        "husband_name": husband_name,
        "village": village,
        "block": block,
        "bank_account": bank_account,
        "ifsc": ifsc,
    }

    errors, cleaned = services.validate_application(data, doc_path, cfg)
    if errors:
        return {
            "status": "validation_failed",
            "errors": errors,
            "next_questions": "Please ask the citizen to correct the following items: " + "; ".join(errors)
        }

    # Check existing active application
    conn = services.get_db(cfg)
    cur = conn.cursor()
    existing = services.active_application(cur, mobile)

    if existing:
        cur.close()
        conn.close()
        return {
            "status": "active_application_exists",
            "existing_application_no": existing[1],
            "existing_status": existing[2],
            "message": "You already hold an active application (%s: %s). Only one active pension is permitted." % (existing[1], existing[2]),
            "message_hi": "Aapka pehle se ek aavedan darj hai (%s: %s)." % (existing[1], existing[2]),
            "next_step": "If this was an error, you may withdraw your pending application first."
        }

    # Persist durable draft in Postgres and generate cryptographically bound confirmation token
    draft_id, payload_hash, confirmation_token, expires_at = services.create_draft(
        cur, mobile, cleaned, scheme_version="v1.0", ttl_minutes=30
    )
    conn.commit()
    cur.close()
    conn.close()

    masked_acc = "XXXX" + cleaned["bank_account"][-4:] if len(cleaned["bank_account"]) >= 4 else cleaned["bank_account"]

    return {
        "status": "ready_for_confirmation",
        "draft_id": draft_id,
        "payload_hash": payload_hash,
        "confirmation_token": confirmation_token,
        "valid_for_minutes": 30,
        "preview": {
            "applicant_name": cleaned["applicant_name"],
            "date_of_birth": cleaned["dob"].strftime("%d/%m/%Y"),
            "village": cleaned["village"],
            "block": cleaned["block"],
            "bank_account": masked_acc,
            "ifsc": cleaned["ifsc"],
            "document_attached": os.path.basename(doc_path) if doc_path else "Yes"
        },
        "declaration": "I declare that all details are accurate and I qualify for the Old Age Pension.",
        "declaration_hi": "Main ghoshna karta/karti hoon ki di gayi jankari sahi hai aur main Vriddhavastha Pension ke patra hoon.",
        "assistant_instruction": "Read the preview and declaration aloud to the citizen. Call submit_application ONLY after receiving their explicit confirmation."
    }


def submit_application(mobile, confirmation_token=None, draft_id=None, hash=None):
    """
    Submits a validated application using the draft_id and confirmation token/hash.
    Accepts confirmation_token (formatted as <draft_id>.<hash>), or draft_id and confirmation_token/hash.
    Enforces atomic DB row lock, single-use, non-expiry, and cryptographic hash verification.
    """
    d_id = None
    p_hash = None

    if draft_id and (confirmation_token or hash):
        d_id = str(draft_id).strip()
        p_hash = str(hash or confirmation_token).strip()
    elif confirmation_token:
        tok = str(confirmation_token).strip()
        if "." in tok:
            d_id, p_hash = tok.split(".", 1)
        else:
            d_id = tok
            p_hash = str(hash or "").strip()

    if not d_id or not p_hash:
        return {
            "status": "error",
            "error": "Both draft_id and confirmation token/hash are required to submit.",
            "error_hi": "Aavedan submit karne ke liye draft_id aur confirmation token anivarya hain."
        }

    cfg = services.load_config()
    conn = services.get_db(cfg)
    ok, result = services.submit_draft(conn, mobile, d_id, p_hash, cfg)
    conn.close()
    return result


def withdraw_application(mobile, confirm=False):
    """
    Allows a citizen to withdraw their own PENDING application so they can re-apply.
    Two-step pattern: prompt if confirm is False; withdraw if confirm is True.
    """
    conn = services.get_db()
    cur = conn.cursor()
    cur.execute(
        "SELECT id, application_no, status FROM applications WHERE mobile = %s AND status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED')",
        (mobile,)
    )
    row = cur.fetchone()

    if not row:
        cur.close()
        conn.close()
        return {
            "status": "not_found",
            "message": "No active application found to withdraw.",
            "message_hi": "Vapas lene ke liye koi sakriya aavedan nahi mila."
        }

    app_id, app_no, current_status = row
    if current_status != "PENDING":
        cur.close()
        conn.close()
        return {
            "status": "error",
            "error": "Only a pending application can be withdrawn. Your application is already %s." % current_status,
            "error_hi": "Keval vicharadhin aavedan vapas liya ja sakta hai."
        }

    if not confirm:
        cur.close()
        conn.close()
        return {
            "status": "confirmation_required",
            "application_number": app_no,
            "warning": "Are you sure you want to withdraw application %s? Once withdrawn, you can submit a new application." % app_no,
            "warning_hi": "Kya aap aavedan %s vapas lena chahte hain? Iske baad aap naya aavedan jama kar sakenge." % app_no,
            "instruction": "Call withdraw_application with confirm=True to proceed."
        }

    ok, msg, _ = services.withdraw_application(cur, app_id, mobile, actor="applicant:%s" % mobile)
    if ok:
        services.invalidate_citizen_drafts(cur, mobile, "withdrawn")
        conn.commit()
    else:
        conn.rollback()
    cur.close()
    conn.close()

    return {
        "status": "withdrawn" if ok else "error",
        "application_number": app_no,
        "message": msg,
        "message_hi": "Aapka aavedan safaltapoorvak vapas le liya gaya hai. Aap naya aavedan kar sakte hain." if ok else msg
    }


def sign_out(mobile):
    """Ends the citizen session and revokes tokens for shared-device and kiosk safety."""
    revoked = revoke_citizen_session(mobile)
    try:
        conn = services.get_db()
        cur = conn.cursor()
        services.invalidate_citizen_drafts(cur, mobile, "expired")
        conn.commit()
        cur.close()
        conn.close()
    except Exception:
        pass

    return {
        "status": "signed_out",
        "sessions_revoked": revoked,
        "message": "You have been signed out safely. Kiosk session cleared.",
        "message_hi": "Aap safaltapoorvak sign out ho gaye hain. Suraksha ke liye session band kar diya gaya hai."
    }
