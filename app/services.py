# -*- coding: utf-8 -*-
"""
Sewa Setu - Shared core services for portal web routes and MCP servers.
Plain Python module: zero Flask dependencies. Single source of truth.
"""

import os
import re
import random
import hashlib
import configparser
from datetime import datetime, date, timedelta
from zoneinfo import ZoneInfo
import requests

IST = ZoneInfo("Asia/Kolkata")
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ACTIVE_STATUSES = ("PENDING", "APPROVED", "DEEMED_APPROVED")
BLOCKS = ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"]


def load_config(config_path=None):
    if not config_path:
        config_path = os.environ.get("SEWASETU_CONFIG") or os.path.join(BASE_DIR, "config", "app.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    return cfg


def now_ist():
    """Portal clock is Indian Standard Time."""
    return datetime.now(IST).replace(tzinfo=None)


def get_db(cfg=None):
    import psycopg2
    if cfg is None:
        cfg = load_config()
    host = os.environ.get("PGHOST") or cfg.get("database", "host", fallback="localhost")
    port = int(os.environ.get("PGPORT") or cfg.getint("database", "port", fallback=5432))
    dbname = os.environ.get("PGDATABASE") or cfg.get("database", "name", fallback="sewasetu")
    user = os.environ.get("PGUSER") or cfg.get("database", "user", fallback="sewasetu")
    password = os.environ.get("PGPASSWORD") or cfg.get("database", "password", fallback="sewasetu123")
    return psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )


def sanitize(value, maxlen=100):
    if value is None:
        return ""
    return str(value).strip()[:maxlen]


def hash_password(p):
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def new_application_no():
    return "SSP" + datetime.now().strftime("%y") + str(random.randint(100000, 999999))


def send_sms(mobile, text, cfg=None):
    if cfg is None:
        cfg = load_config()
    gateway_url = os.environ.get("SMS_GATEWAY_URL") or cfg.get("app", "sms_gateway_url", fallback="http://localhost:8025")
    try:
        requests.post(gateway_url.rstrip("/") + "/api/send",
                      json={"to": mobile, "text": text}, timeout=5)
    except Exception:
        pass


def write_audit(cur, app_id, action, actor, note=""):
    cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (app_id, action, actor, note, datetime.now()))


def parse_dob(raw):
    try:
        return datetime.strptime((raw or "").strip(), "%d/%m/%Y").date()
    except (ValueError, TypeError):
        return None


def age_on(dob, on):
    return on.year - dob.year - ((on.month, on.day) < (dob.month, dob.day))


def get_scheme_info(cfg=None):
    """Dynamic scheme details read directly from config."""
    if cfg is None:
        cfg = load_config()
    min_age = cfg.getint("pension", "min_age", fallback=60)
    sla_days = cfg.getint("pension", "sla_days", fallback=15)
    raw_deadline = cfg.get("pension", "scheme_deadline", fallback="2026-10-31 23:59")
    deadline = datetime.strptime(raw_deadline, "%Y-%m-%d %H:%M")
    delta = deadline - now_ist()
    hours_left = int(delta.total_seconds() // 3600) if delta.total_seconds() > 0 else 0
    is_open = delta.total_seconds() > 0
    monthly_amount = cfg.getint("pension", "monthly_amount", fallback=None)
    if monthly_amount is None:
        monthly_amount = cfg.getint("pension", "monthly_pension_amount_inr", fallback=250)
    return {
        "min_age": min_age,
        "sla_days": sla_days,
        "scheme_deadline": raw_deadline,
        "hours_left": hours_left,
        "is_open": is_open,
        "blocks": list(BLOCKS),
        "required_documents": ["Age proof (JPG, PNG or PDF up to 5 MB)"],
        "monthly_pension_amount_inr": monthly_amount,
        "monthly_amount": monthly_amount,
    }


def validate_application(data, doc_path, cfg=None):
    """Validate application data. Returns (errors, cleaned). Single source of truth."""
    if cfg is None:
        cfg = load_config()
    min_age = cfg.getint("pension", "min_age", fallback=60)
    deadline = datetime.strptime(cfg.get("pension", "scheme_deadline", fallback="2026-10-31 23:59"),
                                 "%Y-%m-%d %H:%M")
    errors = []
    cleaned = {
        "applicant_name": sanitize(data.get("applicant_name")),
        "village": sanitize(data.get("village")),
        "block": sanitize(data.get("block")),
        "gender": sanitize(data.get("gender"), 10),
        "marital_status": sanitize(data.get("marital_status"), 20),
        "husband_name": sanitize(data.get("husband_name")),
        "husband_employer": "",
        "bank_account": re.sub(r"[\s-]", "", str(data.get("bank_account") or "")),
        "ifsc": re.sub(r"[\s-]", "", str(data.get("ifsc") or "")).upper(),
        "doc_path": str(doc_path or "").strip(),
        "dob": None,
    }

    for label, key in (("full name", "applicant_name"), ("village", "village"),
                       ("block", "block"), ("bank account", "bank_account")):
        if not cleaned[key]:
            errors.append("%s is required" % label)

    if cleaned["block"] and cleaned["block"] not in BLOCKS:
        errors.append("block must be one of: " + ", ".join(BLOCKS))

    if cleaned["bank_account"] and not re.fullmatch(r"\d{9,18}", cleaned["bank_account"]):
        errors.append("bank account number must be 9 to 18 digits")

    if cleaned["ifsc"] and not re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", cleaned["ifsc"]):
        errors.append("IFSC must be 11 characters, e.g. SBIN0003077")

    dob = parse_dob(data.get("dob"))
    if dob is None:
        errors.append("date of birth must be given as DD/MM/YYYY")
    else:
        cleaned["dob"] = dob
        if age_on(dob, now_ist().date()) < min_age:
            errors.append("applicant must be %d years of age or above" % min_age)

    if not cleaned["doc_path"]:
        errors.append("age proof document is required")

    if now_ist() > deadline:
        errors.append("the application window has closed")

    return errors, cleaned


def active_application(cur, mobile):
    """The applicant's current live application, if any."""
    cur.execute("SELECT id, application_no, status, submitted_at FROM applications "
                "WHERE mobile = %s AND status IN %s "
                "ORDER BY submitted_at DESC LIMIT 1", (mobile, ACTIVE_STATUSES))
    return cur.fetchone()


def create_application(cur, mobile, cleaned, actor=None):
    """Insert a validated application; ensure portal_user exists and write audit.
    Caller commits transaction. Returns (id, application_no).
    """
    app_no = new_application_no()
    now = datetime.now()
    cur.execute(
        """INSERT INTO applications
           (application_no, applicant_name, mobile, dob, gender, marital_status,
            husband_name, husband_employer, village, block, bank_account, ifsc,
            doc_path, status, submitted_at)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING',%s)
           RETURNING id""",
        (app_no, cleaned["applicant_name"], mobile, cleaned["dob"], cleaned["gender"],
         cleaned["marital_status"], cleaned["husband_name"], cleaned["husband_employer"],
         cleaned["village"], cleaned["block"], cleaned["bank_account"], cleaned["ifsc"],
         cleaned["doc_path"], now))
    new_id = cur.fetchone()[0]

    # Status portal account: password is DOB as DDMMYYYY
    portal_pass = cleaned["dob"].strftime("%d%m%Y")
    cur.execute("SELECT count(*) FROM portal_users WHERE mobile = %s", (mobile,))
    if cur.fetchone()[0] == 0:
        cur.execute("INSERT INTO portal_users (mobile, password_hash) VALUES (%s,%s)",
                    (mobile, hash_password(portal_pass)))

    audit_actor = actor or ("applicant:%s" % mobile)
    write_audit(cur, new_id, "SUBMIT", audit_actor)
    return new_id, app_no


def decide_application(cur, app_id, new_status, actor, note=""):
    """Approve or reject a PENDING application atomically.
    Requires reason if rejecting.
    Returns (success: bool, message: str, application_no: str or None)
    """
    if new_status == "REJECTED" and not (note or "").strip():
        return False, "A specific reason is mandatory when rejecting an application.", None

    now = datetime.now()
    cur.execute("UPDATE applications SET status = %s, decided_at = %s, decided_by = %s "
                "WHERE id = %s AND status = 'PENDING' RETURNING application_no",
                (new_status, now, actor, app_id))
    row = cur.fetchone()
    if row:
        app_no = row[0]
        write_audit(cur, app_id, new_status, actor, note.strip())
        return True, "Application %s %s." % (app_no, new_status.lower()), app_no

    # If rowcount was 0, check real current status
    cur.execute("SELECT application_no, status FROM applications WHERE id = %s", (app_id,))
    current = cur.fetchone()
    if not current:
        return False, "Application #%s not found." % app_id, None
    return False, "Application %s is already decided (current status: %s)." % (current[0], current[1]), current[0]


def withdraw_application(cur, app_id, mobile, actor=None):
    """Applicant withdraws their own PENDING application.
    Returns (success: bool, message: str, application_no: str or None)
    """
    now = datetime.now()
    cur.execute("UPDATE applications SET status = 'WITHDRAWN', decided_at = %s, "
                "decided_by = 'APPLICANT' WHERE id = %s AND mobile = %s "
                "AND status = 'PENDING' RETURNING application_no",
                (now, app_id, mobile))
    row = cur.fetchone()
    if row:
        app_no = row[0]
        write_audit(cur, app_id, "WITHDRAW", actor or ("applicant:%s" % mobile))
        return True, "Application %s has been withdrawn." % app_no, app_no

    cur.execute("SELECT application_no, status FROM applications WHERE id = %s AND mobile = %s",
                (app_id, mobile))
    current = cur.fetchone()
    if not current:
        return False, "No application found.", None
    return False, "Only a pending application can be withdrawn (current status: %s)." % current[1], current[0]
