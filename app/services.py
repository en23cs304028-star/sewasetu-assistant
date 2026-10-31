# -*- coding: utf-8 -*-
"""
Sewa Setu - Shared core services for portal web routes and MCP servers.
Plain Python module: zero Flask dependencies. Single source of truth.
"""

import os
import re
import random
import hashlib
import hmac
import json
import secrets
import logging
import ipaddress
import configparser
from datetime import datetime, date, timedelta, timezone
from zoneinfo import ZoneInfo
import requests

logger = logging.getLogger("sewasetu.services")

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
    raw_pwd = os.environ.get("POSTGRES_PASSWORD") or os.environ.get("PGPASSWORD")
    if not raw_pwd:
        raw_pwd = cfg.get("database", "password", fallback="").strip()
    password = raw_pwd or "sewasetu123"

    is_production = os.environ.get("ENV", "").lower() == "production" or os.environ.get("FLASK_ENV", "").lower() == "production"
    if is_production:
        if not password or password in ("sewasetu123", "password", "admin", "default", "changeme") or len(password) < 16:
            raise RuntimeError("In production, database password (POSTGRES_PASSWORD / PGPASSWORD) must be set, not 'sewasetu123', and at least 16 characters long.")
    return psycopg2.connect(
        host=host,
        port=port,
        dbname=dbname,
        user=user,
        password=password,
    )


DEFAULT_TRUSTED_PROXY_CIDRS = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,::1/128"


def get_client_ip(req):
    """
    Obtain client IP address with proxy spoofing protection:
    - Uses X-Forwarded-For ONLY when direct peer is inside trusted proxy CIDRs (TRUSTED_PROXY_CIDRS).
    - Takes right-most untrusted forwarded IP to defeat spoofed leading headers.
    - If direct peer is not trusted, ignores X-Forwarded-For and returns remote_addr.
    """
    peer_ip_str = getattr(req, "remote_addr", None) or "127.0.0.1"
    trusted_cidrs_str = os.environ.get("TRUSTED_PROXY_CIDRS", DEFAULT_TRUSTED_PROXY_CIDRS)
    trusted_nets = []
    for cidr in trusted_cidrs_str.split(","):
        cidr = cidr.strip()
        if cidr:
            try:
                trusted_nets.append(ipaddress.ip_network(cidr))
            except ValueError:
                pass

    try:
        peer_ip = ipaddress.ip_address(peer_ip_str)
        is_trusted = any(peer_ip in net for net in trusted_nets)
    except ValueError:
        is_trusted = False

    if not is_trusted:
        return peer_ip_str

    # Direct peer is trusted proxy: check X-Forwarded-For
    headers = getattr(req, "headers", {})
    xff = headers.get("X-Forwarded-For") if hasattr(headers, "get") else None
    if not xff:
        return peer_ip_str

    entries = [ip.strip() for ip in xff.split(",") if ip.strip()]
    if not entries:
        return peer_ip_str

    # Return right-most untrusted entry, or right-most entry if all are untrusted/trusted
    for entry in reversed(entries):
        try:
            parsed = ipaddress.ip_address(entry)
            if not any(parsed in net for net in trusted_nets):
                return entry
        except ValueError:
            continue

    return entries[-1]


def secure_compare(val1, val2) -> bool:
    """
    Safely compare two strings or byte sequences in constant time.
    Encodes both to UTF-8 bytes to prevent type errors, handles None,
    empty strings, and arbitrary lengths (including non-ASCII and large strings)
    without raising exceptions.
    """
    if val1 is None or val2 is None:
        return False
    try:
        b1 = val1.encode("utf-8") if isinstance(val1, str) else bytes(val1)
        b2 = val2.encode("utf-8") if isinstance(val2, str) else bytes(val2)
        return secrets.compare_digest(b1, b2)
    except Exception:
        return False


def sanitize(value, maxlen=100):
    if value is None:
        return ""
    # Strip NUL and ASCII control characters (preserving no html.escape on input)
    s = re.sub(r"[\x00-\x1f\x7f]", "", str(value))
    return s.strip()[:maxlen]


def hash_password(p):
    return hashlib.sha256(p.encode("utf-8")).hexdigest()


def new_application_no():
    return "SSP" + datetime.now().strftime("%y") + str(random.randint(100000, 999999))


def send_sms(mobile, text, cfg=None, timeout=5):
    if cfg is None:
        cfg = load_config()
    gateway_url = os.environ.get("SMS_GATEWAY_URL") or cfg.get("app", "sms_gateway_url", fallback="http://localhost:8025")
    try:
        resp = requests.post(
            gateway_url.rstrip("/") + "/api/send",
            json={"to": mobile, "text": text},
            timeout=timeout
        )
        return resp.status_code == 200
    except Exception as e:
        logger.warning("SMS gateway delivery failed for %s: %s", mobile, e)
        return False


def write_audit(cur, app_id, action, actor, note=""):
    clean_note = sanitize(note, maxlen=500)
    cur.execute("INSERT INTO audit_log (application_id, action, actor, note, at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (app_id, action, actor, clean_note, datetime.now()))


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
    Requires reason if rejecting. Caps note length at 500 characters.
    Returns (success: bool, message: str, application_no: str or None)
    """
    clean_note = sanitize(note, maxlen=500)
    if new_status == "REJECTED" and not clean_note:
        return False, "A specific reason is mandatory when rejecting an application.", None

    now = datetime.now()
    cur.execute("UPDATE applications SET status = %s, decided_at = %s, decided_by = %s "
                "WHERE id = %s AND status = 'PENDING' RETURNING application_no",
                (new_status, now, actor, app_id))
    row = cur.fetchone()
    if row:
        app_no = row[0]
        write_audit(cur, app_id, new_status, actor, clean_note)
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


# ---------------------------------------------------------------------------
# Durable Draft State & Cryptographic Hash Binding
# ---------------------------------------------------------------------------

def ensure_security_tables(conn):
    """Idempotently ensures security, revocation, lockout, and rate limiting tables exist."""
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS oauth_revocations (
            jti        VARCHAR(64) PRIMARY KEY,
            subject    VARCHAR(80),
            revoked_at TIMESTAMP DEFAULT NOW(),
            expires_at TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_revocations_subject ON oauth_revocations (subject);

        CREATE TABLE IF NOT EXISTS oauth_session_revocations (
            subject    VARCHAR(80) PRIMARY KEY,
            revoked_at TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS rate_limits (
            key            VARCHAR(128) PRIMARY KEY,
            count          INT DEFAULT 1,
            first_attempt  TIMESTAMP DEFAULT NOW(),
            last_attempt   TIMESTAMP DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS security_audit_log (
            id         SERIAL PRIMARY KEY,
            event_type VARCHAR(64) NOT NULL,
            subject    VARCHAR(128),
            ip         VARCHAR(64),
            user_agent TEXT,
            details    JSONB,
            created_at TIMESTAMP DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_sec_audit_event ON security_audit_log (event_type);
        CREATE INDEX IF NOT EXISTS idx_sec_audit_created ON security_audit_log (created_at);

        CREATE TABLE IF NOT EXISTS confirmation_tokens (
            token_hash      VARCHAR(64) PRIMARY KEY,
            application_id  INTEGER NOT NULL,
            decision        VARCHAR(20) NOT NULL,
            officer_subject VARCHAR(80) NOT NULL,
            reason          VARCHAR(500),
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at      TIMESTAMPTZ NOT NULL,
            used_at         TIMESTAMPTZ
        );
        CREATE INDEX IF NOT EXISTS idx_conf_tokens_app ON confirmation_tokens (application_id);

        ALTER TABLE otps ADD COLUMN IF NOT EXISTS attempts INT DEFAULT 0;
        ALTER TABLE otps ADD COLUMN IF NOT EXISTS used_at TIMESTAMP;
    """)
    conn.commit()
    cur.close()


def check_rate_limit(conn, key, max_attempts, window_seconds):
    """
    PostgreSQL-backed atomic sliding-window rate limiter.
    Returns (allowed: bool, retry_after_seconds: int)
    """
    cur = conn.cursor()
    now = datetime.now()
    cur.execute("SELECT count, first_attempt FROM rate_limits WHERE key = %s", (key,))
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO rate_limits (key, count, first_attempt, last_attempt) VALUES (%s, 1, %s, %s)",
                    (key, now, now))
        conn.commit()
        cur.close()
        return True, 0
    count, first_attempt = row
    if (now - first_attempt).total_seconds() > window_seconds:
        cur.execute("UPDATE rate_limits SET count = 1, first_attempt = %s, last_attempt = %s WHERE key = %s",
                    (now, now, key))
        conn.commit()
        cur.close()
        return True, 0
    if count >= max_attempts:
        retry_after = int(window_seconds - (now - first_attempt).total_seconds())
        cur.close()
        return False, max(1, retry_after)
    cur.execute("UPDATE rate_limits SET count = count + 1, last_attempt = %s WHERE key = %s", (now, key))
    conn.commit()
    cur.close()
    return True, 0


def is_rate_limited(conn, key, max_attempts, window_seconds):
    """
    Checks if a key has reached max_attempts within window_seconds without incrementing.
    Returns (limited: bool, retry_after: int)
    """
    cur = conn.cursor()
    now = datetime.now()
    cur.execute("SELECT count, first_attempt FROM rate_limits WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()
    if not row:
        return False, 0
    count, first_attempt = row
    elapsed = (now - first_attempt).total_seconds()
    if elapsed > window_seconds:
        return False, 0
    if count >= max_attempts:
        retry_after = max(1, int(window_seconds - elapsed))
        return True, retry_after
    return False, 0


def record_rate_limit_failure(conn, key, window_seconds):
    """
    Increments failure count for a key. Returns new count.
    """
    cur = conn.cursor()
    now = datetime.now()
    cur.execute("SELECT count, first_attempt FROM rate_limits WHERE key = %s", (key,))
    row = cur.fetchone()
    if not row:
        cur.execute("INSERT INTO rate_limits (key, count, first_attempt, last_attempt) VALUES (%s, 1, %s, %s)",
                    (key, now, now))
        conn.commit()
        cur.close()
        return 1
    count, first_attempt = row
    if (now - first_attempt).total_seconds() > window_seconds:
        cur.execute("UPDATE rate_limits SET count = 1, first_attempt = %s, last_attempt = %s WHERE key = %s",
                    (now, now, key))
        conn.commit()
        cur.close()
        return 1
    new_count = count + 1
    cur.execute("UPDATE rate_limits SET count = %s, last_attempt = %s WHERE key = %s", (new_count, now, key))
    conn.commit()
    cur.close()
    return new_count


def clear_rate_limit(conn, key):
    """Resets rate limiting counter for a given key on successful authentication."""
    cur = conn.cursor()
    cur.execute("DELETE FROM rate_limits WHERE key = %s", (key,))
    conn.commit()
    cur.close()


def get_rate_limit_count(conn, key, window_seconds=900):
    """Returns current failure count for a key within window_seconds, or 0 if expired."""
    cur = conn.cursor()
    now = datetime.now()
    cur.execute("SELECT count, first_attempt FROM rate_limits WHERE key = %s", (key,))
    row = cur.fetchone()
    cur.close()
    if not row:
        return 0
    count, first_attempt = row
    if (now - first_attempt).total_seconds() > window_seconds:
        return 0
    return count
    cur.close()


def log_security_event(conn, event_type, subject=None, ip=None, user_agent=None, details=None):
    """
    Records security events in security_audit_log.
    Strips passwords, OTP codes, raw tokens, and sensitive secrets before persisting.
    """
    if details and isinstance(details, dict):
        safe_details = {}
        sensitive_keys = {"password", "otp", "code", "token", "raw_token", "secret", "client_secret", "private_pem"}
        for k, v in details.items():
            if any(s in str(k).lower() for s in sensitive_keys):
                safe_details[k] = "[REDACTED]"
            else:
                safe_details[k] = v
    else:
        safe_details = details or {}

    cur = conn.cursor()
    cur.execute("""
        INSERT INTO security_audit_log (event_type, subject, ip, user_agent, details, created_at)
        VALUES (%s, %s, %s, %s, %s, NOW())
    """, (event_type, subject, ip, user_agent, json.dumps(safe_details) if safe_details else None))
    conn.commit()
    cur.close()


def ensure_drafts_table(conn):
    """Idempotently ensures the drafts table, indexes, and active application index exist."""
    ensure_security_tables(conn)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS drafts (
            draft_id        VARCHAR(64) PRIMARY KEY,
            citizen_id      VARCHAR(64) NOT NULL,
            payload         JSONB NOT NULL,
            payload_hash    VARCHAR(64) NOT NULL,
            scheme_version  VARCHAR(32) NOT NULL DEFAULT 'v1.0',
            status          VARCHAR(20) NOT NULL DEFAULT 'prepared',
            created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at      TIMESTAMPTZ NOT NULL,
            submitted_at    TIMESTAMPTZ,
            application_id  INTEGER REFERENCES applications(id) ON DELETE SET NULL,
            CONSTRAINT chk_draft_status CHECK (status IN ('prepared', 'submitted', 'withdrawn', 'expired'))
        );
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns 
                WHERE table_name = 'drafts' AND column_name = 'created_at' AND data_type = 'timestamp without time zone'
            ) THEN
                ALTER TABLE drafts ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
                ALTER TABLE drafts ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
                ALTER TABLE drafts ALTER COLUMN submitted_at TYPE TIMESTAMPTZ USING submitted_at AT TIME ZONE 'UTC';
            END IF;
        END $$;
        CREATE INDEX IF NOT EXISTS idx_drafts_citizen_id ON drafts (citizen_id);
        CREATE INDEX IF NOT EXISTS idx_drafts_expires_at ON drafts (expires_at);
        CREATE UNIQUE INDEX IF NOT EXISTS uq_drafts_application_id ON drafts (application_id) WHERE application_id IS NOT NULL;
    """)
    conn.commit()
    cur.close()
    ensure_active_application_index(conn)


def ensure_active_application_index(conn):
    """
    Idempotently ensures the unique partial index on active applications exists.
    Checks for duplicate active applications before creation; reports them without deleting rows.
    """
    cur = conn.cursor()
    cur.execute("""
        SELECT mobile, count(*)
        FROM applications
        WHERE status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED')
        GROUP BY mobile
        HAVING count(*) > 1
    """)
    dups = cur.fetchall()
    if dups:
        cur.close()
        raise RuntimeError(f"Cannot create unique index: duplicate active applications exist in DB: {dups}")
    cur.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_active_application_mobile
        ON applications (mobile)
        WHERE status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED');
    """)
    conn.commit()
    cur.close()


def ensure_all_tables(conn=None):
    """Idempotently ensure all application, drafts, security, and migration tables/indexes exist."""
    close_on_exit = False
    if conn is None:
        conn = get_db()
        close_on_exit = True
    try:
        ensure_drafts_table(conn)
        ensure_security_tables(conn)
        ensure_active_application_index(conn)
    finally:
        if close_on_exit:
            conn.close()


def format_utc_iso(dt):
    """Formats datetime as fixed UTC ISO-8601 string with Z suffix."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def canonicalize_draft_payload(citizen_id, cleaned_data, scheme_version, expires_at_str):
    """
    Produces deterministic canonical JSON for draft validation & hashing.
    Keys are sorted, types/whitespace normalized, and encoding is fixed UTF-8.
    """
    norm_fields = {}
    for k, v in cleaned_data.items():
        if isinstance(v, (datetime, date)):
            norm_fields[k] = v.strftime("%Y-%m-%d")
        elif v is None:
            norm_fields[k] = ""
        else:
            norm_fields[k] = str(v).strip()

    canonical_obj = {
        "citizen_id": str(citizen_id).strip(),
        "application_fields": norm_fields,
        "scheme_version": str(scheme_version).strip(),
        "expires_at": str(expires_at_str).strip(),
    }
    return json.dumps(canonical_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_payload_hash(canonical_json):
    """Returns SHA-256 hex digest of canonical JSON payload."""
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def create_draft(cur, citizen_id, cleaned_data, scheme_version="v1.0", ttl_minutes=30):
    """
    Creates a new prepared draft record in Postgres.
    Supersedes (expires) any earlier prepared draft for the same citizen.
    Returns (draft_id, payload_hash, confirmation_token, expires_at).
    """
    # Supersede existing prepared drafts for this citizen
    cur.execute(
        "UPDATE drafts SET status = 'expired' WHERE citizen_id = %s AND status = 'prepared'",
        (citizen_id,)
    )

    draft_id = secrets.token_urlsafe(24)  # 192-bit cryptographic randomness
    created_at = datetime.now(timezone.utc)
    expires_at = created_at + timedelta(minutes=ttl_minutes)
    expires_at_str = format_utc_iso(expires_at)

    canonical_json = canonicalize_draft_payload(citizen_id, cleaned_data, scheme_version, expires_at_str)
    payload_hash = compute_payload_hash(canonical_json)
    payload_dict = json.loads(canonical_json)

    cur.execute(
        """INSERT INTO drafts (draft_id, citizen_id, payload, payload_hash, scheme_version,
                               status, created_at, expires_at)
           VALUES (%s, %s, %s, %s, %s, 'prepared', %s, %s)""",
        (draft_id, citizen_id, json.dumps(payload_dict), payload_hash, scheme_version, created_at, expires_at)
    )

    confirmation_token = f"{draft_id}.{payload_hash}"
    return draft_id, payload_hash, confirmation_token, expires_at


def invalidate_citizen_drafts(cur, citizen_id, new_status="withdrawn"):
    """Marks any outstanding prepared drafts for the citizen with new_status."""
    cur.execute(
        "UPDATE drafts SET status = %s WHERE citizen_id = %s AND status = 'prepared'",
        (new_status, citizen_id)
    )
    return cur.rowcount


def submit_draft(conn, citizen_id, draft_id, provided_hash, cfg=None):
    """
    Submits a prepared draft in a single atomic database transaction.
    Enforces row-level lock (FOR UPDATE), owner matching, non-expiry, single-use,
    and cryptographic hash binding using hmac.compare_digest.
    Returns (success: bool, result_dict: dict)
    """
    if cfg is None:
        cfg = load_config()

    cur = conn.cursor()
    app_no = None
    new_app_id = None
    now_utc = datetime.now(timezone.utc)
    cleaned = {}

    try:
        # 1. Lock the draft row exclusively for this authenticated citizen
        cur.execute(
            """SELECT draft_id, citizen_id, payload, payload_hash, scheme_version,
                      status, expires_at, application_id
               FROM drafts
               WHERE draft_id = %s AND citizen_id = %s
               FOR UPDATE""",
            (draft_id, citizen_id)
        )
        row = cur.fetchone()
        if not row:
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Draft not found or expired.",
                "error_hi": "Aavedan draft nahi mila ya expire ho gaya hai."
            }

        d_id, c_id, payload_raw, stored_hash, scheme_ver, status, expires_at, app_id = row

        # 2. Check lifecycle status (single use & validity)
        if status == "submitted":
            conn.rollback()
            return False, {
                "status": "error",
                "error": "This draft has already been submitted.",
                "error_hi": "Yeh draft pehle hi jama kiya ja chuka hai.",
                "application_id": app_id
            }

        if status != "prepared":
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Draft is not in a submittable state (status: %s)." % status
            }

        # 3. Check expiry (timezone-aware UTC comparison)
        expires_at_utc = expires_at.replace(tzinfo=timezone.utc) if expires_at.tzinfo is None else expires_at.astimezone(timezone.utc)
        if now_utc > expires_at_utc:
            cur.execute("UPDATE drafts SET status = 'expired' WHERE draft_id = %s", (d_id,))
            conn.commit()
            return False, {
                "status": "error",
                "error": "Draft has expired. Please prepare the application again.",
                "error_hi": "Draft expire ho gaya hai. Kripya punah koshish karein."
            }

        # 4. Hash binding verification (tamper resistance)
        payload_dict = payload_raw if isinstance(payload_raw, dict) else json.loads(payload_raw)
        app_fields = payload_dict.get("application_fields", payload_dict)

        expires_at_str = format_utc_iso(expires_at_utc)
        canonical_str = canonicalize_draft_payload(
            citizen_id=c_id,
            cleaned_data=app_fields,
            scheme_version=scheme_ver,
            expires_at_str=expires_at_str
        )
        recomputed_hash = compute_payload_hash(canonical_str)

        # Integrity check: stored payload must match stored hash
        if not secure_compare(recomputed_hash, stored_hash):
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Draft payload integrity check failed (stored data tampered).",
                "error_hi": "Draft data chhedchhad ki wajah se asweekar kiya gaya."
            }

        # Authenticity check: provided token/hash must match stored hash
        if not secure_compare(provided_hash, stored_hash):
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Confirmation token/hash mismatch. Submission rejected.",
                "error_hi": "Confirmation token aavedan data se match nahi hua."
            }

        # 5. Check active application rule at submission time
        existing = active_application(cur, c_id)
        if existing:
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Active application %s already exists for this mobile number." % existing[1]
            }

        # 6. Parse and validate date of birth
        cleaned = dict(app_fields)
        if isinstance(cleaned.get("dob"), str):
            dob_str = cleaned["dob"].strip()
            parsed = parse_dob(dob_str)
            if not parsed:
                try:
                    parsed = datetime.strptime(dob_str, "%Y-%m-%d").date()
                except Exception:
                    parsed = None
            cleaned["dob"] = parsed

        if not cleaned.get("dob") or not isinstance(cleaned["dob"], (date, datetime)):
            conn.rollback()
            return False, {
                "status": "error",
                "error": "Invalid date of birth in draft. Cannot submit without a valid date of birth.",
                "error_hi": "Aavedan me janmatithi amaanya hai."
            }

        actor = "applicant:%s" % c_id
        new_app_id, app_no = create_application(cur, c_id, cleaned, actor=actor)

        # 7. Update draft status to submitted and record application_id
        cur.execute(
            """UPDATE drafts
               SET status = 'submitted', submitted_at = %s, application_id = %s
               WHERE draft_id = %s""",
            (now_utc, new_app_id, d_id)
        )

        conn.commit()
    except Exception as e:
        conn.rollback()
        import psycopg2.errors
        if isinstance(e, psycopg2.errors.UniqueViolation) and getattr(getattr(e, "diag", None), "constraint_name", None) == "uq_active_application_mobile":
            cur2 = conn.cursor()
            existing = active_application(cur2, citizen_id)
            cur2.close()
            if existing:
                return False, {
                    "status": "error",
                    "error": "Active application %s already exists for this mobile number." % existing[1],
                    "error_hi": "Is mobile number par pehle se ek aavedan kramank maujood hai."
                }
            return False, {
                "status": "error",
                "error": "Active application already exists for this mobile number.",
                "error_hi": "Is mobile number par pehle se ek aavedan kramank maujood hai."
            }
        raise
    finally:
        cur.close()

    # SMS delivery outside the DB transaction so gateway errors don't fail submission
    sms_sent = False
    try:
        sms_sent = bool(send_sms(
            citizen_id,
            "Sewa Setu: application %s received. Track at the status portal with mobile no. and password (DOB as DDMMYYYY)." % app_no,
            cfg,
            timeout=5
        ))
    except Exception as e:
        logger.warning("Failed to send confirmation SMS to %s for application %s: %s", citizen_id, app_no, e)
        sms_sent = False

    return True, {
        "status": "submitted",
        "application_number": app_no,
        "applicant_name": cleaned.get("applicant_name", ""),
        "submission_date": now_utc.strftime("%d/%m/%Y %H:%M"),
        "status_code": "PENDING",
        "sms_sent": sms_sent,
        "message": "Application %s successfully submitted." % app_no,
        "message_hi": "Aapka aavedan kramank %s safaltapoorvak jama ho gaya hai." % app_no,
        "tracking_instruction": "You can track your application anytime using your mobile number and date of birth (DDMMYYYY)."
    }
