# -*- coding: utf-8 -*-
"""
mcp/auth.py: OAuth 2.1 verification and RFC 9728 Protected Resource Metadata.
Validates RS256 JWTs against portal JWKS or database keys, checking:
  - iss: matching portal issuer
  - aud: matching canonical resource URL
  - exp: not expired
  - role and scope: matching endpoint ('citizen' or 'officer')
  - sub: identity extraction ('citizen:<mobile>' or 'officer:<username>')
"""

import os
import time
import json
import base64
import hashlib
import configparser
from datetime import datetime, date
import jwt
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
if os.path.join(BASE_DIR, "app") not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, "app"))
try:
    import services
except ImportError:
    from app import services


def load_config():
    config_path = os.environ.get("SEWASETU_CONFIG") or os.path.join(BASE_DIR, "app", "config", "app.ini")
    cfg = configparser.ConfigParser()
    cfg.read(config_path)
    return cfg


def get_public_base_url():
    return os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000").rstrip("/")


def get_public_keys_from_db():
    """Retrieve public keys for token verification directly from the database or JWKS cache."""
    cfg = load_config()
    try:
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT kid, private_pem FROM oauth_keys ORDER BY created_at ASC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        keys = {}
        for kid, pem in rows:
            priv = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
            keys[kid] = priv.public_key()
        return keys
    except Exception:
        return {}


JWT_PUBLIC_KEYS_OVERRIDE = None


def is_token_revoked(jti, subject=None, iat=None):
    """Check whether a token or session has been revoked in Postgres. Fails closed on DB error."""
    if not jti:
        return True
    conn = None
    try:
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM oauth_revocations WHERE jti = %s", (jti,))
        row = cur.fetchone()
        if row and row[0] == 1:
            cur.close()
            conn.close()
            return True
        if subject:
            cur.execute("SELECT revoked_at FROM oauth_session_revocations WHERE subject = %s", (subject,))
            row = cur.fetchone()
            if row and row[0]:
                revoked_at = row[0]
                if isinstance(revoked_at, (datetime, date)):
                    revoked_ts = int(revoked_at.timestamp())
                else:
                    revoked_ts = int(revoked_at)
                if iat is None or iat <= revoked_ts:
                    cur.close()
                    conn.close()
                    return True
        cur.close()
        conn.close()
        return False
    except Exception as e:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
        raise RuntimeError(f"Database error checking token revocation: {e}")


def verify_token(token, expected_resource, expected_role=None, public_keys=None):
    """
    Verify RS256 JWT access token.
    Enforces RS256 only, requires: iss, aud, exp, nbf, role, jti, and sub.
    Returns (valid: bool, claims_or_error: dict or str)
    """
    if not token:
        return False, "missing_token"

    issuer = get_public_base_url()
    try:
        unverified_headers = jwt.get_unverified_header(token)
    except Exception as e:
        return False, "invalid_header: %s" % e

    alg = unverified_headers.get("alg")
    if alg != "RS256":
        return False, "unsupported_algorithm: RS256 required, got %s" % alg

    kid = unverified_headers.get("kid")
    if not kid:
        return False, "missing_kid"

    if public_keys is None:
        public_keys = JWT_PUBLIC_KEYS_OVERRIDE if JWT_PUBLIC_KEYS_OVERRIDE is not None else get_public_keys_from_db()

    pub_key = public_keys.get(kid) if kid else None
    if not pub_key:
        return False, "signing_key_not_found"

    try:
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            issuer=issuer,
            options={"verify_aud": False, "require": ["exp", "iss", "sub", "jti", "nbf", "aud"]}
        )
    except jwt.ExpiredSignatureError:
        return False, "token_expired"
    except jwt.InvalidIssuerError:
        return False, "invalid_issuer"
    except Exception as e:
        return False, "token_verification_failed: %s" % e

    # Require role claim
    token_role = claims.get("role") or claims.get("scope")
    if not token_role:
        return False, "missing_role"

    # Role and scope checks (role mismatch is forbidden -> 403)
    if expected_role and token_role != expected_role:
        return False, "forbidden: expected role %s, got %s" % (expected_role, token_role)

    # Audience check: must match canonical endpoint resource URL
    token_aud = claims.get("aud")
    if expected_resource and token_aud != expected_resource:
        return False, "invalid_audience: expected %s, got %s" % (expected_resource, token_aud)

    # Absolute session end check if present
    if "session_ends" in claims:
        if int(time.time()) > claims["session_ends"]:
            return False, "session_ended: absolute session lifetime elapsed"

    # Revocation check against Postgres (fails closed on DB error)
    try:
        if is_token_revoked(claims.get("jti"), subject=claims.get("sub"), iat=claims.get("iat")):
            return False, "token_revoked"
    except Exception as e:
        return False, "auth_service_unavailable: %s" % e

    return True, claims


def get_protected_resource_metadata(resource_path=""):
    """RFC 9728 Protected Resource Metadata document for an endpoint."""
    base_url = get_public_base_url()
    clean_path = ("/" + resource_path.strip("/")) if resource_path.strip("/") else ""
    if clean_path in ("/mcp/citizen", "mcp/citizen"):
        canonical_resource = base_url + "/mcp/citizen"
        scopes = ["citizen"]
    elif clean_path in ("/mcp/officer", "mcp/officer"):
        canonical_resource = base_url + "/mcp/officer"
        scopes = ["officer"]
    else:
        canonical_resource = base_url
        scopes = ["citizen", "officer"]

    return {
        "resource": canonical_resource,
        "authorization_servers": [base_url],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
        "resource_documentation": base_url + "/about"
    }


def revoke_citizen_session(mobile, jti=None):
    """Revoke all active refresh tokens, session, and optional jti for a citizen when signing out."""
    cfg = load_config()
    try:
        conn = services.get_db(cfg)
        cur = conn.cursor()
        subject = "citizen:%s" % mobile
        now = datetime.now()
        cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE subject = %s AND revoked_at IS NULL",
                    (now, subject))
        n = cur.rowcount
        cur.execute("""
            INSERT INTO oauth_session_revocations (subject, revoked_at)
            VALUES (%s, %s)
            ON CONFLICT (subject) DO UPDATE SET revoked_at = EXCLUDED.revoked_at
        """, (subject, now))
        if jti:
            cur.execute("""
                INSERT INTO oauth_revocations (jti, subject, revoked_at)
                VALUES (%s, %s, %s)
                ON CONFLICT (jti) DO NOTHING
            """, (jti, subject, now))
        conn.commit()
        cur.close()
        conn.close()
        return n
    except Exception:
        return 0
