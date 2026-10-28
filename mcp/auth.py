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
from datetime import datetime
import jwt
from cryptography.hazmat.primitives import serialization

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
import sys
if os.path.join(BASE_DIR, "app") not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, "app"))
import services


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


def verify_token(token, expected_resource, expected_role=None, public_keys=None):
    """
    Verify RS256 JWT access token.
    Returns (valid: bool, claims_or_error: dict or str)
    """
    if not token:
        return False, "missing_token"

    issuer = get_public_base_url()
    try:
        unverified_headers = jwt.get_unverified_header(token)
    except Exception as e:
        return False, "invalid_header: %s" % e

    kid = unverified_headers.get("kid")
    if public_keys is None:
        public_keys = JWT_PUBLIC_KEYS_OVERRIDE if JWT_PUBLIC_KEYS_OVERRIDE is not None else get_public_keys_from_db()

    pub_key = public_keys.get(kid) if kid else None
    if not pub_key and public_keys:
        # If kid not matched, try the first key
        pub_key = list(public_keys.values())[0]

    if not pub_key:
        return False, "signing_key_not_found"

    try:
        # Decode and verify signature, issuer, and audience
        claims = jwt.decode(
            token,
            pub_key,
            algorithms=["RS256"],
            audience=expected_resource,
            issuer=issuer,
            options={"require": ["exp", "iss", "aud", "sub"]}
        )
    except jwt.ExpiredSignatureError:
        return False, "token_expired"
    except jwt.InvalidAudienceError:
        return False, "invalid_audience"
    except jwt.InvalidIssuerError:
        return False, "invalid_issuer"
    except Exception as e:
        return False, "token_verification_failed: %s" % e

    # Role and scope checks
    if expected_role:
        token_role = claims.get("role") or claims.get("scope")
        if token_role != expected_role:
            return False, "forbidden: expected role %s, got %s" % (expected_role, token_role)

    # Absolute session end check if present
    if "session_ends" in claims:
        if int(time.time()) > claims["session_ends"]:
            return False, "session_ended: absolute session lifetime elapsed"

    return True, claims


def get_protected_resource_metadata(resource_path=""):
    """RFC 9728 Protected Resource Metadata document for an endpoint."""
    base_url = get_public_base_url()
    if not resource_path or resource_path == "/":
        canonical_resource = base_url
        scopes = ["citizen", "officer"]
    elif "officer" in resource_path:
        canonical_resource = base_url + resource_path
        scopes = ["officer"]
    else:
        canonical_resource = base_url + resource_path
        scopes = ["citizen"]

    return {
        "resource": canonical_resource,
        "authorization_servers": [base_url],
        "scopes_supported": scopes,
        "bearer_methods_supported": ["header"],
        "resource_documentation": base_url + "/about"
    }


def revoke_citizen_session(mobile):
    """Revoke all active refresh tokens for a citizen when signing out."""
    cfg = load_config()
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=cfg.get("database", "host", fallback="localhost"),
            port=cfg.getint("database", "port", fallback=5432),
            dbname=cfg.get("database", "name", fallback="sewasetu"),
            user=cfg.get("database", "user", fallback="sewasetu"),
            password=cfg.get("database", "password", fallback="sewasetu123"),
        )
        cur = conn.cursor()
        subject = "citizen:%s" % mobile
        cur.execute("UPDATE oauth_refresh_tokens SET revoked_at = %s WHERE subject = %s AND revoked_at IS NULL",
                    (datetime.now(), subject))
        n = cur.rowcount
        conn.commit()
        cur.close()
        conn.close()
        return n
    except Exception:
        return 0
