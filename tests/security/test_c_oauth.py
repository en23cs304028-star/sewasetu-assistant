# -*- coding: utf-8 -*-
"""
tests/security/test_c_oauth.py: Threat C - OAuth 2.1 Security & Grant Validation
Checks:
  - Wrong code_verifier rejected (PASS)
  - Authorization code reuse rejected (PASS)
  - Authorization code expiry rejected (PASS)
  - Redirect URI mismatch rejected (PASS)
  - Redirect URI omission bypass in token exchange (FAIL EXPECTED: oauth.py skips check if omitted)
  - Plain PKCE method rejected (PASS)
  - Missing state parameter in authorization request (FAIL EXPECTED: state not mandated)
  - Malicious redirect URI registration (javascript:, data:, non-loopback http) rejected (PASS)
  - Refresh token reuse and revocation (FAIL EXPECTED: token family compromise revocation not performed)
"""

import os
import sys
import time
import json
import base64
import hashlib
import secrets
import unittest
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")

import app as portal
import oauth
import services


def _b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


class TestThreatCOAuth(unittest.TestCase):

    def setUp(self):
        self.app = portal.app.test_client()
        os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"
        self.verifier = secrets.token_urlsafe(32)
        self.challenge = _b64url(hashlib.sha256(self.verifier.encode()).digest())
        self.redirect_uri = "http://localhost:8080/callback"
        self.client_id = f"test_client_{secrets.token_hex(4)}"

        # Register client in DB
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO oauth_clients (client_id, client_name, redirect_uris, secret_hash, kind, created_at, fetched_at) "
            "VALUES (%s, %s, %s, NULL, 'dcr', %s, %s) ON CONFLICT (client_id) DO NOTHING",
            (self.client_id, "Security Test Client", json.dumps([self.redirect_uri]), datetime.now(), datetime.now())
        )
        conn.commit()
        cur.close()
        conn.close()

    def _create_auth_code(self, client_id=None, redirect_uri=None, challenge=None, role="citizen", subject="citizen:9990001001", ttl_offset=0):
        code = secrets.token_urlsafe(32)
        c_id = client_id or self.client_id
        r_uri = redirect_uri or self.redirect_uri
        chal = challenge or self.challenge
        created = datetime.now() + timedelta(seconds=ttl_offset)

        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scope, code_challenge, resource, subject, role, created_at) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
            (hashlib.sha256(code.encode()).hexdigest(), c_id, r_uri, role, chal,
             "http://localhost:8000/mcp/citizen", subject, role, created)
        )
        conn.commit()
        cur.close()
        conn.close()
        return code

    def test_c1_wrong_code_verifier_rejected(self):
        """Token exchange with wrong code_verifier must fail PKCE verification."""
        code = self._create_auth_code()
        resp = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": "completely_wrong_verifier_string"
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_grant")
        self.assertIn("PKCE", data.get("error_description", ""))

    def test_c2_auth_code_reuse_rejected(self):
        """Reusing the same authorization code twice must fail on the second attempt."""
        code = self._create_auth_code()
        # First exchange - must succeed
        resp1 = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier
        })
        self.assertEqual(resp1.status_code, 200)

        # Second exchange with the same code - must be rejected
        resp2 = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier
        })
        self.assertEqual(resp2.status_code, 400)
        data2 = resp2.get_json()
        self.assertEqual(data2.get("error"), "invalid_grant")

    def test_c3_expired_auth_code_rejected(self):
        """Authorization code older than 5 minutes (CODE_TTL) must be rejected."""
        # Code created 301 seconds ago
        code = self._create_auth_code(ttl_offset=-305)
        resp = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_grant")
        self.assertIn("expired", data.get("error_description", ""))

    def test_c4_redirect_uri_mismatch_rejected(self):
        """Token exchange with a redirect_uri differing from the authorization code's must be rejected."""
        code = self._create_auth_code()
        resp = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": "http://localhost:8080/different_callback",
            "code_verifier": self.verifier
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_grant")
        self.assertIn("redirect_uri mismatch", data.get("error_description", ""))

    def test_c5_redirect_uri_omission_must_be_rejected(self):
        """[FAIL EXPECTED] Omitting redirect_uri in token request when code had redirect_uri must be rejected."""
        code = self._create_auth_code()
        # Client deliberately omits redirect_uri parameter
        resp = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            # redirect_uri omitted
            "code_verifier": self.verifier
        })
        # RFC 6749 4.1.3 requires: if redirect_uri was in auth request, it MUST be included and match.
        # Current oauth.py line 524 skips check if omitted: if f.get("redirect_uri") and f.get("redirect_uri") != c_redirect:
        self.assertEqual(
            resp.status_code, 400,
            "Server permitted token exchange when redirect_uri was omitted by client, bypassing mismatch checks"
        )

    def test_c6_plain_pkce_rejected(self):
        """PKCE code_challenge_method=plain must be rejected in /oauth/authorize."""
        resp = self.app.get("/oauth/authorize", query_string={
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "code_challenge": "plain_test_challenge",
            "code_challenge_method": "plain",
            "scope": "citizen"
        })
        # Should redirect back with error=invalid_request or render 400
        if resp.status_code == 302:
            self.assertIn("invalid_request", resp.headers.get("Location", ""))
        else:
            self.assertEqual(resp.status_code, 400)

    def test_c7_missing_state_parameter(self):
        """[FAIL EXPECTED] /oauth/authorize should mandate 'state' parameter to enforce CSRF protection."""
        resp = self.app.get("/oauth/authorize", query_string={
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
            "scope": "citizen"
            # state intentionally omitted
        })
        # Per OAuth 2.1 RFC 9700 Security Best Current Practice, state is required for CSRF mitigation
        if resp.status_code == 302:
            self.assertIn("error", resp.headers.get("Location", ""), "Missing state should be rejected")
        else:
            self.assertEqual(resp.status_code, 400, "Missing state parameter accepted")

    def test_c8_register_javascript_uri_rejected(self):
        """Dynamic client registration with javascript: redirect_uri must be rejected."""
        resp = self.app.post("/oauth/register", json={
            "client_name": "XSS Client",
            "redirect_uris": ["javascript:alert(1)"]
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_redirect_uri")

    def test_c9_register_non_loopback_http_rejected(self):
        """Dynamic client registration with plaintext non-loopback http:// URI must be rejected."""
        resp = self.app.post("/oauth/register", json={
            "client_name": "Insecure HTTP Client",
            "redirect_uris": ["http://insecure-external-website.com/cb"]
        })
        self.assertEqual(resp.status_code, 400)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_redirect_uri")

    def test_c10_refresh_token_reuse_family_revocation(self):
        """[FAIL EXPECTED] Reusing an old refresh token must trigger compromise revocation of all issued tokens."""
        # Issue initial tokens
        code = self._create_auth_code()
        resp1 = self.app.post("/oauth/token", data={
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": self.verifier
        })
        data1 = resp1.get_json()
        rt1 = data1["refresh_token"]

        # First refresh -> rotates to rt2
        resp2 = self.app.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": rt1
        })
        self.assertEqual(resp2.status_code, 200)
        data2 = resp2.get_json()
        rt2 = data2["refresh_token"]

        # Attacker / replay presents old rt1 again
        resp_reuse = self.app.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": rt1
        })
        self.assertEqual(resp_reuse.status_code, 400)

        # Under OAuth 2.1 Section 4.3.3, detecting reuse of rt1 MUST revoke the whole family, including rt2!
        # Test if rt2 is still active or revoked:
        resp_check = self.app.post("/oauth/token", data={
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "refresh_token": rt2
        })
        self.assertEqual(
            resp_check.status_code, 400,
            "Compromise detection missing: reusing rotated refresh token rt1 did not revoke legitimate active token rt2"
        )


if __name__ == "__main__":
    unittest.main()
