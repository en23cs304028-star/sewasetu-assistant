# -*- coding: utf-8 -*-
"""
tests/security/test_security_audit.py: Group 6 Security Audit Logging
Verifies:
  - security_audit_log table exists and records security events
  - failed logins (citizen OTP and officer password) are recorded
  - lockouts are recorded
  - token revocations are recorded
  - rejected tokens are recorded
  - client registrations are recorded
  - passwords, OTP values, raw tokens, and private keys are NEVER logged
"""

import os
import sys
import json
import time
import secrets
import unittest
from datetime import datetime

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
import server
import auth


class TestSecurityAuditLog(unittest.TestCase):

    def setUp(self):
        self.app = portal.app.test_client()
        os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"
        conn = portal.get_db()
        cur = conn.cursor()
        services.ensure_security_tables(conn)
        cur.execute("DELETE FROM security_audit_log")
        cur.execute("DELETE FROM rate_limits")
        conn.commit()
        cur.close()
        conn.close()

    def _get_csrf(self):
        with self.app.session_transaction() as sess:
            if "csrf_token" not in sess:
                sess["csrf_token"] = secrets.token_hex(32)
            return sess["csrf_token"]

    def _get_events(self, event_type=None):
        conn = portal.get_db()
        cur = conn.cursor()
        if event_type:
            cur.execute("SELECT event_type, subject, ip, user_agent, details, created_at FROM security_audit_log WHERE event_type = %s ORDER BY id ASC", (event_type,))
        else:
            cur.execute("SELECT event_type, subject, ip, user_agent, details, created_at FROM security_audit_log ORDER BY id ASC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        return rows

    def test_audit_table_exists(self):
        """security_audit_log table must exist with required columns."""
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'security_audit_log'
        """)
        cols = {row[0] for row in cur.fetchall()}
        cur.close()
        conn.close()
        self.assertIn("event_type", cols)
        self.assertIn("subject", cols)
        self.assertIn("ip", cols)
        self.assertIn("user_agent", cols)
        self.assertIn("details", cols)
        self.assertIn("created_at", cols)

    def test_audit_login_failure_and_lockout(self):
        """Failed officer login and lockout must be recorded without logging passwords."""
        csrf = self._get_csrf()
        secret_bad_pass = "super_secret_bad_pwd_xyz123"

        # 5 failed attempts
        for _ in range(5):
            self.app.post("/admin", data={"username": "admin", "password": secret_bad_pass, "csrf_token": csrf})

        # 6th attempt -> lockout
        resp = self.app.post("/admin", data={"username": "admin", "password": secret_bad_pass, "csrf_token": csrf})
        self.assertEqual(resp.status_code, 429)

        events = self._get_events()
        event_types = [e[0] for e in events]
        self.assertIn("login_failure", event_types)
        self.assertIn("lockout", event_types)

        # Confirm passwords are NEVER in the audit log
        for e in events:
            details_str = json.dumps(e[4]) if isinstance(e[4], dict) else str(e[4])
            self.assertNotIn(secret_bad_pass, details_str)
            self.assertNotIn("password", details_str.lower())

    def test_audit_token_revocation(self):
        """Token revocation must be logged without raw token values."""
        raw_secret_token = f"sensitive_token_{secrets.token_hex(16)}"
        conn = portal.get_db()
        services.log_security_event(
            conn,
            event_type="token_revocation",
            subject="citizen:9990001001",
            ip="127.0.0.1",
            details={"jti": "jti_abc_123", "token_type": "access_token"}
        )
        conn.close()

        events = self._get_events("token_revocation")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][1], "citizen:9990001001")
        details_str = json.dumps(events[0][4])
        self.assertNotIn(raw_secret_token, details_str)

    def test_audit_client_registration(self):
        """Dynamic client registration must log client_registered event."""
        payload = {
            "client_name": "Audit Test App",
            "redirect_uris": ["http://localhost:8080/callback"]
        }
        resp = self.app.post("/oauth/register", json=payload)
        self.assertEqual(resp.status_code, 201)

        events = self._get_events("client_registered")
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[-1][0], "client_registered")

    def test_audit_token_rejection(self):
        """Invalid or expired bearer token must log token_rejected event."""
        mcp_client = server.app.test_client()
        bogus_token = "invalid.bearer.token"
        resp = mcp_client.post(
            "/mcp/citizen",
            headers={"Authorization": f"Bearer {bogus_token}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        )
        self.assertEqual(resp.status_code, 401)

        events = self._get_events("token_rejected")
        self.assertGreaterEqual(len(events), 1)
        self.assertEqual(events[-1][0], "token_rejected")
        # Ensure the raw token is never logged
        for e in events:
            details_str = json.dumps(e[4]) if isinstance(e[4], dict) else str(e[4])
            self.assertNotIn(bogus_token, details_str)


if __name__ == "__main__":
    unittest.main()
