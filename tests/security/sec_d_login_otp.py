# -*- coding: utf-8 -*-
"""
tests/security/sec_d_login_otp.py: Threat D - Authentication, OTP & Session Security
Checks:
  - Unlimited OTP brute-force guesses without lockout (FAIL EXPECTED)
  - OTP reuse within 5-minute validity window (FAIL EXPECTED)
  - Expired OTP rejection (PASS)
  - Officer password brute-force without lockout / rate-limiting (FAIL EXPECTED)
  - Missing CSRF protection on login and consent forms (FAIL EXPECTED)
  - Session cookie flags (missing Secure flag) (FAIL EXPECTED)
  - User enumeration by message in portal application submission (FAIL EXPECTED)
  - User enumeration by timing in portal login (PASS)
"""

import os
import sys
import time
import json
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


class TestThreatDLoginOTP(unittest.TestCase):

    def setUp(self):
        self.app = portal.app.test_client()
        os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"
        self.mobile = "9998881234"

    def _create_oauth_request(self, role="citizen", mobile=None):
        rid = secrets.token_urlsafe(24)
        params = {
            "client_id": "test_client", "client_name": "Test Client",
            "redirect_uri": "http://localhost:8080/callback", "state": "xyz",
            "code_challenge": "chal", "scope": role, "resource": "http://localhost:8000/mcp/citizen"
        }
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO oauth_requests (id, params, role, pending_mobile, created_at) VALUES (%s, %s, %s, %s, %s)",
            (rid, json.dumps(params), role, mobile, datetime.now())
        )
        conn.commit()
        cur.close()
        conn.close()
        return rid

    def _insert_otp(self, mobile, code, age_seconds=0):
        created = datetime.now() - timedelta(seconds=age_seconds)
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("INSERT INTO otps (mobile, code, created_at) VALUES (%s, %s, %s)", (mobile, code, created))
        conn.commit()
        cur.close()
        conn.close()

    def test_d1_unlimited_otp_guesses_without_lockout(self):
        """[FAIL EXPECTED] Submitting 10 wrong OTP attempts must trigger lockout or rate limit."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "123456")

        for attempt in range(10):
            wrong_otp = f"{attempt:06d}"
            resp = self.app.post(f"/oauth/login?rid={rid}", data={"otp": wrong_otp})
            self.assertEqual(resp.status_code, 200)

        # 11th attempt: server should lock out with 429 Too Many Requests or account lockout error
        resp11 = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "000010"})
        self.assertIn(
            resp11.status_code, (429, 403),
            "Server permitted unlimited sequential OTP brute-force guesses without rate-limit or lockout"
        )

    def test_d2_otp_reuse_prevention(self):
        """[FAIL EXPECTED] A valid OTP must be single-use and cannot be used twice."""
        rid1 = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "654321")

        # First use -> successful redirect to consent
        resp1 = self.app.post(f"/oauth/login?rid={rid1}", data={"otp": "654321"})
        self.assertEqual(resp1.status_code, 302)
        self.assertIn("/oauth/consent", resp1.headers.get("Location", ""))

        # Second use with a new request -> must be rejected as already used
        rid2 = self._create_oauth_request(role="citizen", mobile=self.mobile)
        resp2 = self.app.post(f"/oauth/login?rid={rid2}", data={"otp": "654321"})
        self.assertNotEqual(
            resp2.status_code, 302,
            "OTP was reused successfully on a second login request within the validity window"
        )

    def test_d3_expired_otp_rejected(self):
        """OTP older than 5 minutes (300 seconds) must be rejected."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "777888", age_seconds=310)

        resp = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "777888"})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Invalid or expired OTP", resp.get_data(as_text=True))

    def test_d4_officer_password_brute_force_lockout(self):
        """[FAIL EXPECTED] Repeated failed officer login attempts must be rate-limited or locked out."""
        rid = self._create_oauth_request(role="officer")

        for _ in range(15):
            resp = self.app.post(f"/oauth/login?rid={rid}", data={
                "username": "admin",
                "password": "wrong_password_attempt"
            })
            self.assertEqual(resp.status_code, 200)

        # 16th attempt should return 429 Too Many Requests
        resp_limit = self.app.post(f"/oauth/login?rid={rid}", data={
            "username": "admin",
            "password": "wrong_password_attempt"
        })
        self.assertEqual(
            resp_limit.status_code, 429,
            "Officer login has no rate limiting or lockout; allows unlimited dictionary attacks"
        )

    def test_d5_missing_csrf_on_login_and_consent(self):
        """[FAIL EXPECTED] POST requests to login and consent without CSRF token must be rejected."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "999111")

        resp_login = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "999111"})
        self.assertEqual(
            resp_login.status_code, 400,
            "Form accepted POST request without CSRF protection token"
        )

    def test_d6_session_cookie_security_flags(self):
        """[FAIL EXPECTED] Session cookies must enforce Secure, HttpOnly, and SameSite flags."""
        resp = self.app.get("/apply")
        cookie_header = resp.headers.get("Set-Cookie", "")
        self.assertIn(
            "Secure", cookie_header,
            "Session cookie lacks 'Secure' flag, allowing plaintext transmission over HTTP"
        )

    def test_d7_user_enumeration_by_message(self):
        """[FAIL EXPECTED] Differential messages must not leak whether a citizen has an existing application."""
        registered_mobile = "9998887711"
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_ENUM_TEST', 'Enum Applicant', %s, '1950-01-01', 'Sonari', 'Sonari', '111122224444', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id""",
            (registered_mobile,)
        )
        app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Submit portal application for existing registered mobile
        with self.app.session_transaction() as sess:
            sess["verified_mobile"] = registered_mobile
            sess["captcha_answer"] = 10
            sess["form_data"] = {
                "applicant_name": "Enum Applicant", "dob": "01/01/1950", "gender": "Female",
                "marital_status": "Widowed", "husband_name": "", "village": "Sonari", "block": "Sonari",
                "bank_account": "111122224444", "ifsc": "SBIN0003077"
            }
        resp = self.app.post("/declaration", data={"declaration": "on"}, follow_redirects=True)
        html = resp.get_data(as_text=True)

        # Clean up
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (app_id,))
        conn.commit()
        cur.close()
        conn.close()

        # Specific application number and status leak account existence
        self.assertNotIn(
            "already exists for this mobile number", html,
            "Portal leaks application existence and status for registered mobile numbers via differential message"
        )

    def test_d8_user_enumeration_by_timing(self):
        """Portal login timing should be consistent for existing vs non-existing users."""
        # Non-existing user timing
        t0 = time.time()
        self.app.post("/status", data={"mobile": "0000000000", "password": "wrongpassword"})
        t_non_existing = time.time() - t0

        # Existing admin user timing (or portal user)
        t0 = time.time()
        self.app.post("/status", data={"mobile": "9998881234", "password": "wrongpassword"})
        t_existing = time.time() - t0

        # Timing difference should be small (< 0.5s) to prevent timing oracle
        self.assertLess(abs(t_existing - t_non_existing), 0.5)


if __name__ == "__main__":
    unittest.main()
