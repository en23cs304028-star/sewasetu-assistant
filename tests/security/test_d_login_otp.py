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
        conn = portal.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM rate_limits")
        cur.execute("DELETE FROM otps WHERE mobile LIKE '999%'")
        conn.commit()
        cur.close()
        conn.close()

    def _get_csrf_token(self):
        with self.app.session_transaction() as sess:
            if "csrf_token" not in sess:
                sess["csrf_token"] = secrets.token_hex(32)
            return sess["csrf_token"]

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
        cur.execute("INSERT INTO otps (mobile, code, created_at, attempts, used_at) VALUES (%s, %s, %s, 0, NULL)",
                    (mobile, code, created))
        conn.commit()
        cur.close()
        conn.close()

    def test_d1_unlimited_otp_guesses_without_lockout(self):
        """[FIXED] Submitting 10 wrong OTP attempts triggers lockout / rate limit (429 with Retry-After)."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "123456")
        csrf = self._get_csrf_token()

        for attempt in range(10):
            wrong_otp = f"{attempt:06d}"
            resp = self.app.post(f"/oauth/login?rid={rid}", data={"otp": wrong_otp, "csrf_token": csrf})
            self.assertEqual(resp.status_code, 200)

        # 11th attempt: server locks out with 429 Too Many Requests
        resp11 = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "000010", "csrf_token": csrf})
        self.assertEqual(
            resp11.status_code, 429,
            "Server permitted sequential OTP brute-force guesses without rate-limit or lockout"
        )
        self.assertIn("Retry-After", resp11.headers)

    def test_d2_otp_reuse_prevention(self):
        """[FIXED] A valid OTP must be single-use and cannot be used twice."""
        rid1 = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "654321")
        csrf = self._get_csrf_token()

        # First use -> successful redirect to consent
        resp1 = self.app.post(f"/oauth/login?rid={rid1}", data={"otp": "654321", "csrf_token": csrf})
        self.assertEqual(resp1.status_code, 302)
        self.assertIn("/oauth/consent", resp1.headers.get("Location", ""))

        # Second use with a new request -> must be rejected as already used
        rid2 = self._create_oauth_request(role="citizen", mobile=self.mobile)
        resp2 = self.app.post(f"/oauth/login?rid={rid2}", data={"otp": "654321", "csrf_token": csrf})
        self.assertNotEqual(
            resp2.status_code, 302,
            "OTP was reused successfully on a second login request within the validity window"
        )
        self.assertEqual(resp2.status_code, 200)
        self.assertIn("Invalid or expired OTP", resp2.get_data(as_text=True))

    def test_d3_expired_otp_rejected(self):
        """OTP older than 5 minutes (300 seconds) must be rejected."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "777888", age_seconds=310)
        csrf = self._get_csrf_token()

        resp = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "777888", "csrf_token": csrf})
        self.assertEqual(resp.status_code, 200)
        self.assertIn("Invalid or expired OTP", resp.get_data(as_text=True))

    def test_d4_officer_password_brute_force_lockout(self):
        """[FIXED] Lockout after 5 failed officer login attempts per IP/user (429 with Retry-After)."""
        rid = self._create_oauth_request(role="officer")
        csrf = self._get_csrf_token()

        for _ in range(5):
            resp = self.app.post(f"/oauth/login?rid={rid}", data={
                "username": "admin",
                "password": "wrong_password_attempt",
                "csrf_token": csrf
            })
            self.assertEqual(resp.status_code, 200)

        # 6th attempt should return 429 Too Many Requests with Retry-After header
        resp_limit = self.app.post(f"/oauth/login?rid={rid}", data={
            "username": "admin",
            "password": "wrong_password_attempt",
            "csrf_token": csrf
        })
        self.assertEqual(
            resp_limit.status_code, 429,
            "Officer login has no rate limiting or lockout; allows unlimited dictionary attacks"
        )
        self.assertIn("Retry-After", resp_limit.headers)

    def test_d5_missing_csrf_on_login_and_consent(self):
        """[FIXED] POST requests to login and consent without CSRF token must be rejected with 400."""
        rid = self._create_oauth_request(role="citizen", mobile=self.mobile)
        self._insert_otp(self.mobile, "999111")

        # 1. Login without CSRF token -> rejected with 400
        resp_login = self.app.post(f"/oauth/login?rid={rid}", data={"otp": "999111"})
        self.assertEqual(
            resp_login.status_code, 400,
            "Form accepted POST request without CSRF protection token"
        )

        # 2. Consent without CSRF token -> rejected with 400
        resp_consent = self.app.post(f"/oauth/consent?rid={rid}", data={"decision": "allow"})
        self.assertEqual(
            resp_consent.status_code, 400,
            "Consent accepted POST request without CSRF protection token"
        )

    def test_d6_session_cookie_security_flags(self):
        """[FIXED] Session cookies enforce HttpOnly and SameSite=Lax; Secure flag only when PUBLIC_BASE_URL starts with https."""
        # 1. Plain HTTP environment: HttpOnly and SameSite=Lax set, Secure flag omitted
        os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"
        resp_http = self.app.get("/apply")
        cookie_http = resp_http.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie_http)
        self.assertIn("SameSite=Lax", cookie_http)
        self.assertNotIn("Secure", cookie_http)

        # 2. HTTPS environment: Secure flag enforced alongside HttpOnly and SameSite=Lax
        os.environ["PUBLIC_BASE_URL"] = "https://sewasetu.assam.gov.in"
        resp_https = self.app.get("/apply")
        cookie_https = resp_https.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie_https)
        self.assertIn("SameSite=Lax", cookie_https)
        self.assertIn("Secure", cookie_https)

        # Reset
        os.environ["PUBLIC_BASE_URL"] = "http://localhost:8000"

    def test_d7_user_enumeration_by_message(self):
        """[FIXED] Responses and status codes are uniform across known and unknown identities."""
        csrf = self._get_csrf_token()
        registered_mobile = "9998887711"

        # 1. OAuth OTP request path: responses must be identical for known and unknown mobiles
        rid_known = self._create_oauth_request(role="citizen")
        resp_known = self.app.post(f"/oauth/login?rid={rid_known}", data={"mobile": registered_mobile, "csrf_token": csrf})
        rid_unknown = self._create_oauth_request(role="citizen")
        resp_unknown = self.app.post(f"/oauth/login?rid={rid_unknown}", data={"mobile": "9990000000", "csrf_token": csrf})
        self.assertEqual(
            resp_known.status_code, resp_unknown.status_code,
            "OAuth OTP request returned different status codes for known vs unknown mobile numbers"
        )

        # 2. Officer login path: unknown username vs known username
        rid_officer = self._create_oauth_request(role="officer")
        resp_off_known = self.app.post(f"/oauth/login?rid={rid_officer}", data={"username": "admin", "password": "wrong", "csrf_token": csrf})
        resp_off_unknown = self.app.post(f"/oauth/login?rid={rid_officer}", data={"username": "nonexistent_officer", "password": "wrong", "csrf_token": csrf})
        self.assertEqual(
            resp_off_known.status_code, resp_off_unknown.status_code,
            "Officer login returned different status codes for known vs unknown username"
        )
        self.assertEqual(
            resp_off_known.get_data(as_text=True), resp_off_unknown.get_data(as_text=True),
            "Officer login returned different response bodies for known vs unknown username"
        )

    def test_d8_user_enumeration_by_timing(self):
        """Timing difference between known and unknown identities must be <= 50 ms across 20 samples."""
        import statistics
        csrf = self._get_csrf_token()

        def get_median_latency(request_fn, samples=20):
            times = []
            for _ in range(samples):
                t0 = time.perf_counter()
                request_fn()
                times.append(time.perf_counter() - t0)
            return statistics.median(times)

        # 1. Status portal login timing
        med_non_existing = get_median_latency(
            lambda: self.app.post("/status", data={"mobile": "0000000000", "password": "wrongpassword", "csrf_token": csrf})
        )
        med_existing = get_median_latency(
            lambda: self.app.post("/status", data={"mobile": "9998881234", "password": "wrongpassword", "csrf_token": csrf})
        )
        diff_portal = abs(med_existing - med_non_existing)
        self.assertLess(
            diff_portal, 0.050,
            f"Status login timing difference ({diff_portal*1000:.1f}ms) exceeds 50ms threshold (timing oracle)"
        )

        # 2. Officer login timing
        rid = self._create_oauth_request(role="officer")
        med_off_unknown = get_median_latency(
            lambda: self.app.post(f"/oauth/login?rid={rid}", data={"username": "nobody", "password": "wrongpassword", "csrf_token": csrf})
        )
        med_off_known = get_median_latency(
            lambda: self.app.post(f"/oauth/login?rid={rid}", data={"username": "admin", "password": "wrongpassword", "csrf_token": csrf})
        )
        diff_officer = abs(med_off_known - med_off_unknown)
        self.assertLess(
            diff_officer, 0.050,
            f"Officer login timing difference ({diff_officer*1000:.1f}ms) exceeds 50ms threshold (timing oracle)"
        )

        # 3. OAuth OTP request timing
        rid_c = self._create_oauth_request(role="citizen")
        med_otp_unknown = get_median_latency(
            lambda: self.app.post(f"/oauth/login?rid={rid_c}", data={"mobile": "0000000000", "csrf_token": csrf})
        )
        med_otp_known = get_median_latency(
            lambda: self.app.post(f"/oauth/login?rid={rid_c}", data={"mobile": "9998881234", "csrf_token": csrf})
        )
        diff_otp = abs(med_otp_known - med_otp_unknown)
        self.assertLess(
            diff_otp, 0.050,
            f"OAuth OTP request timing difference ({diff_otp*1000:.1f}ms) exceeds 50ms threshold (timing oracle)"
        )


if __name__ == "__main__":
    unittest.main()

