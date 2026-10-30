# -*- coding: utf-8 -*-
"""
tests/security/sec_g_leaks.py: Threat G - Sensitive Data Leaks & Information Disclosure
Checks:
  - /__gateway/ exposes all other numbers' OTPs when ?to= is omitted (FAIL EXPECTED: G-01)
  - /__gateway/ console exposes live SMS traffic without auth (FAIL EXPECTED: G-02)
  - Stack trace / Python ValueError leak in MCP tool errors (FAIL EXPECTED: G-03)
  - Database schema error leak in tool responses (FAIL EXPECTED: G-04)
"""

import os
import sys
import time
import json
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")

import server
import auth
import services
import importlib.util

spec = importlib.util.spec_from_file_location("smsgw_app", os.path.join(BASE_DIR, "smsgw", "app.py"))
smsgw_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smsgw_module)


class TestThreatGLeaks(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sec_g_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app_mcp = server.app.test_client()
        self.app_gw = smsgw_module.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer
        now = int(time.time())

        # Officer token
        o_claims = {
            "iss": self.issuer, "sub": "officer:admin", "aud": f"{self.issuer}/mcp/officer",
            "role": "officer", "scope": "officer", "iat": now, "exp": now + 1800, "jti": "jti_go"
        }
        self.o_token = jwt.encode(o_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_g_kid"})

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def test_g1_gateway_exposes_all_otps_without_recipient_filter(self):
        """[FAIL EXPECTED] Calling SMS gateway /api/messages without ?to= must not dump entire inbox."""
        now = time.time()
        smsgw_module.MESSAGES.clear()
        smsgw_module.MESSAGES.extend([
            {"id": 1, "to": "9990001111", "text": "Your OTP is 112233", "sent_at": now - 10, "delivery_at": now - 5},
            {"id": 2, "to": "9990002222", "text": "Your OTP is 445566", "sent_at": now - 10, "delivery_at": now - 5},
        ])

        resp = self.app_gw.get("/api/messages")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        messages = data.get("messages", [])

        self.assertEqual(
            len(messages), 0,
            "SMS gateway returned all global OTP messages when recipient 'to' parameter was omitted"
        )

    def test_g2_gateway_console_public_exposure(self):
        """[FAIL EXPECTED] Gateway web console / renders confidential OTP messages without authentication."""
        now = time.time()
        smsgw_module.MESSAGES.clear()
        smsgw_module.MESSAGES.append(
            {"id": 1, "to": "9990009999", "text": "SECRET_OTP_789012", "sent_at": now - 10, "delivery_at": now - 5}
        )

        resp = self.app_gw.get("/")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)

        self.assertNotIn(
            "SECRET_OTP_789012", html,
            "Gateway root console / renders confidential citizen OTPs in plaintext to unauthenticated clients"
        )

    def test_g3_internal_python_value_error_leaked(self):
        """[FAIL EXPECTED] Passing non-numeric argument to tool leaks internal Python ValueError message."""
        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "get_application", "arguments": {"app_id": "not_an_int"}}
        }
        resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json() or {}
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")

        self.assertNotIn(
            "invalid literal for int()", content,
            "Internal Python exception message (invalid literal for int()) was leaked in tool response"
        )

    def test_g4_sql_error_leaked_in_tool_response(self):
        """[FAIL EXPECTED] Database schema constraint errors leaked in tool error responses."""
        import secrets
        rnd_mobile = f"99{secrets.randbelow(100000000):08d}"
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_TEST_LEAK', 'Leak Test User', %s, '1950-01-01', 'Sonari', 'Sonari', '999988887779', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id""",
            (rnd_mobile,)
        )
        app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 11, "method": "tools/call",
            "params": {"name": "approve_application", "arguments": {"app_id": app_id, "note": "Z" * 600}}
        }
        resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
        data = resp.get_json() or {}
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")

        # Clean up
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (app_id,))
        conn.commit()
        cur.close()
        conn.close()

        self.assertNotIn(
            "character varying", content,
            "Database schema information (character varying) leaked to client in error message"
        )

    def test_g5_log_leak_sensitive_data(self):
        """[FAIL EXPECTED] Application and MCP logs must not contain OTPs, passwords, tokens, or full bank numbers."""
        import logging
        import io

        log_stream = io.StringIO()
        handler = logging.StreamHandler(log_stream)
        handler.setLevel(logging.DEBUG)

        root_logger = logging.getLogger()
        root_logger.addHandler(handler)

        test_mobile = "9998889999"
        test_bank_acc = "987654321098"
        test_pwd = os.environ.get("ADMIN_PASSWORD", "TestAdminPassword123!")

        # 1. Citizen flow: request OTP
        portal_app = importlib.import_module("app").app.test_client()
        with portal_app.session_transaction() as sess:
            sess["captcha_answer"] = 12
        portal_app.post("/apply", data={"mobile": test_mobile, "captcha": "12"})

        # 2. Officer login flow
        portal_app.post("/admin", data={"username": "admin", "password": test_pwd})

        # 3. Citizen MCP prepare application
        req_c = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "prepare_application",
                "arguments": {
                    "applicant_name": "Log Test User", "dob": "01/01/1950", "gender": "Female",
                    "marital_status": "Widowed", "husband_name": "", "village": "Sonari", "block": "Sonari",
                    "bank_account": test_bank_acc, "ifsc": "SBIN0003077"
                }
            }
        }
        # Mint token
        now = int(time.time())
        c_claims = {
            "iss": self.issuer, "sub": f"citizen:{test_mobile}", "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen", "scope": "citizen", "iat": now, "exp": now + 1800, "jti": "jti_log"
        }
        c_tok = jwt.encode(c_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_g_kid"})
        self.app_mcp.post("/mcp/citizen", headers={"Authorization": f"Bearer {c_tok}"}, json=req_c)

        root_logger.removeHandler(handler)
        logs = log_stream.getvalue()

        # Sensitive data assertions
        self.assertNotIn(test_pwd, logs, "Plaintext admin password leaked into server logs")
        self.assertNotIn(test_bank_acc, logs, "Full unmasked bank account number leaked into server logs")
        self.assertNotIn(c_tok, logs, "Raw JWT access token leaked into server logs")


if __name__ == "__main__":
    unittest.main()

