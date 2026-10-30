# -*- coding: utf-8 -*-
"""
tests/security/test_e_injection.py: Threat E - Injection Attacks & Input Sanitization
Checks:
  - SQL injection defenses (PASS)
  - XSS payload stored without HTML tag sanitization (FAIL EXPECTED)
  - Embedded null bytes in free-text fields causing DB error (FAIL EXPECTED)
  - Excessive length and unescaped control characters in audit notes (FAIL EXPECTED)
"""

import os
import sys
import json
import time
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
import officer


class TestThreatEInjection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sec_inj_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app = server.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer
        now = int(time.time())

        # Citizen token
        c_claims = {
            "iss": self.issuer, "sub": "citizen:9990009999", "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen", "iat": now, "exp": now + 1800, "jti": "jti_c"
        }
        self.c_token = jwt.encode(c_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_inj_kid"})

        # Officer token
        o_claims = {
            "iss": self.issuer, "sub": "officer:admin", "aud": f"{self.issuer}/mcp/officer",
            "role": "officer", "iat": now, "exp": now + 1800, "jti": "jti_o"
        }
        self.o_token = jwt.encode(o_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_inj_kid"})

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def test_e1_sql_injection_defense(self):
        """SQL injection strings in filters and queries must not alter query logic (parameterized queries)."""
        sqli_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE applications; --",
            "1' UNION SELECT NULL, NULL, NULL, NULL, NULL, NULL, NULL--",
        ]
        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        for payload in sqli_payloads:
            req = {
                "jsonrpc": "2.0", "id": 1, "method": "tools/call",
                "params": {"name": "list_applications", "arguments": {"block": payload, "status": payload}}
            }
            resp = self.app.post("/mcp/officer", headers=headers, json=req)
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertNotIn("syntax error", str(data).lower())

    def test_e2_xss_storage_without_sanitization(self):
        """[FAIL EXPECTED] XSS tags must be sanitized or stripped before persistence; sanitize() currently allows them."""
        xss_string = "<script>alert('XSS')</script>"
        sanitized = services.sanitize(xss_string)
        # services.sanitize only slices length and strips whitespace; leaves HTML tags intact
        self.assertNotIn(
            "<script>", sanitized,
            "services.sanitize() failed to neutralize executable HTML/JavaScript tags"
        )

    def test_e3_embedded_null_byte_handling(self):
        """[FAIL EXPECTED] Embedded null bytes in input strings cause unhandled ValueError from psycopg2."""
        null_byte_str = "Sundari\x00Bai"
        conn = services.get_db()
        cur = conn.cursor()
        failed_with_null_byte = False
        try:
            cur.execute(
                """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
                   VALUES ('SSP_NULL_TEST', %s, '9990009997', '1950-01-01', 'Sonari', 'Sonari', '999988887776', 'SBIN0003077', 'PENDING', NOW())""",
                (null_byte_str,)
            )
            conn.commit()
        except ValueError as e:
            conn.rollback()
            failed_with_null_byte = "nul" in str(e).lower() or "null" in str(e).lower()
        finally:
            cur.close()
            conn.close()

        # Input sanitization should strip null bytes before DB operations
        self.assertFalse(
            failed_with_null_byte,
            "services.sanitize() did not strip null byte; caused unhandled ValueError in database driver"
        )

    def test_e4_excessive_length_and_control_chars_in_notes(self):
        """[FAIL EXPECTED] Officer decision notes exceeding 500 chars leak internal DB StringDataRightTruncation error."""
        import secrets
        rnd_mobile = f"99{secrets.randbelow(100000000):08d}"
        bloated_note = ("A" * 600)
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_TEST_NOTE', 'Test User', %s, '1950-01-01', 'Sonari', 'Sonari', '999988887777', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id""",
            (rnd_mobile,)
        )
        app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "approve_application", "arguments": {"app_id": app_id, "note": bloated_note}}
        }
        resp = self.app.post("/mcp/officer", headers=headers, json=req)
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
            "varying(500)", content,
            "Officer tool leaked internal database column limit error (varying(500)) to client"
        )


if __name__ == "__main__":
    unittest.main()
