# -*- coding: utf-8 -*-
"""
tests/security/sec_e_injection.py: Threat E - Injection Attacks & Input Sanitization
Checks:
  - SQL injection defenses (PASS)
  - Autoescape active on render paths; portal/dashboard escape HTML tags (PASS)
  - Audit that no Jinja template disables autoescaping via |safe (PASS)
  - Embedded null bytes in free-text fields cause unhandled DB error (FAIL EXPECTED: E-02)
  - Excessive length decision notes leak internal DB column truncation error (FAIL EXPECTED: E-03)
"""

import os
import re
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

import app as portal
import server
import auth
import services


class TestThreatEInjection(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sec_inj_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app_mcp = server.app.test_client()
        self.app_portal = portal.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer
        now = int(time.time())

        # Officer token
        o_claims = {
            "iss": self.issuer, "sub": "officer:admin", "aud": f"{self.issuer}/mcp/officer",
            "role": "officer", "iat": now, "nbf": now, "exp": now + 1800, "jti": "jti_o"
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
            resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertNotIn("syntax error", str(data).lower())

    def test_e2_no_template_uses_safe_filter(self):
        """Assert that no Jinja template uses |safe to bypass autoescaping."""
        templates_dir = os.path.join(BASE_DIR, "app", "templates")
        violations = []
        safe_pattern = re.compile(r"\|\s*safe\b", re.IGNORECASE)

        for fname in os.listdir(templates_dir):
            if fname.endswith(".html"):
                fpath = os.path.join(templates_dir, fname)
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                    matches = safe_pattern.findall(content)
                    if matches:
                        violations.append(f"{fname} ({len(matches)} occurrences)")

        self.assertEqual(
            violations, [],
            f"Templates found using '|safe' filter, which bypasses HTML autoescaping: {violations}"
        )

    def test_e3_render_paths_escape_html_output(self):
        """Verify that portal render paths autoescape HTML tags in user-supplied data."""
        # Test Jinja autoescape by rendering user data containing script tag
        conn = services.get_db()
        cur = conn.cursor()
        xss_name = "<script>alert('XSS')</script>"
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_XSS_TEST', %s, '9990008888', '1950-01-01', 'Sonari', 'Sonari', '999988887771', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id""",
            (xss_name,)
        )
        app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Admin view render
        with self.app_portal.session_transaction() as sess:
            sess["admin"] = True
            sess["admin_user"] = "admin"

        resp = self.app_portal.get(f"/admin/application/{app_id}")
        html = resp.get_data(as_text=True)

        # Clean up
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (app_id,))
        conn.commit()
        cur.close()
        conn.close()

        # Must be escaped as &lt;script&gt; and NOT raw <script>
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_e4_embedded_null_byte_handling(self):
        """Embedded null bytes in input strings are stripped by services.sanitize() to prevent DB errors."""
        null_byte_str = "Sundari\x00Bai"
        clean_name = services.sanitize(null_byte_str)
        self.assertNotIn("\x00", clean_name)
        conn = services.get_db()
        cur = conn.cursor()
        failed_with_null_byte = False
        try:
            cur.execute(
                """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
                   VALUES ('SSP_NULL_TEST', %s, '9990009997', '1950-01-01', 'Sonari', 'Sonari', '999988887776', 'SBIN0003077', 'PENDING', NOW())""",
                (clean_name,)
            )
            conn.commit()
            # Clean up test row
            cur.execute("DELETE FROM applications WHERE application_no = 'SSP_NULL_TEST'")
            conn.commit()
        except ValueError as e:
            conn.rollback()
            failed_with_null_byte = "nul" in str(e).lower() or "null" in str(e).lower()
        finally:
            cur.close()
            conn.close()

        self.assertFalse(
            failed_with_null_byte,
            "services.sanitize() did not strip null byte; caused unhandled ValueError in database driver"
        )

    def test_e5_excessive_length_and_control_chars_in_notes(self):
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
            "varying(500)", content,
            "Officer tool leaked internal database column limit error (varying(500)) to client"
        )


if __name__ == "__main__":
    unittest.main()
