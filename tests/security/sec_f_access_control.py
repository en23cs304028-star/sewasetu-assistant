# -*- coding: utf-8 -*-
"""
tests/security/sec_f_access_control.py: Threat F - Access Control & Authorization Boundaries
Checks:
  - IDOR protection on portal application view (PASS)
  - IDOR protection on portal application withdrawal (PASS)
  - Citizen token calling officer MCP endpoint returns 403 Forbidden (PASS)
  - Officer token calling citizen MCP endpoint returns 403 Forbidden (PASS)
  - Officer action on missing application handled safely (PASS)
  - Officer action on already-decided application refused (PASS)
  - MCP get_my_status IDOR isolation (PASS)
  - MCP withdraw_application IDOR isolation (PASS)
  - MCP submit_application draft ownership isolation (PASS)
  - Public eval-dashboard results.json contains no credentials or tokens (PASS)
"""

import os
import sys
import time
import json
import secrets
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


class TestThreatFAccessControl(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sec_f_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app_mcp = server.app.test_client()
        self.app_portal = portal.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer
        now = int(time.time())

        # Citizen A token
        c_claims = {
            "iss": self.issuer, "sub": "citizen:9991112222", "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen", "scope": "citizen", "iat": now, "exp": now + 1800, "jti": "jti_fc"
        }
        self.c_token = jwt.encode(c_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_f_kid"})

        # Officer token
        o_claims = {
            "iss": self.issuer, "sub": "officer:admin", "aud": f"{self.issuer}/mcp/officer",
            "role": "officer", "scope": "officer", "iat": now, "exp": now + 1800, "jti": "jti_fo"
        }
        self.o_token = jwt.encode(o_claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_f_kid"})

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def test_f1_citizen_idor_view_other_application_prevented(self):
        """Logged-in citizen attempting to view another citizen's application ID receives 404."""
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_IDOR_1', 'Victim User', '9991113333', '1950-01-01', 'Sonari', 'Sonari', '111122223333', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id"""
        )
        victim_app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        with self.app_portal.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9991112222"

        resp = self.app_portal.get(f"/application/{victim_app_id}")

        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (victim_app_id,))
        conn.commit()
        cur.close()
        conn.close()

        self.assertEqual(resp.status_code, 404, "Citizen should not be able to view another citizen's application")

    def test_f2_citizen_idor_withdraw_other_application_prevented(self):
        """Logged-in citizen attempting to withdraw another citizen's application is blocked."""
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_IDOR_2', 'Victim User 2', '9991114444', '1950-01-01', 'Sonari', 'Sonari', '444422223333', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id"""
        )
        victim_app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        with self.app_portal.session_transaction() as sess:
            sess["logged_in"] = True
            sess["portal_mobile"] = "9991112222"

        resp = self.app_portal.post(f"/application/{victim_app_id}/withdraw")

        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT status FROM applications WHERE id = %s", (victim_app_id,))
        status = cur.fetchone()[0]
        cur.execute("DELETE FROM applications WHERE id = %s", (victim_app_id,))
        conn.commit()
        cur.close()
        conn.close()

        self.assertEqual(status, "PENDING", "Victim's application should not be withdrawn by another user")

    def test_f3_citizen_calling_officer_mcp_forbidden(self):
        """Citizen token calling officer MCP endpoint must return HTTP 403 Forbidden."""
        headers = {"Authorization": f"Bearer {self.c_token}", "Content-Type": "application/json"}
        req = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
        self.assertEqual(resp.status_code, 403)
        self.assertIn("forbidden", resp.get_data(as_text=True).lower())

    def test_f4_officer_calling_citizen_mcp_forbidden(self):
        """Officer token calling citizen MCP endpoint must return HTTP 403 / 401."""
        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        resp = self.app_mcp.post("/mcp/citizen", headers=headers, json=req)
        self.assertIn(resp.status_code, (401, 403))

    def test_f5_officer_action_on_missing_application(self):
        """Officer attempting action on non-existent application ID returns error gracefully."""
        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "approve_application", "arguments": {"app_id": 99999999, "note": "Approval test"}}
        }
        resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")
        self.assertIn("not found", content.lower())

    def test_f6_officer_action_on_already_decided_application(self):
        """Officer attempting to re-decide an already APPROVED application is refused."""
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at, decided_at, decided_by)
               VALUES ('SSP_DECIDED_1', 'Decided User', '9991115555', '1950-01-01', 'Sonari', 'Sonari', '555522223333', 'SBIN0003077', 'APPROVED', NOW(), NOW(), 'officer:admin')
               RETURNING id"""
        )
        decided_app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        headers = {"Authorization": f"Bearer {self.o_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "reject_application", "arguments": {"app_id": decided_app_id, "reason": "Attempting re-decision"}}
        }
        resp = self.app_mcp.post("/mcp/officer", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")

        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (decided_app_id,))
        conn.commit()
        cur.close()
        conn.close()

        self.assertIn("already decided", content.lower())

    def test_f8_idor_mcp_get_my_status(self):
        """Citizen A calling get_my_status receives only their own status, never Citizen B's."""
        # Insert app for Citizen B (9991113333)
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_STATUS_B', 'Citizen B', '9991113333', '1950-01-01', 'Borgaon', 'Borgaon', '333322221111', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id"""
        )
        b_app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Citizen A calls get_my_status
        headers = {"Authorization": f"Bearer {self.c_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 8, "method": "tools/call",
            "params": {"name": "get_my_status", "arguments": {}}
        }
        resp = self.app_mcp.post("/mcp/citizen", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")

        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM applications WHERE id = %s", (b_app_id,))
        conn.commit()
        cur.close()
        conn.close()

        self.assertNotIn("SSP_STATUS_B", content)
        self.assertNotIn("Citizen B", content)

    def test_f9_idor_mcp_withdraw_application(self):
        """Citizen A calling withdraw_application cannot withdraw Citizen B's pending application."""
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO applications (application_no, applicant_name, mobile, dob, village, block, bank_account, ifsc, status, submitted_at)
               VALUES ('SSP_WITHDRAW_B', 'Citizen B', '9991113333', '1950-01-01', 'Borgaon', 'Borgaon', '333322221111', 'SBIN0003077', 'PENDING', NOW())
               RETURNING id"""
        )
        b_app_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        conn.close()

        # Citizen A tries to withdraw
        headers = {"Authorization": f"Bearer {self.c_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 9, "method": "tools/call",
            "params": {"name": "withdraw_application", "arguments": {"confirm": True}}
        }
        resp = self.app_mcp.post("/mcp/citizen", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)

        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT status FROM applications WHERE id = %s", (b_app_id,))
        status_b = cur.fetchone()[0]
        cur.execute("DELETE FROM applications WHERE id = %s", (b_app_id,))
        conn.commit()
        cur.close()
        conn.close()

        # Citizen B's application must still be PENDING
        self.assertEqual(status_b, "PENDING")

    def test_f10_idor_mcp_submit_application(self):
        """Citizen A calling submit_application with Citizen B's draft is refused."""
        conn = services.get_db()
        cur = conn.cursor()
        draft_id, p_hash, conf_token, _ = services.create_draft(
            cur, "9991113333",  # Belonging to Citizen B
            {"applicant_name": "Citizen B", "dob": "01/01/1950", "village": "Sonari", "block": "Sonari",
             "bank_account": "123456789012", "ifsc": "SBIN0003077"}
        )
        conn.commit()
        cur.close()
        conn.close()

        # Citizen A submits Citizen B's confirmation token
        headers = {"Authorization": f"Bearer {self.c_token}", "Content-Type": "application/json"}
        req = {
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "submit_application", "arguments": {"confirmation_token": conf_token}}
        }
        resp = self.app_mcp.post("/mcp/citizen", headers=headers, json=req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")
        self.assertIn("not found or expired", content.lower())

    def test_f11_eval_results_json_no_secrets(self):
        """Verify that public results.json files contain no passwords, bearer tokens, or secret keys."""
        candidates = [
            os.path.join(BASE_DIR, "evals", "results.json"),
            os.path.join(BASE_DIR, "app", "evals", "results.json")
        ]
        for path in candidates:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    content = f.read().lower()
                self.assertNotIn("bearer ", content)
                self.assertNotIn("admin_password", content)
                self.assertNotIn("secret_key", content)
                self.assertNotIn("eyj", content)  # Common JWT token header prefix


if __name__ == "__main__":
    unittest.main()

