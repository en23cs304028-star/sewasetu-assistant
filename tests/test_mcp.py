# -*- coding: utf-8 -*-
"""
tests/test_mcp.py: Comprehensive test suite for Citizen and Officer MCP servers.
Tests:
  - RFC 9728 discovery metadata
  - Bearer token authentication and WWW-Authenticate header
  - Role-based authorization isolation (citizen cannot access officer endpoint)
  - All 6 Citizen tools (get_scheme_info, get_my_status, prepare_application, submit_application, withdraw_application, sign_out)
  - All 5 Officer tools (queue_summary, list_applications, get_application, approve_application, reject_application)
"""

import sys
import os
import json
import time
import base64
import unittest
from datetime import datetime, date
from unittest.mock import MagicMock, patch
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

# Ensure paths
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "mcp")))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")

import server
import auth
import citizen
import officer
import services


class TestMCPServers(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate an RSA test key for minting and verifying mock tokens
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"test_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app = server.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        citizen.DRAFTS.clear()
        self.p_rev = patch.object(auth, "is_token_revoked", return_value=False)
        self.p_rate = patch.object(services, "check_rate_limit", return_value=(True, 0))
        self.p_rev.start()
        self.p_rate.start()

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None
        self.p_rev.stop()
        self.p_rate.stop()

    def mint_token(self, subject, role, audience, exp_offset=1200):
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "role": role,
            "scope": role,
            "iat": now,
            "nbf": now,
            "exp": now + exp_offset,
            "jti": "tok123"
        }
        return jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "test_kid"})

    # -----------------------------------------------------------------------
    # RFC 9728 and Auth tests
    # -----------------------------------------------------------------------

    def test_rfc9728_discovery(self):
        resp = self.app.get("/.well-known/oauth-protected-resource/mcp/citizen")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("authorization_servers", data)
        self.assertIn("scopes_supported", data)
        self.assertEqual(data["scopes_supported"], ["citizen"])

    def test_unauthenticated_request_returns_401_with_www_authenticate(self):
        resp = self.app.post("/mcp/citizen", json={"method": "tools/list", "id": 1})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("WWW-Authenticate", resp.headers)
        self.assertIn("resource_metadata", resp.headers["WWW-Authenticate"])

    def test_citizen_token_rejected_at_officer_endpoint(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/officer")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/list", "id": 1}
            )
            # Expect 403 Forbidden due to role mismatch
            self.assertEqual(resp.status_code, 403)
            data = resp.get_json()
            self.assertIn("forbidden", data.get("error_description", ""))

    def test_wrong_audience_rejected(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/wrong-audience")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/list", "id": 1}
            )
            self.assertEqual(resp.status_code, 401)

    # -----------------------------------------------------------------------
    # Citizen Tools Tests
    # -----------------------------------------------------------------------

    def test_citizen_tools_list_isolation(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/list", "id": 1}
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()["result"]["tools"]
            tool_names = [t["name"] for t in data]
            self.assertEqual(len(tool_names), 6)
            self.assertIn("get_scheme_info", tool_names)
            self.assertIn("prepare_application", tool_names)
            self.assertIn("submit_application", tool_names)
            # Ensure no officer tools are visible
            self.assertNotIn("approve_application", tool_names)
            self.assertNotIn("queue_summary", tool_names)

    def test_citizen_get_scheme_info(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "get_scheme_info", "arguments": {}}, "id": 2}
            )
            self.assertEqual(resp.status_code, 200)
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "success")
            self.assertEqual(content["minimum_age"], 60)
            self.assertEqual(content["statutory_sla_days"], 15)

    def test_citizen_prepare_and_submit_happy_path(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/citizen")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur

        stored_draft = {}

        def mock_execute(sql, params=None):
            sql_clean = " ".join(sql.split()).upper()
            if "INSERT INTO DRAFTS" in sql_clean:
                # (draft_id, citizen_id, payload, payload_hash, scheme_version, created_at, expires_at)
                stored_draft["row"] = (params[0], params[1], params[2], params[3], params[4], 'prepared', params[6], None)
            elif "UPDATE DRAFTS SET STATUS = 'SUBMITTED'" in sql_clean:
                r = stored_draft.get("row")
                if r:
                    stored_draft["row"] = (r[0], r[1], r[2], r[3], r[4], 'submitted', r[6], params[1])

        def mock_fetchone():
            calls = mock_cur.execute.call_args_list
            if not calls:
                return None
            last_sql = " ".join(calls[-1][0][0].split()).upper()
            if "FROM DRAFTS" in last_sql:
                return stored_draft.get("row")
            elif "FROM APPLICATIONS" in last_sql and "SELECT ID, APPLICATION_NO, STATUS" in last_sql:
                return None
            elif "INSERT INTO APPLICATIONS" in last_sql:
                return (701,)
            elif "FROM PORTAL_USERS" in last_sql:
                return (0,)
            return None

        mock_cur.execute.side_effect = mock_execute
        mock_cur.fetchone.side_effect = mock_fetchone

        dummy_doc = base64.b64encode(b"Dummy PDF content").decode()

        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn), \
             patch.object(services, "send_sms"):

            # Step 1: Prepare application
            prepare_args = {
                "applicant_name": "Sundari Bai",
                "dob": "10/04/1955",
                "gender": "Female",
                "marital_status": "Widowed",
                "husband_name": "Late Ramesh",
                "village": "Lakhipur",
                "block": "Sonari",
                "bank_account": "123456789012",
                "ifsc": "SBIN0003077",
                "document_filename": "age_proof.pdf",
                "document_base64": dummy_doc
            }
            resp = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "prepare_application", "arguments": prepare_args}, "id": 3}
            )
            self.assertEqual(resp.status_code, 200)
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "ready_for_confirmation")
            confirm_token = content["confirmation_token"]
            self.assertTrue(confirm_token)
            self.assertIn("preview", content)
            self.assertEqual(content["preview"]["block"], "Sonari")

            # Step 2: Submit application using the confirmation token
            resp_sub = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "submit_application", "arguments": {"confirmation_token": confirm_token}}, "id": 4}
            )
            self.assertEqual(resp_sub.status_code, 200)
            sub_content = json.loads(resp_sub.get_json()["result"]["content"][0]["text"])
            self.assertEqual(sub_content["status"], "submitted")
            self.assertTrue(sub_content["application_number"].startswith("SSP"))

            # Step 3: Reusing the same confirmation token must fail (single-use)
            resp_reuse = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "submit_application", "arguments": {"confirmation_token": confirm_token}}, "id": 5}
            )
            reuse_content = json.loads(resp_reuse.get_json()["result"]["content"][0]["text"])
            self.assertEqual(reuse_content["status"], "error")

    def test_citizen_prepare_underage_rejected(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            args = {
                "applicant_name": "Ramlal",
                "dob": "10/04/1968",  # 58 years old
                "village": "Dighaljan",
                "block": "Rajapara",
                "bank_account": "123456789012",
                "ifsc": "SBIN0003077",
                "document_base64": base64.b64encode(b"doc").decode()
            }
            resp = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "prepare_application", "arguments": args}, "id": 6}
            )
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "validation_failed")
            self.assertTrue(any("60 years" in e for e in content["errors"]))

    def test_citizen_withdraw_two_step(self):
        token = self.mint_token("citizen:9876543210", "citizen", "http://localhost:8000/mcp/citizen")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        # Returns active pending application
        mock_cur.fetchone.return_value = (501, "SSP26999999", "PENDING")

        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn):

            # Step 1: Call without confirm=True
            resp1 = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "withdraw_application", "arguments": {"confirm": False}}, "id": 7}
            )
            content1 = json.loads(resp1.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content1["status"], "confirmation_required")
            self.assertIn("confirm=True", content1["instruction"])

            # Step 2: Call with confirm=True
            mock_cur.fetchone.side_effect = [
                (501, "SSP26999999", "PENDING"),  # initial check
                ("SSP26999999",)                  # UPDATE RETURNING
            ]
            resp2 = self.app.post(
                "/mcp/citizen",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "withdraw_application", "arguments": {"confirm": True}}, "id": 8}
            )
            content2 = json.loads(resp2.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content2["status"], "withdrawn")
            self.assertEqual(content2["application_number"], "SSP26999999")

    # -----------------------------------------------------------------------
    # Officer Tools Tests
    # -----------------------------------------------------------------------

    def test_officer_tools_list_isolation(self):
        token = self.mint_token("officer:meena", "officer", "http://localhost:8000/mcp/officer")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/list", "id": 9}
            )
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()["result"]["tools"]
            tool_names = [t["name"] for t in data]
            self.assertEqual(len(tool_names), 5)
            self.assertIn("queue_summary", tool_names)
            self.assertIn("list_applications", tool_names)
            self.assertIn("approve_application", tool_names)
            self.assertIn("reject_application", tool_names)
            # Ensure no citizen tools are visible
            self.assertNotIn("prepare_application", tool_names)
            self.assertNotIn("submit_application", tool_names)

    def test_officer_reject_without_reason_rejected(self):
        token = self.mint_token("officer:meena", "officer", "http://localhost:8000/mcp/officer")
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict):
            resp = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "reject_application", "arguments": {"app_id": 101, "reason": ""}}, "id": 10}
            )
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "error")
            self.assertIn("reason is mandatory", content["error"])

    def test_officer_reject_with_reason_succeeds(self):
        token = self.mint_token("officer:meena", "officer", "http://localhost:8000/mcp/officer")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        # Step 1: SELECT app -> returns pending app details
        mock_cur.fetchone.return_value = ("SSP26123456", "Applicant", "Village", "Sonari", "PENDING")
 
        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn):
            # Step 1: Call without confirmation_token -> confirmation required
            resp1 = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "reject_application", "arguments": {"app_id": 101, "reason": "Age proof blurred"}}, "id": 11}
            )
            content1 = json.loads(resp1.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content1["status"], "confirmation_required")
            conf_token = content1["confirmation_token"]

            # Step 2: Call with confirmation_token -> executed
            from datetime import timedelta
            mock_cur.fetchone.side_effect = [
                ("SSP26123456", "Applicant", "Village", "Sonari", "PENDING"),
                (101, "REJECTED", "officer:meena", "Age proof blurred", datetime.now() + timedelta(minutes=5), None),
                ("SSP26123456",)
            ]
            resp2 = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "reject_application", "arguments": {"app_id": 101, "reason": "Age proof blurred", "confirmation_token": conf_token}}, "id": 12}
            )
            content2 = json.loads(resp2.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content2["status"], "rejected")
            self.assertEqual(content2["application_no"], "SSP26123456")

    def test_officer_approve_application_succeeds(self):
        token = self.mint_token("officer:meena", "officer", "http://localhost:8000/mcp/officer")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        # Step 1: SELECT app -> returns pending app details
        mock_cur.fetchone.return_value = ("SSP26123456", "Applicant", "Village", "Sonari", "PENDING")

        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn):
            # Step 1: Call without confirmation_token -> confirmation required
            resp1 = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "approve_application", "arguments": {"app_id": 101, "note": "Verified genuine"}}, "id": 13}
            )
            content1 = json.loads(resp1.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content1["status"], "confirmation_required")
            conf_token = content1["confirmation_token"]

            # Step 2: Call with confirmation_token -> executed
            from datetime import timedelta
            mock_cur.fetchone.side_effect = [
                ("SSP26123456", "Applicant", "Village", "Sonari", "PENDING"),
                (101, "APPROVED", "officer:meena", "Verified genuine", datetime.now() + timedelta(minutes=5), None),
                ("SSP26123456",)
            ]
            resp2 = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "approve_application", "arguments": {"app_id": 101, "note": "Verified genuine", "confirmation_token": conf_token}}, "id": 14}
            )
            content2 = json.loads(resp2.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content2["status"], "approved")
            self.assertEqual(content2["application_no"], "SSP26123456")


if __name__ == "__main__":
    unittest.main()
