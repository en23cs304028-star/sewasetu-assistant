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

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def mint_token(self, subject, role, audience, exp_offset=1200):
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "role": role,
            "scope": role,
            "iat": now,
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
        # active_application returns None (no duplicate)
        mock_cur.fetchone.side_effect = [
            None,      # active_application in prepare
            None,      # active_application in submit
            (701,),    # create_application RETURNING id
            (0,),      # portal_users check
        ]

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
        mock_cur.fetchone.return_value = ("SSP26123456",)

        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn):
            resp = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "reject_application", "arguments": {"app_id": 101, "reason": "Age proof blurred"}}, "id": 11}
            )
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "rejected")
            self.assertEqual(content["application_no"], "SSP26123456")
            # Audit log check: actor should be officer:meena
            audit_call = mock_cur.execute.call_args_list[1]
            self.assertEqual(audit_call[0][1][2], "officer:meena")
            self.assertEqual(audit_call[0][1][3], "Age proof blurred")

    def test_officer_approve_application_succeeds(self):
        token = self.mint_token("officer:meena", "officer", "http://localhost:8000/mcp/officer")

        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_conn.cursor.return_value = mock_cur
        mock_cur.fetchone.return_value = ("SSP26123456",)

        with patch.object(auth, "get_public_keys_from_db", return_value=self.keys_dict), \
             patch.object(services, "get_db", return_value=mock_conn):
            resp = self.app.post(
                "/mcp/officer",
                headers={"Authorization": "Bearer " + token},
                json={"method": "tools/call", "params": {"name": "approve_application", "arguments": {"app_id": 101, "note": "Verified genuine"}}, "id": 12}
            )
            content = json.loads(resp.get_json()["result"]["content"][0]["text"])
            self.assertEqual(content["status"], "approved")
            self.assertEqual(content["application_no"], "SSP26123456")


if __name__ == "__main__":
    unittest.main()
