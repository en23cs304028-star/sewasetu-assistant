# -*- coding: utf-8 -*-
"""
tests/security/sec_a_protocol.py: Threat A - Protocol Edge Cases & Robustness
Checks:
  - Invalid JSON body handling (FAIL EXPECTED: returns 202 instead of -32700)
  - Wrong jsonrpc version handling (FAIL EXPECTED: accepts 1.0)
  - Missing method handling (FAIL EXPECTED: returns -32601 instead of -32600)
  - Unknown method handling (PASS)
  - Unknown tool handling (PASS)
  - Tool arguments with wrong types (FAIL EXPECTED: leaks ValueError)
  - JSON-RPC batch arrays (FAIL EXPECTED: 500 AttributeError)
  - Deeply nested JSON (PASS)
  - 5 MB body size limit (FAIL EXPECTED: processes 5MB instead of 413)
  - prepare_application spam / rate limiting (FAIL EXPECTED: allows unlimited draft creation)
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


class TestThreatAProtocol(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sec_test_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

    def setUp(self):
        self.app = server.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "scope": "citizen",
            "iat": now,
            "nbf": now,
            "exp": now + 1800,
            "jti": "jti_proto_sec"
        }
        self.token = jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_test_kid"})
        self.headers = {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def test_a1_invalid_json_body_should_return_parse_error(self):
        """[FAIL EXPECTED] Invalid JSON body must return JSON-RPC -32700 Parse error, not HTTP 202."""
        resp = self.app.post("/mcp/citizen", headers=self.headers, data=b"{this is not valid json")
        self.assertNotEqual(
            resp.status_code, 202,
            "Server silently treated malformed JSON as an empty notification and returned HTTP 202"
        )
        data = resp.get_json(silent=True) or {}
        self.assertIn("error", data, "Response for malformed JSON must contain JSON-RPC error")
        self.assertEqual(data.get("error", {}).get("code"), -32700, "Error code must be -32700 (Parse error)")

    def test_a2_wrong_jsonrpc_version_should_return_invalid_request(self):
        """[FAIL EXPECTED] Request with 'jsonrpc': '1.0' should return -32600 Invalid Request."""
        payload = {"jsonrpc": "1.0", "id": 1, "method": "tools/list"}
        resp = self.app.post("/mcp/citizen", headers=self.headers, json=payload)
        data = resp.get_json(silent=True) or {}
        self.assertIn("error", data, "Server should reject unsupported jsonrpc version")
        self.assertEqual(data.get("error", {}).get("code"), -32600)

    def test_a3_missing_method_should_return_invalid_request(self):
        """[FAIL EXPECTED] Request with id but missing 'method' field should return -32600 Invalid Request."""
        payload = {"jsonrpc": "2.0", "id": 10}
        resp = self.app.post("/mcp/citizen", headers=self.headers, json=payload)
        data = resp.get_json(silent=True) or {}
        self.assertIn("error", data)
        self.assertEqual(data.get("error", {}).get("code"), -32600, "Missing method should be code -32600, not -32601")

    def test_a4_unknown_method_returns_32601(self):
        """Unknown method name should return -32601 Method not found."""
        payload = {"jsonrpc": "2.0", "id": 20, "method": "system/restart"}
        resp = self.app.post("/mcp/citizen", headers=self.headers, json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data.get("error", {}).get("code"), -32601)

    def test_a5_unknown_tool_returns_clean_error(self):
        """Calling nonexistent tool must return clean error without crashing."""
        payload = {"jsonrpc": "2.0", "id": 30, "method": "tools/call", "params": {"name": "nonexistent_tool", "arguments": {}}}
        resp = self.app.post("/mcp/citizen", headers=self.headers, json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")
        self.assertIn("Unknown tool", content)

    def test_a6_wrong_argument_types_should_not_leak_stack_trace(self):
        """[FAIL EXPECTED] Wrong argument types (e.g. app_id='abc') should return structured validation error, not Python ValueError."""
        claims = {
            "iss": self.issuer,
            "sub": "officer:admin",
            "aud": f"{self.issuer}/mcp/officer",
            "role": "officer",
            "scope": "officer",
            "iat": int(time.time()),
            "nbf": int(time.time()),
            "exp": int(time.time()) + 1800,
            "jti": "jti_proto_o"
        }
        o_tok = jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "sec_test_kid"})
        payload = {
            "jsonrpc": "2.0", "id": 40, "method": "tools/call",
            "params": {"name": "get_application", "arguments": {"app_id": "invalid_alpha_id"}}
        }
        resp = self.app.post("/mcp/officer", headers={"Authorization": f"Bearer {o_tok}", "Content-Type": "application/json"}, json=payload)
        data = resp.get_json() or {}
        text = data.get("result", {}).get("content", [{}])[0].get("text", "")
        self.assertNotIn("invalid literal for int()", text, "Internal Python exception message leaked to client")

    def test_a7_batch_array_should_not_cause_500(self):
        """[FAIL EXPECTED] Batch request array should not cause unhandled 500 AttributeError on server."""
        batch = [
            {"jsonrpc": "2.0", "id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": 2, "method": "ping"}
        ]
        resp = self.app.post("/mcp/citizen", headers=self.headers, json=batch)
        self.assertNotEqual(resp.status_code, 500, "Server crashed with HTTP 500 on batch array")

    def test_a8_deeply_nested_json(self):
        """[FAIL EXPECTED] Server should reject 100,000-deep nested JSON cleanly without unhandled RecursionError 500."""
        nested_bytes = b'{"a":' * 100000 + b'"val"' + b'}' * 100000
        resp = self.app.post("/mcp/citizen", headers=self.headers, data=nested_bytes)
        self.assertNotEqual(
            resp.status_code, 500,
            "100,000-deep nested JSON caused unhandled RecursionError resulting in HTTP 500"
        )

    def test_a9_enforce_body_size_limit(self):
        """[FAIL EXPECTED] 5 MB garbage payload should be rejected with HTTP 413 Payload Too Large."""
        large_body = b"{" + b'"padding":"' + (b"X" * (5 * 1024 * 1024)) + b'"}'
        resp = self.app.post("/mcp/citizen", headers=self.headers, data=large_body)
        self.assertEqual(resp.status_code, 413, f"Expected 413 Payload Too Large, got {resp.status_code}")

    def test_a10_prepare_application_spam_rate_limit(self):
        """[FAIL EXPECTED] Rapid repeated prepare_application calls must be rate-limited to prevent DB bloat."""
        args = {
            "applicant_name": "Spam Applicant",
            "dob": "01/01/1950",
            "gender": "Female",
            "marital_status": "Widowed",
            "village": "Sonari",
            "block": "Sonari",
            "bank_account": "123456789012",
            "ifsc": "SBIN0003077"
        }
        statuses = []
        for i in range(25):
            payload = {
                "jsonrpc": "2.0", "id": 100 + i, "method": "tools/call",
                "params": {"name": "prepare_application", "arguments": args}
            }
            resp = self.app.post("/mcp/citizen", headers=self.headers, json=payload)
            statuses.append(resp.status_code)

        # In absence of rate limiting, all 25 succeed (200) without 429
        # Security test expects rate limit (429) after excessive rapid prepare calls
        self.assertIn(
            429, statuses,
            "prepare_application allows unlimited rapid spam without rate limiting, risking DB draft bloat"
        )


if __name__ == "__main__":
    unittest.main()

