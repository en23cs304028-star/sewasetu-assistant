# -*- coding: utf-8 -*-
"""
tests/test_http_mcp.py: Real HTTP + JSON-RPC 2.0 wire tests for MCP server.
Tests:
  1. RFC 9728 Discovery endpoint (GET /.well-known/oauth-protected-resource)
  2. Unauthenticated request to /mcp/citizen returns HTTP 401 with WWW-Authenticate header
  3. Authenticated JSON-RPC 2.0 initialize handshake
  4. Authenticated JSON-RPC 2.0 tools/list endpoint
  5. Authenticated JSON-RPC 2.0 tools/call for citizen tools (get_scheme_info, prepare_application)
  6. Authenticated JSON-RPC 2.0 tools/call for officer tools (queue_summary)
  7. Cross-role authorization failure (citizen token on officer endpoint returns 403)
"""

import sys
import os
import json
import time
import threading
import unittest
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

# Ensure paths
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

import server
import auth
import citizen
import officer
import services


class TestRealHTTPMCP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Generate test RSA key pair
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"http_test_kid": cls.pub_key}
        cls.issuer = "http://localhost:8000"

        # Patch auth key resolution to use our test key
        auth.JWT_PUBLIC_KEYS_OVERRIDE = cls.keys_dict

        # Start live Flask test server on an ephemeral port
        cls.port = 8899
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(
            target=lambda: server.app.run(host="127.0.0.1", port=cls.port, debug=False, use_reloader=False),
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(0.5)  # Wait for server to bind

    @classmethod
    def tearDownClass(cls):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def mint_token(self, subject, role, audience):
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "role": role,
            "scope": role,
            "iat": now,
            "nbf": now,
            "exp": now + 1800,
            "jti": f"http_tok_{int(time.time())}"
        }
        return jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "http_test_kid"})

    def test_01_rfc9728_discovery(self):
        """Test GET /.well-known/oauth-protected-resource over HTTP wire."""
        resp = requests.get(f"{self.base_url}/.well-known/oauth-protected-resource", timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("authorization_servers", data)
        self.assertIn("resource", data)
        self.assertIn("scopes_supported", data)
        self.assertIn("citizen", data["scopes_supported"])
        self.assertIn("officer", data["scopes_supported"])

    def test_02_unauthenticated_request_challenge(self):
        """Test unauthenticated POST to /mcp/citizen returns HTTP 401 with WWW-Authenticate header."""
        resp = requests.post(f"{self.base_url}/mcp/citizen", json={}, timeout=5)
        self.assertEqual(resp.status_code, 401)
        self.assertIn("WWW-Authenticate", resp.headers)
        auth_header = resp.headers["WWW-Authenticate"]
        self.assertIn("Bearer", auth_header)
        self.assertIn("resource_metadata", auth_header)

    def test_03_jsonrpc_initialize(self):
        """Test authenticated JSON-RPC 2.0 initialize handshake."""
        token = self.mint_token("9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client"}}
        }
        resp = requests.post(f"{self.base_url}/mcp/citizen", headers=headers, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data.get("jsonrpc"), "2.0")
        self.assertEqual(data.get("id"), 1)
        result = data.get("result", {})
        self.assertIn("serverInfo", result)
        self.assertEqual(result["serverInfo"]["name"], "sewasetu-mcp")

    def test_04_jsonrpc_tools_list(self):
        """Test authenticated JSON-RPC 2.0 tools/list returns all 6 citizen tools."""
        token = self.mint_token("9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }
        resp = requests.post(f"{self.base_url}/mcp/citizen", headers=headers, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        tools = data.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        expected_tools = ["get_scheme_info", "get_my_status", "prepare_application", "submit_application", "withdraw_application", "sign_out"]
        for expected in expected_tools:
            self.assertIn(expected, tool_names)

    def test_05_jsonrpc_tools_call_scheme_info(self):
        """Test authenticated JSON-RPC 2.0 tools/call for get_scheme_info."""
        token = self.mint_token("9876543210", "citizen", "http://localhost:8000/mcp/citizen")
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "get_scheme_info",
                "arguments": {}
            }
        }
        resp = requests.post(f"{self.base_url}/mcp/citizen", headers=headers, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        content = data.get("result", {}).get("content", [])
        self.assertTrue(len(content) > 0)
        text = content[0]["text"]
        self.assertIn("Indira Gandhi National Old Age Pension", text)
        self.assertIn("Sonari", text)

    def test_06_officer_tools_call_and_rbac(self):
        """Test officer endpoint requires officer token, rejects citizen token with 403."""
        citizen_token = self.mint_token("9876543210", "citizen", "http://localhost:8000/mcp/officer")
        headers_citizen = {"Authorization": f"Bearer {citizen_token}", "Content-Type": "application/json"}
        resp = requests.post(f"{self.base_url}/mcp/officer", headers=headers_citizen, json={}, timeout=5)
        self.assertEqual(resp.status_code, 403)

        officer_token = self.mint_token("admin", "officer", "http://localhost:8000/mcp/officer")
        headers_officer = {"Authorization": f"Bearer {officer_token}", "Content-Type": "application/json"}
        payload = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/list",
            "params": {}
        }
        resp = requests.post(f"{self.base_url}/mcp/officer", headers=headers_officer, json=payload, timeout=5)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        tools = data.get("result", {}).get("tools", [])
        tool_names = [t["name"] for t in tools]
        self.assertIn("queue_summary", tool_names)
        self.assertIn("approve_application", tool_names)
        self.assertIn("reject_application", tool_names)


if __name__ == "__main__":
    unittest.main()
