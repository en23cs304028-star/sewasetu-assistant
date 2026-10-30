# -*- coding: utf-8 -*-
"""
tests/test_sdk_mcp.py: Tests official Python MCP SDK client against live streamable HTTP server.
Validates:
  - Official MCP SDK client (mcp.client.streamable_http + ClientSession)
  - initialize handshake and protocolVersion negotiation
  - tools/list on /mcp/citizen (6 tools) and /mcp/officer (5 tools)
  - tools/call for citizen (get_scheme_info) and officer
  - Unauthenticated 401 challenge with WWW-Authenticate header pointing to resource_metadata
  - Citizen token on /mcp/officer returns 403 Forbidden
  - RFC 9728 discovery metadata endpoints
  - GET on endpoint returns 405 Method Not Allowed (stateless POST-only)
"""

import os
import sys
import time
import threading
import asyncio
import unittest
import requests
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

import server
import auth
from mcp.client.session import ClientSession
import mcp.client.streamable_http as mcp_sh


class TestOfficialSDKMCP(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"sdk_test_kid": cls.pub_key}
        auth.JWT_PUBLIC_KEYS_OVERRIDE = cls.keys_dict
        cls.issuer = auth.get_public_base_url()

        cls.port = 8898
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(
            target=lambda: server.app.run(host="127.0.0.1", port=cls.port, debug=False, use_reloader=False),
            daemon=True
        )
        cls.server_thread.start()
        time.sleep(0.6)

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
            "jti": f"sdk_tok_{int(time.time())}"
        }
        return jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "sdk_test_kid"})

    def test_01_sdk_citizen_flow(self):
        """Test official MCP SDK client completes initialize, tools/list, and tools/call on /mcp/citizen."""
        token = self.mint_token("9990001001", "citizen", f"{self.issuer}/mcp/citizen")
        endpoint = f"{self.base_url}/mcp/citizen"

        async def run_flow():
            headers = {"Authorization": f"Bearer {token}"}
            async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
                async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (r, w):
                    async with ClientSession(r, w) as session:
                        init_res = await session.initialize()
                        self.assertIsNotNone(init_res.protocol_version)

                        tools_res = await session.list_tools()
                        tool_names = [t.name for t in tools_res.tools]
                        self.assertEqual(len(tool_names), 6)
                        self.assertIn("get_scheme_info", tool_names)
                        self.assertIn("prepare_application", tool_names)
                        self.assertIn("submit_application", tool_names)

                        call_res = await session.call_tool("get_scheme_info", {})
                        self.assertFalse(call_res.is_error)
                        self.assertTrue(len(call_res.content) > 0)
                        text = call_res.content[0].text
                        self.assertIn("Indira Gandhi National Old Age Pension", text)

        asyncio.run(run_flow())

    def test_02_sdk_officer_flow(self):
        """Test official MCP SDK client completes initialize, tools/list, and tools/call on /mcp/officer."""
        token = self.mint_token("officer:admin", "officer", f"{self.issuer}/mcp/officer")
        endpoint = f"{self.base_url}/mcp/officer"

        async def run_flow():
            headers = {"Authorization": f"Bearer {token}"}
            async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
                async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (r, w):
                    async with ClientSession(r, w) as session:
                        init_res = await session.initialize()
                        self.assertIsNotNone(init_res.protocol_version)

                        tools_res = await session.list_tools()
                        tool_names = [t.name for t in tools_res.tools]
                        self.assertEqual(len(tool_names), 5)
                        self.assertIn("queue_summary", tool_names)
                        self.assertIn("approve_application", tool_names)
                        self.assertIn("reject_application", tool_names)

        asyncio.run(run_flow())

    def test_03_citizen_token_on_officer_returns_403(self):
        """A citizen token on /mcp/officer returns HTTP 403 Forbidden."""
        citizen_token = self.mint_token("9990001001", "citizen", f"{self.issuer}/mcp/citizen")
        resp = requests.post(
            f"{self.base_url}/mcp/officer",
            headers={"Authorization": f"Bearer {citizen_token}"},
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            timeout=5
        )
        self.assertEqual(resp.status_code, 403)
        data = resp.json()
        self.assertEqual(data.get("error"), "insufficient_scope")
        self.assertIn("forbidden", data.get("error_description", ""))

    def test_04_unauthenticated_returns_401_with_header(self):
        """No token returns HTTP 401 with WWW-Authenticate header containing resource_metadata."""
        resp = requests.post(
            f"{self.base_url}/mcp/citizen",
            json={"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            timeout=5
        )
        self.assertEqual(resp.status_code, 401)
        self.assertIn("WWW-Authenticate", resp.headers)
        auth_hdr = resp.headers["WWW-Authenticate"]
        self.assertIn("Bearer", auth_hdr)
        self.assertIn("resource_metadata=", auth_hdr)
        self.assertIn("/.well-known/oauth-protected-resource/mcp/citizen", auth_hdr)

    def test_05_rfc9728_discovery_metadata(self):
        """Test RFC 9728 metadata at root and path-suffixed endpoints."""
        # 1. Root
        r1 = requests.get(f"{self.base_url}/.well-known/oauth-protected-resource", timeout=5)
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertEqual(d1["resource"], self.issuer)
        self.assertIn("citizen", d1["scopes_supported"])
        self.assertIn("officer", d1["scopes_supported"])

        # 2. /mcp/citizen
        r2 = requests.get(f"{self.base_url}/.well-known/oauth-protected-resource/mcp/citizen", timeout=5)
        self.assertEqual(r2.status_code, 200)
        d2 = r2.json()
        self.assertEqual(d2["resource"], f"{self.issuer}/mcp/citizen")
        self.assertEqual(d2["scopes_supported"], ["citizen"])

        # 3. /mcp/officer
        r3 = requests.get(f"{self.base_url}/.well-known/oauth-protected-resource/mcp/officer", timeout=5)
        self.assertEqual(r3.status_code, 200)
        d3 = r3.json()
        self.assertEqual(d3["resource"], f"{self.issuer}/mcp/officer")
        self.assertEqual(d3["scopes_supported"], ["officer"])

    def test_06_get_returns_405_method_not_allowed(self):
        """GET on /mcp/citizen returns HTTP 405 Method Not Allowed (stateless POST only)."""
        resp = requests.get(f"{self.base_url}/mcp/citizen", timeout=5)
        self.assertEqual(resp.status_code, 405)
        self.assertEqual(resp.headers.get("Allow"), "POST")

    def test_07_all_supported_protocol_versions(self):
        """Test official MCP SDK client pinned to EACH handshake protocol version."""
        import mcp.client.session as mcp_session
        token = self.mint_token("9990001001", "citizen", f"{self.issuer}/mcp/citizen")
        endpoint = f"{self.base_url}/mcp/citizen"

        async def run_pinned_versions():
            orig_version = mcp_session.LATEST_HANDSHAKE_VERSION
            try:
                for v in ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"):
                    mcp_session.LATEST_HANDSHAKE_VERSION = v
                    headers = {"Authorization": f"Bearer {token}"}
                    async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
                        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (r, w):
                            async with ClientSession(r, w) as session:
                                init_res = await session.initialize()
                                self.assertEqual(init_res.protocol_version, v)
                                tools_res = await session.list_tools()
                                self.assertEqual(len(tools_res.tools), 6)
                                call_res = await session.call_tool("get_scheme_info", {})
                                self.assertFalse(call_res.is_error)
            finally:
                mcp_session.LATEST_HANDSHAKE_VERSION = orig_version

        asyncio.run(run_pinned_versions())

    def test_08_raw_http_protocol_version_2026_07_28(self):
        """Raw-HTTP test for modern protocolVersion 2026-07-28 with MCP-Protocol-Version header."""
        token = self.mint_token("9990001001", "citizen", f"{self.issuer}/mcp/citizen")
        endpoint = f"{self.base_url}/mcp/citizen"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream"
        }

        # 1. initialize request with protocolVersion 2026-07-28
        init_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "raw-http-client", "version": "1.0"}
            }
        }
        r1 = requests.post(endpoint, headers=headers, json=init_body, timeout=5)
        self.assertEqual(r1.status_code, 200)
        d1 = r1.json()
        self.assertEqual(d1["result"]["protocolVersion"], "2026-07-28")
        self.assertEqual(r1.headers.get("MCP-Protocol-Version"), "2026-07-28")

        # 2. notifications/initialized with MCP-Protocol-Version header
        h2 = dict(headers)
        h2["MCP-Protocol-Version"] = "2026-07-28"
        notif_body = {
            "jsonrpc": "2.0",
            "method": "notifications/initialized"
        }
        r2 = requests.post(endpoint, headers=h2, json=notif_body, timeout=5)
        self.assertEqual(r2.status_code, 202)
        self.assertEqual(r2.text, "")
        self.assertEqual(r2.headers.get("MCP-Protocol-Version"), "2026-07-28")

        # 3. tools/list with MCP-Protocol-Version header
        list_body = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list"
        }
        r3 = requests.post(endpoint, headers=h2, json=list_body, timeout=5)
        self.assertEqual(r3.status_code, 200)
        d3 = r3.json()
        self.assertIn("tools", d3["result"])
        self.assertEqual(len(d3["result"]["tools"]), 6)
        self.assertEqual(r3.headers.get("MCP-Protocol-Version"), "2026-07-28")


if __name__ == "__main__":
    unittest.main()
