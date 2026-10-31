# -*- coding: utf-8 -*-
"""
tests/test_phase4b_infrastructure.py: Security assertions for Phase 4b infrastructure hardening:
- Security headers (X-Content-Type-Options, Referrer-Policy, CSP, Cache-Control, Server header)
- Database and Admin password enforcement in production mode
- DEMO_GATEWAY isolation and ?to= parameter enforcement
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PUBLIC_BASE_URL", "http://localhost:8000")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")
os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")

import app as portal_app
import server as mcp_server
import services


class TestPhase4bInfrastructure(unittest.TestCase):

    def setUp(self):
        self.portal_client = portal_app.app.test_client()
        self.mcp_client = mcp_server.app.test_client()

    def test_01_portal_security_headers(self):
        """Portal responses include nosniff, no-referrer, CSP with frame-ancestors 'none', and opaque Server."""
        resp = self.portal_client.get("/about")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("default-src 'self'", csp)

        server_hdr = resp.headers.get("Server", "")
        self.assertNotIn("werkzeug", server_hdr.lower())
        self.assertNotIn("gunicorn", server_hdr.lower())
        self.assertIn(server_hdr, ("sewasetu", ""))

    def test_02_sensitive_routes_cache_control_no_store(self):
        """Sensitive web and API endpoints return Cache-Control: no-store."""
        for path in ["/eval-dashboard", "/admin/login", "/status", "/apply"]:
            resp = self.portal_client.get(path)
            cc = resp.headers.get("Cache-Control", "")
            self.assertIn("no-store", cc, f"Path {path} must set Cache-Control: no-store")

        resp_oauth = self.portal_client.get("/oauth/register")
        self.assertIn("no-store", resp_oauth.headers.get("Cache-Control", ""))

    def test_03_mcp_security_headers(self):
        """MCP endpoints enforce strict security headers and no-store."""
        resp = self.mcp_client.post("/mcp/citizen", json={"method": "ping", "id": 1})
        self.assertEqual(resp.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(resp.headers.get("Referrer-Policy"), "no-referrer")
        csp = resp.headers.get("Content-Security-Policy", "")
        self.assertIn("frame-ancestors 'none'", csp)
        cc = resp.headers.get("Cache-Control", "")
        self.assertIn("no-store", cc)

    def test_04_demo_gateway_isolation(self):
        """DEMO_GATEWAY=false returns 404; DEMO_GATEWAY=true requires ?to= parameter and proxies."""
        with patch.dict(os.environ, {"DEMO_GATEWAY": "false"}):
            resp = self.portal_client.get("/__gateway/")
            self.assertEqual(resp.status_code, 404, "DEMO_GATEWAY=false must return 404")

        with patch.dict(os.environ, {"DEMO_GATEWAY": "true"}):
            # Missing ?to= parameter -> 400
            resp_no_to = self.portal_client.get("/__gateway/api/messages")
            self.assertEqual(resp_no_to.status_code, 400)
            self.assertIn("Recipient parameter 'to' is required", resp_no_to.get_data(as_text=True))

            # Valid ?to= parameter proxies to SMS gateway
            with patch("requests.get") as mock_get:
                mock_get.return_value.status_code = 200
                mock_get.return_value.content = b'{"messages": []}'
                mock_get.return_value.headers = {"Content-Type": "application/json"}
                resp_valid = self.portal_client.get("/__gateway/api/messages?to=9990001001")
                self.assertEqual(resp_valid.status_code, 200)

    def test_05_database_password_enforcement_in_production(self):
        """Production mode refuses default 'sewasetu123' and passwords shorter than 16 chars."""
        # 1. Default password sewasetu123 in production must raise RuntimeError
        with patch.dict(os.environ, {"ENV": "production", "POSTGRES_PASSWORD": "sewasetu123", "PGPASSWORD": "sewasetu123"}):
            with self.assertRaises(RuntimeError) as ctx:
                services.get_db()
            self.assertIn("16 characters", str(ctx.exception))

        # 2. Short password (<16 chars) in production must raise RuntimeError
        with patch.dict(os.environ, {"ENV": "production", "POSTGRES_PASSWORD": "ShortPass123!", "PGPASSWORD": "ShortPass123!"}):
            with self.assertRaises(RuntimeError) as ctx:
                services.get_db()
            self.assertIn("16 characters", str(ctx.exception))

        # 3. Valid strong password (>=16 chars) does not raise length/default validation error
        with patch.dict(os.environ, {"ENV": "production", "POSTGRES_PASSWORD": "AStrongProductionSecretPassword2026!", "PGPASSWORD": "AStrongProductionSecretPassword2026!"}):
            with patch("psycopg2.connect") as mock_connect:
                mock_connect.return_value = MagicMock()
                conn = services.get_db()
                self.assertIsNotNone(conn)
                self.assertEqual(mock_connect.call_args[1]["password"], "AStrongProductionSecretPassword2026!")


if __name__ == "__main__":
    unittest.main()
