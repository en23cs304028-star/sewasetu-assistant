# -*- coding: utf-8 -*-
"""
tests/security/sec_ssrf.py: SSRF Attack Tests for Client Metadata Document Fetching.
Threat Vector: client_id derived URL fetching (RFC 7591 / OAuth 2.1 CIMD).
Tests:
  - plain http rejected before HTTP request
  - 127.0.0.1 loopback blocked before HTTP request
  - RFC 1918 private IPs (10.x, 172.16.x, 192.168.x) blocked before HTTP request
  - Cloud metadata (169.254.169.254) blocked before HTTP request
  - Docker service names (db, mcp, app, smsgw) blocked before HTTP request
  - IPv6 loopback ([::1]) blocked before HTTP request
  - DNS names resolving to private/loopback IPs blocked before HTTP request
  - Redirects to private IPs blocked
  - Slow responses (> 3 seconds) timed out
  - Huge responses (> 64 KB) aborted
  - Non-JSON responses rejected
"""

import os
import sys
import json
import socket
import unittest
from unittest.mock import patch, MagicMock

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
import oauth


class TestThreatSSRF(unittest.TestCase):

    def test_ssrf_rejects_plain_http(self):
        """Plain HTTP client_id URLs must be rejected; HTTPS is mandatory."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("http://example.com/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "Plain HTTP client metadata URL must be rejected")

    def test_ssrf_rejects_loopback_ip(self):
        """Loopback IP (127.0.0.1) in client_id must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://127.0.0.1:8000/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to 127.0.0.1 must be blocked before GET")

    def test_ssrf_rejects_rfc1918_10(self):
        """RFC 1918 10.x.x.x private IP must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://10.0.0.1/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to 10.x private IP must be blocked before GET")

    def test_ssrf_rejects_rfc1918_172(self):
        """RFC 1918 172.16.x.x private IP must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://172.16.0.1/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to 172.16.x private IP must be blocked before GET")

    def test_ssrf_rejects_rfc1918_192(self):
        """RFC 1918 192.168.x.x private IP must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://192.168.1.1/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to 192.168.x private IP must be blocked before GET")

    def test_ssrf_rejects_cloud_metadata(self):
        """Cloud metadata endpoint 169.254.169.254 must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://169.254.169.254/latest/meta-data/")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to 169.254.169.254 must be blocked before GET")

    def test_ssrf_rejects_docker_service_names(self):
        """Internal Docker container hosts (db, mcp, app, smsgw) must be blocked before making request."""
        for host in ("db", "mcp", "app", "smsgw"):
            with patch("requests.get") as mock_get:
                client = oauth.load_client(f"https://{host}:8000/client.json")
                mock_get.assert_not_called()
                self.assertIsNone(client, f"SSRF to docker service '{host}' must be blocked before GET")

    def test_ssrf_rejects_ipv6_loopback(self):
        """IPv6 loopback [::1] must be blocked before making request."""
        with patch("requests.get") as mock_get:
            client = oauth.load_client("https://[::1]/client.json")
            mock_get.assert_not_called()
            self.assertIsNone(client, "SSRF to IPv6 loopback must be blocked before GET")

    def test_ssrf_rejects_dns_resolving_to_private_ip(self):
        """Hostnames that resolve via DNS to private or loopback IP must be blocked before making request."""
        with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]):
            with patch("requests.get") as mock_get:
                client = oauth.load_client("https://evil-internal.example.com/client.json")
                mock_get.assert_not_called()
                self.assertIsNone(client, "DNS rebinding to 127.0.0.1 must be blocked before GET")

    def test_ssrf_rejects_redirect_to_private_ip(self):
        """HTTP redirects to private or loopback IPs must be blocked or disallowed."""
        mock_resp = MagicMock()
        mock_resp.is_redirect = True
        mock_resp.status_code = 302
        mock_resp.headers = {"Location": "https://127.0.0.1/secret.json"}
        with patch("requests.get", return_value=mock_resp):
            client = oauth.load_client("https://public-redirector.example.com/client.json")
            self.assertIsNone(client, "Redirect to private IP must be blocked")

    def test_ssrf_slow_response_timeout(self):
        """Slow responses exceeding 3 seconds must timeout and return None."""
        import requests
        with patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out")):
            client = oauth.load_client("https://slow.example.com/client.json")
            self.assertIsNone(client, "Timeout must return None safely")

    def test_ssrf_huge_response_aborted(self):
        """Responses exceeding 64 KB must be rejected."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.status_code = 200
        # Provide 100 KB payload
        mock_resp.iter_content.return_value = [b"x" * 1024 for _ in range(100)]
        mock_resp.json.return_value = {"client_id": "https://huge.example.com/client.json"}
        with patch("requests.get", return_value=mock_resp):
            client = oauth.load_client("https://huge.example.com/client.json")
            self.assertIsNone(client, "Response over 64 KB must be rejected")

    def test_ssrf_non_json_content_type(self):
        """Non-JSON responses (HTML, XML, plain text) must be rejected."""
        mock_resp = MagicMock()
        mock_resp.headers = {"Content-Type": "text/html; charset=utf-8"}
        mock_resp.status_code = 200
        mock_resp.text = "<html><body>Not JSON</body></html>"
        with patch("requests.get", return_value=mock_resp):
            client = oauth.load_client("https://html.example.com/client.json")
            self.assertIsNone(client, "Non-JSON response must be rejected")


if __name__ == "__main__":
    unittest.main()
