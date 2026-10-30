# -*- coding: utf-8 -*-
"""
tests/security/sec_b_tokens.py: Threat B - Token Security & Validation Tests
Checks:
  - Expired tokens rejected (PASS)
  - Wrong signing key rejected (PASS)
  - alg=none rejected (PASS)
  - HS256 key confusion attack rejected (PASS)
  - Wrong issuer rejected (PASS)
  - Wrong audience rejected (PASS)
  - Tampered role rejected (PASS)
  - Missing exp rejected (PASS)
  - Missing jti rejected (FAIL EXPECTED: jti not enforced in verify_token)
  - Unknown kid not in JWKS rejected (FAIL EXPECTED: fallback to key[0] accepts unknown kid)
  - Token still working after sign_out / revoke (FAIL EXPECTED: access token stateless, not blocklisted)
  - One citizen's token used for another citizen's data (PASS)
"""

import os
import sys
import time
import json
import unittest
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

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


class TestThreatBTokens(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"trusted_kid_1": cls.pub_key}
        cls.issuer = "http://localhost:8000"

        # Attacker key pair
        cls.attacker_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.attacker_pub = cls.attacker_priv.public_key()

    def setUp(self):
        self.app = server.app.test_client()
        auth.JWT_PUBLIC_KEYS_OVERRIDE = self.keys_dict
        os.environ["PUBLIC_BASE_URL"] = self.issuer

    def tearDown(self):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None

    def _mint_token(self, claims, kid="trusted_kid_1", key=None, algorithm="RS256", headers=None):
        k = key or self.priv_key
        h = {"kid": kid}
        if headers:
            h.update(headers)
        return jwt.encode(claims, k, algorithm=algorithm, headers=h)

    def test_b1_expired_token_rejected(self):
        """Expired JWT access token must be rejected with 401."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now - 3600,
            "exp": now - 1800,
            "jti": "b1_expired"
        }
        token = self._mint_token(claims)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("token_expired", resp.get_data(as_text=True))

    def test_b2_wrong_signing_key_rejected(self):
        """Token signed with an untrusted RSA key must be rejected with 401."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b2_wrong_key"
        }
        token = self._mint_token(claims, kid="trusted_kid_1", key=self.attacker_priv)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)

    def test_b3_alg_none_rejected(self):
        """Token with alg: none must be rejected with 401."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b3_alg_none"
        }
        token = jwt.encode(claims, key="", algorithm="none", headers={"kid": "trusted_kid_1"})
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)

    def test_b4_hs256_public_key_confusion_rejected(self):
        """Token signed with HS256 using public key string or symmetric HMAC must be rejected."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b4_hs256"
        }
        token = jwt.encode(claims, key="symmetric-secret-key-attacker", algorithm="HS256", headers={"kid": "trusted_kid_1"})
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)

    def test_b5_wrong_issuer_rejected(self):
        """Token with mismatched issuer claim must be rejected."""
        now = int(time.time())
        claims = {
            "iss": "http://evil-attacker.example.com",
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b5_wrong_iss"
        }
        token = self._mint_token(claims)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("invalid_issuer", resp.get_data(as_text=True))

    def test_b6_wrong_audience_rejected(self):
        """Token minted for officer endpoint presented at citizen endpoint must be rejected."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/officer",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b6_wrong_aud"
        }
        token = self._mint_token(claims)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)
        self.assertIn("invalid_audience", resp.get_data(as_text=True))

    def test_b7_tampered_role_fails_signature(self):
        """Tampering with token payload role from citizen to officer invalidates signature."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b7_tamper"
        }
        token = self._mint_token(claims)
        header_b64, payload_b64, sig_b64 = token.split(".")
        payload = json.loads(jwt.utils.base64url_decode(payload_b64).decode("utf-8"))
        payload["role"] = "officer"
        tampered_payload_b64 = jwt.utils.base64url_encode(json.dumps(payload).encode("utf-8")).decode("utf-8")
        tampered_token = f"{header_b64}.{tampered_payload_b64}.{sig_b64}"

        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {tampered_token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)

    def test_b8_missing_exp_claim_rejected(self):
        """Token missing exp claim must be rejected."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "jti": "b8_no_exp"
        }
        token = self._mint_token(claims)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(resp.status_code, 401)

    def test_b9_missing_jti_claim_rejected(self):
        """[FAIL EXPECTED] Token missing jti claim should be rejected to enforce replay tracking."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800
        }
        token = self._mint_token(claims)
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(
            resp.status_code, 401,
            "Server accepted access token without 'jti' claim (replay prevention missing)"
        )

    def test_b10_kid_not_in_jwks_rejected(self):
        """[FAIL EXPECTED] Token specifying kid='unknown_bogus_kid' must be rejected, not fall back to key 0."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b10_bogus_kid"
        }
        token = self._mint_token(claims, kid="unknown_bogus_kid")
        resp = self.app.post("/mcp/citizen", headers={"Authorization": f"Bearer {token}"},
                             json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        self.assertEqual(
            resp.status_code, 401,
            "Server accepted token with unknown kid by falling back to first key in JWKS"
        )

    def test_b11_token_still_working_after_sign_out(self):
        """[FAIL EXPECTED] Access token must not continue working after sign_out tool is called."""
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b11_sign_out_test"
        }
        token = self._mint_token(claims)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Call sign_out tool
        sign_out_req = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "sign_out", "arguments": {}}
        }
        resp = self.app.post("/mcp/citizen", headers=headers, json=sign_out_req)
        self.assertEqual(resp.status_code, 200)

        # Subsequent call with the same access token must be rejected
        list_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
        resp2 = self.app.post("/mcp/citizen", headers=headers, json=list_req)
        self.assertEqual(
            resp2.status_code, 401,
            "Access token is still valid after sign_out because tokens are completely stateless"
        )

    def test_b12_one_citizen_token_used_for_another_citizen_data(self):
        """A citizen token for mobile 9990001001 cannot submit data belonging to 9990001002."""
        conn = services.get_db()
        cur = conn.cursor()
        draft_id, p_hash, conf_token, _ = services.create_draft(
            cur, "9990001002",
            {"applicant_name": "Other User", "dob": "01/01/1950", "village": "Sonari", "block": "Sonari",
             "bank_account": "123456789012", "ifsc": "SBIN0003077"}
        )
        conn.commit()
        cur.close()
        conn.close()

        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": "citizen:9990001001",
            "aud": f"{self.issuer}/mcp/citizen",
            "role": "citizen",
            "iat": now,
            "exp": now + 1800,
            "jti": "b12_cross_citizen"
        }
        token = self._mint_token(claims)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        submit_req = {
            "jsonrpc": "2.0", "id": 10, "method": "tools/call",
            "params": {"name": "submit_application", "arguments": {"confirmation_token": conf_token}}
        }
        resp = self.app.post("/mcp/citizen", headers=headers, json=submit_req)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        content = data.get("result", {}).get("content", [{}])[0].get("text", "")
        self.assertTrue("Draft not found or expired" in content or "error" in content)


if __name__ == "__main__":
    unittest.main()
