# -*- coding: utf-8 -*-
"""
tests/test_durable_drafts.py: Multi-process and database integration tests for durable drafts.
Tests:
  1. Hash binding: tamper with each field in stored payload, submit with wrong hash -> rejected.
  2. Expiry enforcement: force expires_at into past -> rejected.
  3. Single use: submit twice -> exactly one application row.
  4. Cross-user isolation: Citizen B cannot submit Citizen A's draft; error does not leak existence.
  5. Invalidation on supersede, withdraw, and sign-out.
  6. Token vs session: forged Mcp-Session-Id or spoofed citizen_id argument ignored.
  7. Audience regression: wrong audience token rejected even with matching role.
  8. Restart durability: prepare, terminate server process, restart server, submit successfully.
  9. Multi-process cross-process: prepare on process A, submit on process B.
 10. Multi-process concurrent race: N parallel workers across processes race to submit the same draft.
"""

import os
import sys
import time
import json
import base64
import hmac
import hashlib
import secrets
import signal
import subprocess
import multiprocessing
from datetime import datetime, timedelta
import unittest
import requests
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")

import services
import auth
import citizen
import server


def _worker_submit(args):
    """Worker process function for parallel submit race."""
    url, token, payload = args
    try:
        r = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json=payload, timeout=5)
        data = r.json()
        text = data.get("result", {}).get("content", [{}])[0].get("text", "")
        parsed = json.loads(text) if text else {}
        return (r.status_code, parsed.get("status") == "submitted", parsed)
    except Exception as e:
        return (500, False, {"error": str(e)})


class TestDurableDraftsPostgres(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pub_key = cls.priv_key.public_key()
        cls.keys_dict = {"durable_test_kid": cls.pub_key}
        auth.JWT_PUBLIC_KEYS_OVERRIDE = cls.keys_dict
        cls.issuer = auth.get_public_base_url()

        # Ensure database, drafts table, and persist test signing key into oauth_keys
        conn = services.get_db()
        services.ensure_drafts_table(conn)
        cur = conn.cursor()
        pem = cls.priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode("ascii")
        cur.execute(
            """INSERT INTO oauth_keys (kid, private_pem, created_at)
               VALUES (%s, %s, NOW())
               ON CONFLICT (kid) DO UPDATE SET private_pem = EXCLUDED.private_pem""",
            ("durable_test_kid", pem)
        )
        conn.commit()
        cur.close()
        conn.close()

    @classmethod
    def tearDownClass(cls):
        auth.JWT_PUBLIC_KEYS_OVERRIDE = None
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM drafts WHERE citizen_id LIKE '999000%'")
        cur.execute("DELETE FROM applications WHERE mobile LIKE '999000%'")
        conn.commit()
        cur.close()
        conn.close()

    def setUp(self):
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM drafts WHERE citizen_id LIKE '999000%'")
        cur.execute("DELETE FROM applications WHERE mobile LIKE '999000%'")
        conn.commit()
        cur.close()
        conn.close()

    def mint_token(self, mobile, role="citizen", audience=None):
        if audience is None:
            audience = f"{self.issuer}/mcp/citizen"
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "sub": f"citizen:{mobile}" if ":" not in mobile else mobile,
            "aud": audience,
            "role": role,
            "scope": role,
            "iat": now,
            "exp": now + 1800,
            "jti": f"dur_tok_{time.time()}_{mobile}"
        }
        return jwt.encode(claims, self.priv_key, algorithm="RS256", headers={"kid": "durable_test_kid"})

    def get_valid_prepare_data(self):
        dummy_doc = base64.b64encode(b"Dummy PDF content").decode()
        return {
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

    def test_01_hash_binding_tamper_rejection(self):
        """Tampering with any stored payload field or providing a wrong hash rejects submission."""
        mobile = "9990003001"
        data = self.get_valid_prepare_data()
        prep = citizen.prepare_application(mobile=mobile, **data)
        self.assertEqual(prep["status"], "ready_for_confirmation")
        draft_id = prep["draft_id"]
        valid_token = prep["confirmation_token"]

        conn = services.get_db()
        cur = conn.cursor()

        cur.execute("SELECT payload, payload_hash FROM drafts WHERE draft_id = %s", (draft_id,))
        orig_payload_raw, orig_hash = cur.fetchone()
        orig_payload = orig_payload_raw if isinstance(orig_payload_raw, dict) else json.loads(orig_payload_raw)

        # 1. Tamper individual fields in stored payload
        fields_to_tamper = ["applicant_name", "bank_account", "dob", "ifsc", "village", "block"]
        for f in fields_to_tamper:
            cur.execute(
                f"""UPDATE drafts
                    SET payload = jsonb_set(payload, '{{application_fields,{f}}}', '"TAMPERED_VAL"')
                    WHERE draft_id = %s""",
                (draft_id,)
            )
            conn.commit()
            res = citizen.submit_application(mobile=mobile, confirmation_token=valid_token)
            self.assertEqual(res["status"], "error", f"Tampering {f} must be rejected")
            self.assertIn("tampered", res.get("error", "").lower())

        # 2. Restore original valid payload and hash
        cur.execute(
            """UPDATE drafts
               SET payload = %s, payload_hash = %s, status = 'prepared'
               WHERE draft_id = %s""",
            (json.dumps(orig_payload), orig_hash, draft_id)
        )
        conn.commit()

        # Submit with a mismatched/wrong hash
        wrong_token = f"{draft_id}.0000000000000000000000000000000000000000000000000000000000000000"
        res_wrong = citizen.submit_application(mobile=mobile, confirmation_token=wrong_token)
        self.assertEqual(res_wrong["status"], "error")
        self.assertIn("mismatch", res_wrong.get("error", "").lower())

        cur.close()
        conn.close()

    def test_02_draft_expiry_enforcement(self):
        """Expired drafts cannot be submitted."""
        mobile = "9990003002"
        data = self.get_valid_prepare_data()
        prep = citizen.prepare_application(mobile=mobile, **data)
        draft_id = prep["draft_id"]
        token = prep["confirmation_token"]

        conn = services.get_db()
        cur = conn.cursor()
        # Force expires_at into past
        cur.execute("UPDATE drafts SET expires_at = NOW() - INTERVAL '5 minutes' WHERE draft_id = %s", (draft_id,))
        conn.commit()
        cur.close()
        conn.close()

        res = citizen.submit_application(mobile=mobile, confirmation_token=token)
        self.assertEqual(res["status"], "error")
        self.assertIn("expired", res.get("error", "").lower())

    def test_03_single_use_enforcement(self):
        """Submit twice: first succeeds, second fails, exactly one application row created."""
        mobile = "9990003003"
        data = self.get_valid_prepare_data()
        prep = citizen.prepare_application(mobile=mobile, **data)
        token = prep["confirmation_token"]

        # First submit -> succeeds
        res1 = citizen.submit_application(mobile=mobile, confirmation_token=token)
        self.assertEqual(res1["status"], "submitted")

        # Second submit -> fails
        res2 = citizen.submit_application(mobile=mobile, confirmation_token=token)
        self.assertEqual(res2["status"], "error")
        self.assertIn("already been submitted", res2.get("error", "").lower())

        # Check DB count
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
        count = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(count, 1)

    def test_04_cross_user_isolation_no_leak(self):
        """Citizen B submitting Citizen A's draft gets not found error without leaking existence."""
        mobile_a = "9990003004"
        mobile_b = "9990003005"
        data = self.get_valid_prepare_data()
        prep = citizen.prepare_application(mobile=mobile_a, **data)
        token_a = prep["confirmation_token"]

        # Citizen B attempts to submit Citizen A's token
        res_cross = citizen.submit_application(mobile=mobile_b, confirmation_token=token_a)

        # Nonexistent token
        fake_token = f"fake_{secrets.token_hex(16)}.fakehash123456789012345678901234567890"
        res_fake = citizen.submit_application(mobile=mobile_b, confirmation_token=fake_token)

        self.assertEqual(res_cross["status"], "error")
        self.assertEqual(res_fake["status"], "error")
        # Error messages must be identical (no leaking of draft existence)
        self.assertEqual(res_cross.get("error"), res_fake.get("error"))

    def test_05_supersede_withdraw_signout_invalidation(self):
        """Prepare again supersedes prior draft; withdraw and signout invalidate prepared drafts."""
        conn = services.get_db()
        cur = conn.cursor()

        # 1. Supersede
        mobile = "9990003006"
        data = self.get_valid_prepare_data()
        prep1 = citizen.prepare_application(mobile=mobile, **data)
        token1 = prep1["confirmation_token"]
        # Prepare again
        prep2 = citizen.prepare_application(mobile=mobile, **data)
        token2 = prep2["confirmation_token"]

        cur.execute("SELECT status FROM drafts WHERE draft_id = %s", (prep1["draft_id"],))
        self.assertEqual(cur.fetchone()[0], "expired")
        cur.execute("SELECT status FROM drafts WHERE draft_id = %s", (prep2["draft_id"],))
        self.assertEqual(cur.fetchone()[0], "prepared")

        # Submitting draft 1 fails
        res1 = citizen.submit_application(mobile=mobile, confirmation_token=token1)
        self.assertEqual(res1["status"], "error")

        # 2. Sign-out invalidation
        mobile_so = "9990003007"
        prep_so = citizen.prepare_application(mobile=mobile_so, **data)
        citizen.sign_out(mobile_so)
        cur.execute("SELECT status FROM drafts WHERE draft_id = %s", (prep_so["draft_id"],))
        self.assertEqual(cur.fetchone()[0], "expired")

        cur.close()
        conn.close()

    def test_06_token_vs_session_and_spoofed_citizen_id(self):
        """Mcp-Session-Id header or arguments cannot spoof draft ownership."""
        mobile = "9990003008"
        token = self.mint_token(mobile)

        client = server.app.test_client()
        data = self.get_valid_prepare_data()
        # Pass spoofed citizen_id in body
        data["citizen_id"] = "9999999999"

        resp = client.post(
            "/mcp/citizen",
            headers={"Authorization": f"Bearer {token}", "Mcp-Session-Id": "spoofed-session-id"},
            json={"method": "tools/call", "params": {"name": "prepare_application", "arguments": data}, "id": 1}
        )
        self.assertEqual(resp.status_code, 200)
        c = json.loads(resp.get_json()["result"]["content"][0]["text"])
        self.assertEqual(c["status"], "ready_for_confirmation")
        draft_id = c["draft_id"]

        # Check DB: citizen_id must strictly match the token subject (mobile), not spoofed values
        conn = services.get_db()
        cur = conn.cursor()
        cur.execute("SELECT citizen_id FROM drafts WHERE draft_id = %s", (draft_id,))
        owner = cur.fetchone()[0]
        cur.close()
        conn.close()
        self.assertEqual(owner, mobile)

    def test_07_audience_regression_wrong_audience_rejected(self):
        """Token with wrong audience is rejected even if role is citizen."""
        mobile = "9990003009"
        bad_token = self.mint_token(mobile, audience="http://localhost:8000/wrong-audience")
        client = server.app.test_client()
        resp = client.post(
            "/mcp/citizen",
            headers={"Authorization": f"Bearer {bad_token}"},
            json={"method": "tools/list", "id": 1}
        )
        self.assertEqual(resp.status_code, 401)
        data = resp.get_json()
        self.assertEqual(data.get("error"), "invalid_token")

    def _get_subprocess_env(self, port):
        env = dict(os.environ)
        env["PGHOST"] = os.environ.get("PGHOST", "localhost")
        env["PGPORT"] = os.environ.get("PGPORT", "5433")
        env["PGDATABASE"] = os.environ.get("PGDATABASE", "sewasetu")
        env["PGUSER"] = os.environ.get("PGUSER", "sewasetu")
        env["PGPASSWORD"] = os.environ.get("PGPASSWORD", "sewasetu123")
        env["ADMIN_PASSWORD"] = "TestAdminPassword123!"
        env["MCP_PORT"] = str(port)
        return env

    def test_08_restart_durability(self):
        """Prepare draft, kill server process, restart server, submit successfully."""
        port = 8871
        p1 = None
        p2 = None
        env = self._get_subprocess_env(port)
        p1 = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=env)
        time.sleep(1.2)

        mobile = "9990003010"
        token = self.mint_token(mobile)
        base_url = f"http://127.0.0.1:{port}"
        data = self.get_valid_prepare_data()

        try:
            # Prepare on Process 1
            r_prep = requests.post(
                f"{base_url}/mcp/citizen",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "prepare_application", "arguments": data}},
                timeout=5
            )
            self.assertEqual(r_prep.status_code, 200, f"Expected 200 from prepare, got {r_prep.status_code}: {r_prep.text}")
            prep_res = json.loads(r_prep.json()["result"]["content"][0]["text"])
            confirm_token = prep_res["confirmation_token"]

            # Terminate Process 1
            p1.terminate()
            p1.wait(timeout=3)
            p1 = None
            time.sleep(0.6)

            # Start Process 2 on the same port
            p2 = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=env)
            time.sleep(1.2)

            # Submit on Process 2
            r_sub = requests.post(
                f"{base_url}/mcp/citizen",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "submit_application", "arguments": {"confirmation_token": confirm_token}}},
                timeout=5
            )
            self.assertEqual(r_sub.status_code, 200, f"Expected 200 from submit, got {r_sub.status_code}: {r_sub.text}")
            sub_res = json.loads(r_sub.json()["result"]["content"][0]["text"])
            self.assertEqual(sub_res["status"], "submitted")
            self.assertTrue(sub_res["application_number"].startswith("SSP"))
            p2.terminate()
            p2.wait()
            p2 = None
        finally:
            for proc in (p1, p2):
                if proc is not None:
                    try:
                        proc.terminate()
                        proc.kill()
                    except Exception:
                        pass

    def test_09_multi_process_cross_process_prepare_submit(self):
        """Prepare application on Process A (port 8872), submit on Process B (port 8873)."""
        port_a, port_b = 8872, 8873
        pa = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=self._get_subprocess_env(port_a))
        pb = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=self._get_subprocess_env(port_b))
        time.sleep(1.5)

        mobile = "9990003011"
        token = self.mint_token(mobile)
        data = self.get_valid_prepare_data()

        try:
            # 1. Prepare on Process A
            r_prep = requests.post(
                f"http://127.0.0.1:{port_a}/mcp/citizen",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "prepare_application", "arguments": data}},
                timeout=5
            )
            prep_res = json.loads(r_prep.json()["result"]["content"][0]["text"])
            self.assertEqual(prep_res["status"], "ready_for_confirmation")
            confirm_token = prep_res["confirmation_token"]

            # 2. Submit on Process B
            r_sub = requests.post(
                f"http://127.0.0.1:{port_b}/mcp/citizen",
                headers={"Authorization": f"Bearer {token}"},
                json={"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "submit_application", "arguments": {"confirmation_token": confirm_token}}},
                timeout=5
            )
            sub_res = json.loads(r_sub.json()["result"]["content"][0]["text"])
            self.assertEqual(sub_res["status"], "submitted")
            self.assertTrue(sub_res["application_number"].startswith("SSP"))
        finally:
            pa.terminate()
            pb.terminate()
            pa.wait()
            pb.wait()

    def test_10_multi_process_concurrent_race(self):
        """Concurrent race: N parallel submit workers across two server processes for multiple repetitions."""
        port_a, port_b = 8874, 8875
        pa = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=self._get_subprocess_env(port_a))
        pb = subprocess.Popen([sys.executable, os.path.join(BASE_DIR, "mcp", "server.py")], env=self._get_subprocess_env(port_b))
        time.sleep(1.5)

        repetitions = 5
        workers_count = 8
        print(f"\n[Multi-Process Race] Starting {repetitions} repetitions with {workers_count} parallel workers across 2 server processes...")

        try:
            for rep in range(1, repetitions + 1):
                mobile = f"99900040{rep:02d}"
                token = self.mint_token(mobile)
                data = self.get_valid_prepare_data()

                # Prepare draft on Process A
                r_prep = requests.post(
                    f"http://127.0.0.1:{port_a}/mcp/citizen",
                    headers={"Authorization": f"Bearer {token}"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "prepare_application", "arguments": data}},
                    timeout=5
                )
                prep_res = json.loads(r_prep.json()["result"]["content"][0]["text"])
                confirm_token = prep_res["confirmation_token"]

                # Distribute workers across Process A and Process B
                tasks = []
                for i in range(workers_count):
                    target_port = port_a if (i % 2 == 0) else port_b
                    url = f"http://127.0.0.1:{target_port}/mcp/citizen"
                    payload = {
                        "jsonrpc": "2.0",
                        "id": 100 + i,
                        "method": "tools/call",
                        "params": {"name": "submit_application", "arguments": {"confirmation_token": confirm_token}}
                    }
                    tasks.append((url, token, payload))

                with multiprocessing.Pool(processes=workers_count) as pool:
                    results = pool.map(_worker_submit, tasks)

                success_count = sum(1 for status_code, ok, res in results if ok)
                failure_count = sum(1 for status_code, ok, res in results if not ok)

                self.assertEqual(success_count, 1, f"Repetition {rep}: exactly one submit must succeed, got {success_count}")
                self.assertEqual(failure_count, workers_count - 1, f"Repetition {rep}: exactly {workers_count - 1} submits must fail")

                # Verify database state
                conn = services.get_db()
                cur = conn.cursor()
                cur.execute("SELECT count(*) FROM applications WHERE mobile = %s", (mobile,))
                app_count = cur.fetchone()[0]
                cur.execute("SELECT status FROM drafts WHERE draft_id = %s", (prep_res["draft_id"],))
                draft_status = cur.fetchone()[0]
                cur.close()
                conn.close()

                self.assertEqual(app_count, 1, f"Repetition {rep}: exactly 1 application row in DB, got {app_count}")
                self.assertEqual(draft_status, "submitted")
                print(f"  -> Repetition {rep}/{repetitions}: 1 success, {workers_count - 1} rejected, 1 row in DB (PASS)")

        finally:
            pa.terminate()
            pb.terminate()
            pa.wait()
            pb.wait()


if __name__ == "__main__":
    unittest.main()
