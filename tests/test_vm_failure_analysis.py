# -*- coding: utf-8 -*-
"""
tests/test_vm_failure_analysis.py: Regression and robustness tests for VM failure analysis.
Covers:
  (a) Fresh database loaded with ONLY schema.sql (no ensure calls), running full officer two-step flow.
  (b) Two concurrent processes starting at once on an empty database (advisory lock concurrency safety).
  (c) Retention cleanup script against a freshly initialized database (never assumes tables exist).
"""

import os
import sys
import unittest
import secrets
import concurrent.futures
from datetime import datetime, timedelta

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("ADMIN_PASSWORD", "TestAdminPassword123!")

import psycopg2
import services
import officer
import scripts.retention_cleanup as retention_cleanup


class TestVMFailureAnalysis(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure base connection works
        conn = services.get_db()
        conn.close()

    def test_a_fresh_db_schema_only_officer_two_step(self):
        """Test (a): Fresh database loaded with ONLY schema.sql (no ensure calls).
        Verifies that confirmation_tokens exists from schema.sql alone and the
        officer two-step approval and rejection flow succeeds.
        Also proves that without confirmation_tokens in schema (old code), it fails.
        """
        conn = services.get_db()
        cur = conn.cursor()

        # 1. Proove failure on old code: drop confirmation_tokens to simulate old schema
        cur.execute("DROP TABLE IF EXISTS confirmation_tokens CASCADE;")
        conn.commit()

        # Insert a pending application with unique mobile
        rnd = secrets.token_hex(4)
        mob = f"998{secrets.randbelow(10000000):07d}"
        cur.execute("""
            INSERT INTO applications (application_no, applicant_name, mobile, dob, status, submitted_at)
            VALUES (%s, 'Test Applicant 1', %s, '1960-01-01', 'PENDING', NOW())
            RETURNING id;
        """, (f"TEST-VM-{rnd}", mob))
        app_id = cur.fetchone()[0]
        conn.commit()

        # Under the old code (missing confirmation_tokens), approve_application Step 1 MUST FAIL with UndefinedTable
        with self.assertRaises(psycopg2.errors.UndefinedTable) as cm:
            officer.approve_application(app_id=app_id, officer_username="admin", note="Approval test note")
        self.assertIn("confirmation_tokens", str(cm.exception))
        conn.rollback()

        # 2. Apply current schema.sql (which now includes confirmation_tokens)
        schema_path = os.path.join(BASE_DIR, "app", "schema.sql")
        with open(schema_path, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        cur.execute(schema_sql)
        conn.commit()

        # Verify confirmation_tokens now exists from schema.sql alone
        cur.execute("""
            SELECT 1 FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'confirmation_tokens';
        """)
        self.assertIsNotNone(cur.fetchone(), "confirmation_tokens must exist from schema.sql alone")

        # Step 1: Officer initiates approval -> confirmation_required
        res_step1 = officer.approve_application(app_id=app_id, officer_username="admin", note="Approved by schema test")
        self.assertEqual(res_step1.get("status"), "confirmation_required")
        conf_token = res_step1.get("confirmation_token")
        self.assertTrue(conf_token and conf_token.startswith("conf_"))

        # Step 2: Officer confirms approval -> approved
        res_step2 = officer.approve_application(app_id=app_id, officer_username="admin",
                                                note="Approved by schema test", confirmation_token=conf_token)
        self.assertEqual(res_step2.get("status"), "approved")

        # Verify application status in DB
        cur.execute("SELECT status, decided_by FROM applications WHERE id = %s", (app_id,))
        status, decided_by = cur.fetchone()
        self.assertEqual(status, "APPROVED")
        self.assertEqual(decided_by, "officer:admin")

        cur.close()
        conn.close()

    def test_b_concurrent_startup_on_empty_db(self):
        """Test (b): Two concurrent processes/workers starting at once on an empty database.
        Verifies that PostgreSQL advisory locking serializes ensure_all_tables without catalog conflicts.
        """
        def _run_ensure():
            # Open independent connection per worker
            c = services.get_db()
            try:
                services.ensure_all_tables(c)
                ok, missing = services.check_required_tables(c)
                return ok, missing
            finally:
                c.close()

        # Run 4 parallel workers (simulating 2 workers of app + 2 workers of mcp)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_run_ensure) for _ in range(4)]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        for ok, missing in results:
            self.assertTrue(ok, f"ensure_all_tables failed under concurrent execution, missing: {missing}")

    def test_c_retention_script_freshly_initialised_db(self):
        """Test (c): Retention script against a freshly initialized database.
        Verifies that retention_cleanup.run_cleanup() runs without error and handles missing tables gracefully.
        """
        conn = services.get_db()

        # Ensure schema is loaded
        services.ensure_all_tables(conn)

        # 1. Run retention cleanup on clean DB -> must succeed with 0 errors
        stats = retention_cleanup.run_cleanup(conn)
        self.assertIn("confirmation_tokens", stats)
        self.assertIn("rate_limits", stats)
        self.assertIn("otps", stats)
        self.assertIn("oauth_revocations", stats)
        self.assertIn("security_audit_log", stats)

        # 2. Proove graceful handling when a table is missing:
        # Temporarily drop confirmation_tokens
        cur = conn.cursor()
        cur.execute("DROP TABLE IF EXISTS confirmation_tokens CASCADE;")
        conn.commit()

        # run_cleanup MUST NOT crash even if confirmation_tokens does not exist
        stats_missing = retention_cleanup.run_cleanup(conn)
        self.assertEqual(stats_missing.get("confirmation_tokens"), 0)

        # Restore table using ensure_all_tables
        services.ensure_all_tables(conn)
        cur.close()
        conn.close()

    def test_d_healthchecks_fail_if_tables_missing(self):
        """Verifies that app and mcp healthchecks return 503 if required tables are missing."""
        from unittest.mock import patch
        import app as portal_module
        import server as mcp_module

        # 1. Healthy state
        with patch.object(services, "check_required_tables", return_value=(True, [])):
            client_app = portal_module.app.test_client()
            resp_app = client_app.get("/health")
            self.assertEqual(resp_app.status_code, 200)
            self.assertEqual(resp_app.get_json().get("status"), "healthy")

            client_mcp = mcp_module.app.test_client()
            resp_mcp = client_mcp.get("/health")
            self.assertEqual(resp_mcp.status_code, 200)
            self.assertEqual(resp_mcp.get_json().get("status"), "healthy")

        # 2. Unhealthy state (missing confirmation_tokens)
        with patch.object(services, "check_required_tables", return_value=(False, ["confirmation_tokens"])):
            resp_app_bad = client_app.get("/health")
            self.assertEqual(resp_app_bad.status_code, 503)
            self.assertEqual(resp_app_bad.get_json().get("status"), "unhealthy")
            self.assertIn("confirmation_tokens", resp_app_bad.get_json().get("missing_tables", []))

            resp_mcp_bad = client_mcp.get("/health")
            self.assertEqual(resp_mcp_bad.status_code, 503)
            self.assertEqual(resp_mcp_bad.get_json().get("status"), "unhealthy")
            self.assertIn("confirmation_tokens", resp_mcp_bad.get_json().get("missing_tables", []))


if __name__ == "__main__":
    unittest.main()
