# -*- coding: utf-8 -*-
"""
Tests for app/services.py: validation, scheme rules, decisions, audit, and deemed approval.
Uses standard library unittest and unittest.mock.
"""

import sys
import os
import unittest
from datetime import datetime, date, timedelta
from unittest.mock import MagicMock, patch

# Ensure app directory is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
import services


class TestServices(unittest.TestCase):

    def setUp(self):
        self.valid_data = {
            "applicant_name": "Sundari Bai",
            "village": "Lakhipur",
            "block": "Sonari",
            "gender": "Female",
            "marital_status": "Widowed",
            "husband_name": "Late Ramesh",
            "bank_account": "123456789012",
            "ifsc": "SBIN0003077",
            "dob": "10/04/1955",
        }
        self.doc_path = "/var/sewasetu/uploads/doc.pdf"

    def test_validate_valid_application(self):
        errors, cleaned = services.validate_application(self.valid_data, self.doc_path)
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["applicant_name"], "Sundari Bai")
        self.assertEqual(cleaned["block"], "Sonari")
        self.assertEqual(cleaned["bank_account"], "123456789012")
        self.assertEqual(cleaned["ifsc"], "SBIN0003077")
        self.assertEqual(cleaned["dob"], date(1955, 4, 10))

    def test_validate_missing_required_fields(self):
        data = self.valid_data.copy()
        data["applicant_name"] = ""
        data["village"] = ""
        data["block"] = ""
        data["bank_account"] = ""
        errors, _ = services.validate_application(data, "")
        self.assertIn("full name is required", errors)
        self.assertIn("village is required", errors)
        self.assertIn("block is required", errors)
        self.assertIn("bank account is required", errors)
        self.assertIn("age proof document is required", errors)

    def test_validate_invalid_block(self):
        data = self.valid_data.copy()
        data["block"] = "Guwahati Central"
        errors, _ = services.validate_application(data, self.doc_path)
        self.assertTrue(any("block must be one of" in e for e in errors))

    def test_validate_bank_account_regex(self):
        # Too short (<9 digits)
        data = self.valid_data.copy()
        data["bank_account"] = "1234567"
        errors, _ = services.validate_application(data, self.doc_path)
        self.assertIn("bank account number must be 9 to 18 digits", errors)

        # Characters in bank account
        data["bank_account"] = "12345ABC678"
        errors, _ = services.validate_application(data, self.doc_path)
        self.assertIn("bank account number must be 9 to 18 digits", errors)

    def test_validate_ifsc_regex(self):
        data = self.valid_data.copy()
        data["ifsc"] = "INVALID"
        errors, _ = services.validate_application(data, self.doc_path)
        self.assertIn("IFSC must be 11 characters, e.g. SBIN0003077", errors)

    def test_validate_underage_applicant(self):
        data = self.valid_data.copy()
        # 58 years old relative to 2026
        data["dob"] = "15/08/1968"
        errors, _ = services.validate_application(data, self.doc_path)
        self.assertIn("applicant must be 60 years of age or above", errors)

    def test_validate_boundary_age_60(self):
        data = self.valid_data.copy()
        # Exactly 60 or above relative to 2026
        data["dob"] = "01/01/1966"
        errors, cleaned = services.validate_application(data, self.doc_path)
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["dob"], date(1966, 1, 1))

    def test_clean_formatting_and_sanitization(self):
        data = self.valid_data.copy()
        data["applicant_name"] = "  Sundari Bai  "
        data["bank_account"] = " 1234-5678-9012 "
        data["ifsc"] = " sbin0003077 "
        errors, cleaned = services.validate_application(data, self.doc_path)
        self.assertEqual(errors, [])
        self.assertEqual(cleaned["applicant_name"], "Sundari Bai")
        self.assertEqual(cleaned["bank_account"], "123456789012")
        self.assertEqual(cleaned["ifsc"], "SBIN0003077")

    def test_create_application_logic(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.side_effect = [
            (501,),  # RETURNING id
            (0,),    # SELECT count(*) FROM portal_users -> 0 (user needs creation)
        ]
        cleaned = {
            "applicant_name": "Sundari Bai",
            "village": "Lakhipur",
            "block": "Sonari",
            "gender": "Female",
            "marital_status": "Widowed",
            "husband_name": "",
            "husband_employer": "",
            "bank_account": "123456789012",
            "ifsc": "SBIN0003077",
            "doc_path": "/var/sewasetu/uploads/doc.pdf",
            "dob": date(1955, 4, 10),
        }
        app_id, app_no = services.create_application(mock_cur, "9876543210", cleaned)
        self.assertEqual(app_id, 501)
        self.assertTrue(app_no.startswith("SSP"))

        # Verify portal user insert has DOB as DDMMYYYY: 10041955
        expected_pass_hash = services.hash_password("10041955")
        portal_insert = mock_cur.execute.call_args_list[2]
        self.assertIn("INSERT INTO portal_users", portal_insert[0][0])
        self.assertEqual(portal_insert[0][1][0], "9876543210")
        self.assertEqual(portal_insert[0][1][1], expected_pass_hash)

        # Verify audit log insert
        audit_insert = mock_cur.execute.call_args_list[3]
        self.assertIn("INSERT INTO audit_log", audit_insert[0][0])
        self.assertEqual(audit_insert[0][1][0], 501)
        self.assertEqual(audit_insert[0][1][1], "SUBMIT")
        self.assertEqual(audit_insert[0][1][2], "applicant:9876543210")

    def test_active_application(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = (501, "SSP26123456", "PENDING", datetime(2026, 10, 15))
        res = services.active_application(mock_cur, "9876543210")
        self.assertIsNotNone(res)
        self.assertEqual(res[1], "SSP26123456")
        self.assertEqual(res[2], "PENDING")

    def test_scheme_info_dynamic(self):
        info = services.get_scheme_info()
        self.assertEqual(info["min_age"], 60)
        self.assertEqual(info["sla_days"], 15)
        self.assertTrue("Sonari" in info["blocks"])
        self.assertTrue("Rajapara" in info["blocks"])
        self.assertIn("required_documents", info)
        self.assertTrue(info["is_open"])

    def test_decide_reject_requires_non_empty_reason(self):
        mock_cur = MagicMock()
        ok, msg, app_no = services.decide_application(mock_cur, 101, "REJECTED", "officer:admin", note="")
        self.assertFalse(ok)
        self.assertEqual(msg, "A specific reason is mandatory when rejecting an application.")
        self.assertIsNone(app_no)
        # Verify no DB update occurred
        mock_cur.execute.assert_not_called()

        # With whitespace only
        ok, msg, app_no = services.decide_application(mock_cur, 101, "REJECTED", "officer:admin", note="   ")
        self.assertFalse(ok)
        self.assertEqual(msg, "A specific reason is mandatory when rejecting an application.")

    def test_decide_reject_with_reason_succeeds(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = ("SSP26123456",)
        ok, msg, app_no = services.decide_application(
            mock_cur, 101, "REJECTED", "officer:admin", note="Age proof document is illegible."
        )
        self.assertTrue(ok)
        self.assertEqual(app_no, "SSP26123456")
        self.assertIn("rejected", msg)
        # Check audit log insert was called
        self.assertEqual(mock_cur.execute.call_count, 2)
        audit_call = mock_cur.execute.call_args_list[1]
        self.assertIn("INSERT INTO audit_log", audit_call[0][0])
        self.assertIn("Age proof document is illegible.", audit_call[0][1])

    def test_decide_approve_succeeds(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = ("SSP26123456",)
        ok, msg, app_no = services.decide_application(mock_cur, 101, "APPROVED", "officer:admin", note="All verified.")
        self.assertTrue(ok)
        self.assertEqual(app_no, "SSP26123456")
        self.assertIn("approved", msg)

    def test_decide_already_decided_returns_real_status(self):
        mock_cur = MagicMock()
        # First query (UPDATE) returns None (rowcount 0)
        # Second query (SELECT current status) returns row
        mock_cur.fetchone.side_effect = [None, ("SSP26123456", "DEEMED_APPROVED")]
        ok, msg, app_no = services.decide_application(mock_cur, 101, "APPROVED", "officer:admin", note="Too late")
        self.assertFalse(ok)
        self.assertEqual(app_no, "SSP26123456")
        self.assertIn("already decided", msg)
        self.assertIn("DEEMED_APPROVED", msg)

    def test_withdraw_application_pending_succeeds(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.return_value = ("SSP26123456",)
        ok, msg, app_no = services.withdraw_application(mock_cur, 101, "9876543210")
        self.assertTrue(ok)
        self.assertEqual(app_no, "SSP26123456")
        self.assertIn("withdrawn", msg)

    def test_withdraw_application_not_pending_fails(self):
        mock_cur = MagicMock()
        mock_cur.fetchone.side_effect = [None, ("SSP26123456", "APPROVED")]
        ok, msg, app_no = services.withdraw_application(mock_cur, 101, "9876543210")
        self.assertFalse(ok)
        self.assertIn("Only a pending application can be withdrawn", msg)
        self.assertIn("APPROVED", msg)

    def test_deemed_approval_atomic_audit(self):
        """Verify deemed approval script writes audit log rows directly from returned IDs."""
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app", "scripts")))
        with patch.dict(sys.modules, {"psycopg2": MagicMock()}):
            import deemed_approval

            mock_conn = MagicMock()
            mock_cur = MagicMock()
            mock_conn.cursor.return_value = mock_cur
            mock_cur.fetchall.return_value = [
                (101, "SSP26000101", "9876543210"),
                (102, "SSP26000102", "9876543211"),
            ]

            with patch.object(deemed_approval.psycopg2, "connect", return_value=mock_conn), \
                 patch.object(deemed_approval.requests, "post") as mock_post:
                deemed_approval.main()

                # Ensure UPDATE RETURNING id, application_no, mobile was called
                update_sql = mock_cur.execute.call_args_list[0][0][0]
                self.assertIn("RETURNING id, application_no, mobile", update_sql)

                # Ensure audit log rows were inserted for both returned IDs
                audit_call_1 = mock_cur.execute.call_args_list[1]
                self.assertIn("INSERT INTO audit_log", audit_call_1[0][0])
                self.assertIn("DEEMED_APPROVED", audit_call_1[0][0])
                self.assertIn("system:rtps-cron", audit_call_1[0][0])
                self.assertEqual(audit_call_1[0][1][0], 101)

                audit_call_2 = mock_cur.execute.call_args_list[2]
                self.assertEqual(audit_call_2[0][1][0], 102)

                # Ensure transaction committed once
                mock_conn.commit.assert_called_once()
                # Ensure SMS sent for both
                self.assertEqual(mock_post.call_count, 2)


class TestEvalDashboardRoute(unittest.TestCase):
    """Verify /eval-dashboard route renders evaluation results and handles missing data gracefully."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("ADMIN_PASSWORD", "test-admin-secret")
        sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")))
        with patch.dict(sys.modules, {"psycopg2": MagicMock(), "fpdf": MagicMock()}):
            import app as flask_app
            cls.app_client = flask_app.app.test_client()

    def test_eval_dashboard_renders_results(self):
        resp = self.app_client.get("/eval-dashboard")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Sewa Setu — Persona Evaluation Dashboard", html)
        self.assertIn("Sundari Bai", html)
        self.assertIn("Pass Rate", html)

    def test_eval_dashboard_handles_missing_file_gracefully(self):
        with patch("os.path.exists", return_value=False):
            resp = self.app_client.get("/eval-dashboard")
            self.assertEqual(resp.status_code, 200)
            html = resp.get_data(as_text=True)
            self.assertIn("Sewa Setu — Persona Evaluation Dashboard", html)

    def test_app_refuses_to_start_without_admin_password(self):
        """Verify app refuses to start if ADMIN_PASSWORD environment variable is missing."""
        import subprocess
        res = subprocess.run(
            [sys.executable, "-c", "import os; os.environ.pop('ADMIN_PASSWORD', None); import app"],
            cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "app")),
            capture_output=True,
            text=True
        )
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("ADMIN_PASSWORD environment variable must be set", res.stderr)


if __name__ == "__main__":
    unittest.main()
