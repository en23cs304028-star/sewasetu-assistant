# -*- coding: utf-8 -*-
"""
evals/cleanup.py: Cleanup script for dedicated test numbers and eval artifacts.
Ensures reviewers see a clean portal without residual evaluation rows.
"""

import os
import sys
import glob

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
import services


def cleanup_test_data(prefix="999000%"):
    """Removes test applications, portal accounts, audit records, and uploaded files."""
    cfg = services.load_config()
    try:
        conn = services.get_db(cfg)
        cur = conn.cursor()

        # Find application IDs to delete
        cur.execute("SELECT id FROM applications WHERE mobile LIKE %s", (prefix,))
        app_ids = [r[0] for r in cur.fetchall()]

        if app_ids:
            cur.execute("DELETE FROM audit_log WHERE application_id = ANY(%s)", (app_ids,))
            cur.execute("DELETE FROM applications WHERE id = ANY(%s)", (app_ids,))

        cur.execute("DELETE FROM portal_users WHERE mobile LIKE %s", (prefix,))
        cur.execute("DELETE FROM oauth_refresh_tokens WHERE subject LIKE %s", ("citizen:" + prefix,))
        conn.commit()
        cur.close()
        conn.close()
        print("Database test records cleaned up (%d test applications removed)." % len(app_ids))
    except Exception as e:
        print("Database cleanup skipped (database offline or unreachable): %s" % e)

    # Clean local test uploads
    upload_dirs = [
        cfg.get("app", "upload_dir", fallback="/var/sewasetu/uploads"),
        os.path.join(BASE_DIR, "app", "uploads")
    ]
    cleaned_files = 0
    for udir in upload_dirs:
        if os.path.exists(udir):
            for f in glob.glob(os.path.join(udir, "999000*")):
                try:
                    os.remove(f)
                    cleaned_files += 1
                except Exception:
                    pass
    if cleaned_files:
        print("Cleaned up %d temporary test upload files." % cleaned_files)


if __name__ == "__main__":
    cleanup_test_data()
