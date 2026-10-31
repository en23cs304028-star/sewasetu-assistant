#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
app/scripts/retention_cleanup.py: Periodic data retention and cleanup job.
Scheduled via cron or background scheduler.
Retention policies:
  - rate_limits: older than 24 hours
  - otps: older than 24 hours
  - expired revocations: older than 24 hours
  - confirmation_tokens: older than 24 hours
  - security_audit_log: older than 90 days
"""

import os
import sys
import logging
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

import services

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("retention_cleanup")


def run_cleanup(conn=None):
    close_on_exit = False
    if conn is None:
        conn = services.get_db()
        close_on_exit = True

    cur = conn.cursor()
    stats = {}

    try:
        # 1. Clean rate limits older than 24 hours
        cur.execute("DELETE FROM rate_limits WHERE last_attempt < NOW() - INTERVAL '24 hours'")
        stats["rate_limits"] = cur.rowcount

        # 2. Clean OTPs older than 24 hours
        cur.execute("DELETE FROM otps WHERE created_at < NOW() - INTERVAL '24 hours'")
        stats["otps"] = cur.rowcount

        # 3. Clean expired OAuth revocations older than 24 hours
        cur.execute("""
            DELETE FROM oauth_revocations
            WHERE (expires_at IS NOT NULL AND expires_at < NOW() - INTERVAL '24 hours')
               OR (expires_at IS NULL AND revoked_at < NOW() - INTERVAL '24 hours')
        """)
        stats["oauth_revocations"] = cur.rowcount

        # 4. Clean confirmation tokens older than 24 hours
        cur.execute("DELETE FROM confirmation_tokens WHERE created_at < NOW() - INTERVAL '24 hours'")
        stats["confirmation_tokens"] = cur.rowcount

        # 5. Clean security audit log older than 90 days
        cur.execute("DELETE FROM security_audit_log WHERE created_at < NOW() - INTERVAL '90 days'")
        stats["security_audit_log"] = cur.rowcount

        conn.commit()
        logger.info("Retention cleanup completed: %s", stats)
    finally:
        cur.close()
        if close_on_exit:
            conn.close()

    return stats


def main():
    logger.info("Starting retention cleanup job...")
    stats = run_cleanup()
    logger.info("Finished retention cleanup: %s", stats)


if __name__ == "__main__":
    main()
