#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/init_db.py: Database schema initializer and verifier.
Runs once at container startup under PostgreSQL advisory lock.
Exits non-zero with clear fatal log if database connection or schema initialization fails.
"""

import os
import sys
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import services

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("init_db")


def main():
    try:
        logger.info("Verifying and initializing database schema under advisory lock...")
        services.ensure_all_tables()
        ok, missing = services.check_required_tables()
        if not ok:
            logger.critical("FATAL: Required database tables missing after initialization: %s", missing)
            sys.exit(1)
        logger.info("Database schema initialized and verified successfully.")
    except Exception as e:
        logger.critical("FATAL: Database schema initialization failed: %s", e, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()

