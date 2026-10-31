#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/clear_lockouts.py: Operator tool to clear officer login lockouts and rate limits.
Usage:
  python scripts/clear_lockouts.py              # Clear all officer lockouts
  python scripts/clear_lockouts.py --all        # Clear all officer lockouts
  python scripts/clear_lockouts.py --ip <ip>    # Clear lockouts for specific IP
  python scripts/clear_lockouts.py --user <usr> # Clear lockouts for specific username
"""

import sys
import os
import argparse

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
if os.path.join(BASE_DIR, "app") not in sys.path:
    sys.path.insert(0, os.path.join(BASE_DIR, "app"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")

import services


def clear_lockouts(ip=None, username=None):
    conn = services.get_db()
    cur = conn.cursor()
    count = 0

    if ip and username:
        key = f"officer_lockout:{ip}:{username.lower()}"
        cur.execute("DELETE FROM rate_limits WHERE key = %s", (key,))
        count = cur.rowcount
    elif ip:
        pattern = f"officer_lockout:{ip}:%"
        cur.execute("DELETE FROM rate_limits WHERE key LIKE %s", (pattern,))
        count = cur.rowcount
    elif username:
        pattern = f"%:{username.lower()}"
        cur.execute("DELETE FROM rate_limits WHERE key LIKE %s AND key LIKE 'officer_%'", (pattern,))
        count = cur.rowcount
    else:
        # Clear all officer lockouts and delay counters
        cur.execute("DELETE FROM rate_limits WHERE key LIKE 'officer_%'")
        count = cur.rowcount

    conn.commit()
    cur.close()
    conn.close()
    return count


def main():
    parser = argparse.ArgumentParser(description="Clear officer login lockouts from PostgreSQL.")
    parser.add_argument("--ip", help="Clear lockouts for a specific IP address")
    parser.add_argument("--user", help="Clear lockouts for a specific username")
    parser.add_argument("--all", action="store_true", help="Clear all officer lockouts and delay counters")

    args = parser.parse_args()
    deleted = clear_lockouts(ip=args.ip, username=args.user)
    print(f"Cleared {deleted} lockout records.")


if __name__ == "__main__":
    main()

