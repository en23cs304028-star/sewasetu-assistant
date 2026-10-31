#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/clear_lockouts.py: Operator wrapper to clear officer login lockouts and rate limits.
Delegates to app/scripts/clear_lockouts.py.
"""
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app_script = os.path.join(BASE_DIR, "app", "scripts", "clear_lockouts.py")
if os.path.exists(app_script):
    import runpy
    runpy.run_path(app_script, run_name="__main__")
else:
    print(f"Error: {app_script} not found", file=sys.stderr)
    sys.exit(1)

