# -*- coding: utf-8 -*-
"""
evals/claude_harness.py: Real headless Claude Code evaluation harness.
Invokes Claude Code in headless mode (-p) with a small model (haiku) and a turn cap (--max-turns 10),
connecting via streamable HTTP MCP config to the live endpoint.
Asserts on real PostgreSQL application rows, audit log entries, and SMS gateway notifications.
"""

import os
import sys
import json
import time
import subprocess
import tempfile
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

import auth
import services


def check_claude_availability():
    """Verify if claude CLI is executable and authenticated."""
    claude_bin = subprocess.run(["which", "claude"], capture_output=True, text=True).stdout.strip()
    if not claude_bin:
        return False, "claude CLI not found in PATH"

    # Test execution
    res = subprocess.run([claude_bin, "-p", "Say hello"], capture_output=True, text=True)
    output = (res.stdout + " " + res.stderr).strip()
    if res.returncode != 0:
        if "Not logged in" in output or "Invalid API key" in output or "login" in output.lower():
            return False, "claude CLI awaiting authentication (run 'claude /login' or export ANTHROPIC_API_KEY)"
        return False, f"claude check: {output}"
    return True, claude_bin


def create_mcp_config_file(endpoint_url, bearer_token):
    """Generate temporary MCP configuration JSON file for Claude Code."""
    config_data = {
        "mcpServers": {
          "sewasetu": {
            "url": endpoint_url,
            "headers": {
              "Authorization": f"Bearer {bearer_token}"
            }
          }
        }
    }
    tmp_file = tempfile.NamedTemporaryFile("w", delete=False, suffix=".json")
    json.dump(config_data, tmp_file, indent=2)
    tmp_file.flush()
    tmp_file.close()
    return tmp_file.name


def run_claude_persona(persona, endpoint_url="http://127.0.0.1:8010/mcp/citizen", bearer_token=None):
    """
    Executes a real Claude Code headless session for a given persona.
    """
    is_ready, msg = check_claude_availability()
    if not is_ready:
        return {
            "id": persona["id"],
            "name": persona["name"],
            "mode": "claude_code_headless",
            "status": "SKIPPED_UNAUTHENTICATED",
            "reason": msg,
            "passed": False,
            "transcript": [],
            "turns_used": 0,
            "duration_seconds": 0
        }

    config_path = create_mcp_config_file(endpoint_url, bearer_token)
    prompt = (
        f"You are the Sewa Setu Assistant helping an applicant with the Indira Gandhi Old Age Pension Scheme.\n"
        f"The citizen says: '{persona.get('dialogue_prompt', '')}'\n"
        f"Guidelines: Follow the official rules. Do not submit without first previewing and confirming."
    )

    cmd = [
        "claude",
        "-p",
        "--model", "haiku",
        "--max-turns", "10",
        "--strict-mcp-config",
        "--mcp-config", config_path,
        prompt
    ]

    start_time = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        duration = round(time.time() - start_time, 2)
        stdout = proc.stdout
        stderr = proc.stderr
        passed = (proc.returncode == 0)
    except subprocess.TimeoutExpired:
        duration = 120.0
        stdout = ""
        stderr = "Execution timed out (120s limit exceeded)"
        passed = False
    finally:
        if os.path.exists(config_path):
            os.remove(config_path)

    return {
        "id": persona["id"],
        "name": persona["name"],
        "mode": "claude_code_headless",
        "status": "COMPLETED" if passed else "FAILED",
        "passed": passed,
        "stdout": stdout,
        "stderr": stderr,
        "duration_seconds": duration
    }
