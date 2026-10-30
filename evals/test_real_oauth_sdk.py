# -*- coding: utf-8 -*-
"""
evals/test_real_oauth_sdk.py: Verification script for real OAuth 2.1 Code + PKCE
and official Python MCP SDK client against local or remote Sewa Setu servers.

Configuration & Precedence:
- BASE_URL: sys.argv[1] > os.environ["BASE_URL"] > os.environ["PUBLIC_BASE_URL"] > http://localhost:8000
- ADMIN_PASSWORD: Environment variable os.environ["ADMIN_PASSWORD"] takes strict precedence
  over any local .env file. Passwords are never hardcoded in source.
"""

import os
import sys
import time
import json
import base64
import hashlib
import secrets
import re
import threading
import asyncio
from urllib.parse import urlparse, parse_qs
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("SMS_GATEWAY_URL", "http://127.0.0.1:8025")

from mcp.client.session import ClientSession
import mcp.client.streamable_http as mcp_sh


def get_base_url():
    """Determine base URL from CLI argument, environment variable, or default."""
    if len(sys.argv) > 1 and sys.argv[1].startswith("http"):
        return sys.argv[1].rstrip("/")
    if os.environ.get("BASE_URL"):
        return os.environ.get("BASE_URL").rstrip("/")
    if os.environ.get("PUBLIC_BASE_URL"):
        return os.environ.get("PUBLIC_BASE_URL").rstrip("/")
    return "http://localhost:8000"


def get_admin_password():
    """Read officer admin password from environment without hardcoding."""
    pw = os.environ.get("ADMIN_PASSWORD")
    if not pw and os.path.exists(os.path.join(BASE_DIR, ".env")):
        with open(os.path.join(BASE_DIR, ".env")) as f:
            for line in f:
                line = line.strip()
                if line.startswith("ADMIN_PASSWORD=") and not line.startswith("#"):
                    pw = line.split("=", 1)[1].strip()
                    break
    return pw


def is_local_target(url):
    """Check if target URL points to a local instance."""
    return any(h in url for h in ("localhost", "127.0.0.1", "0.0.0.0"))


def start_services(base_portal, mcp_base, sms_gw_url):
    """Start local background services if running against localhost and not yet active."""
    os.environ.setdefault("PGHOST", "localhost")
    os.environ.setdefault("PGPORT", "5433")
    os.environ.setdefault("PGDATABASE", "sewasetu")
    os.environ.setdefault("PGUSER", "sewasetu")
    os.environ.setdefault("PGPASSWORD", "sewasetu123")

    import app as portal_app
    import server as mcp_server
    import smsgw.app as smsgw_app

    # Check if SMS gateway is already running
    try:
        requests.get(f"{sms_gw_url}/api/messages", timeout=0.5)
    except Exception:
        smsgw_app.DELAY_MIN = 0
        smsgw_app.DELAY_MAX = 0
        p_sms = urlparse(sms_gw_url).port or 8025
        t_sms = threading.Thread(
            target=lambda: smsgw_app.app.run(host="127.0.0.1", port=p_sms, debug=False, use_reloader=False),
            daemon=True
        )
        t_sms.start()

    # Check if Portal app is already running
    try:
        requests.get(f"{base_portal}/", timeout=0.5)
    except Exception:
        p_portal = urlparse(base_portal).port or 8000
        t_portal = threading.Thread(
            target=lambda: portal_app.app.run(host="127.0.0.1", port=p_portal, debug=False, use_reloader=False),
            daemon=True
        )
        t_portal.start()

    # Check if MCP server is already running
    try:
        requests.get(f"{mcp_base}/.well-known/oauth-protected-resource", timeout=0.5)
    except Exception:
        p_mcp = urlparse(mcp_base).port or 8010
        t_mcp = threading.Thread(
            target=lambda: mcp_server.app.run(host="127.0.0.1", port=p_mcp, debug=False, use_reloader=False),
            daemon=True
        )
        t_mcp.start()

    time.sleep(1.0)


def perform_oauth_code_pkce(base_portal, mcp_base, role="citizen", mobile="9990001001",
                            username=None, password=None, sms_gw_url=None):
    """Executes OAuth 2.1 Authorization Code grant with PKCE and dynamic client registration."""
    username = username or os.environ.get("ADMIN_USERNAME", "admin")
    mcp_res_url = f"{base_portal}/mcp/{role}"
    sess = requests.Session()

    # 1. Dynamic Client Registration
    reg_resp = sess.post(f"{base_portal}/oauth/register", json={
        "client_name": f"Test {role.capitalize()} Client",
        "redirect_uris": ["http://localhost:8899/callback"]
    }, timeout=5)
    if reg_resp.status_code != 201:
        raise RuntimeError(f"Client registration failed ({reg_resp.status_code}): {reg_resp.text}")
    reg_data = reg_resp.json()
    client_id = reg_data["client_id"]
    redirect_uri = reg_data["redirect_uris"][0]

    # 2. PKCE code challenge
    verifier = secrets.token_urlsafe(40)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")

    # 3. /oauth/authorize
    auth_url = (
        f"{base_portal}/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}"
        f"&response_type=code&code_challenge={challenge}&code_challenge_method=S256"
        f"&scope={role}&resource={mcp_res_url}"
    )
    auth_resp = sess.get(auth_url, allow_redirects=False, timeout=5)
    loc = auth_resp.headers.get("Location", "")
    rid = parse_qs(urlparse(loc).query).get("rid", [""])[0]
    if not rid:
        raise RuntimeError(f"Authorize did not return a valid rid: {auth_resp.status_code} {loc}")

    # 4. Login
    if role == "citizen":
        sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"mobile": mobile}, timeout=5)
        otp_code = None
        for _ in range(12):
            msgs = []
            # Try portal proxy first, then direct SMS gateway URL
            try:
                gw_resp = sess.get(f"{base_portal}/__gateway/api/messages?to={mobile}", timeout=5)
                if gw_resp.status_code == 200:
                    msgs = gw_resp.json().get("messages", [])
            except Exception:
                pass
            if not msgs and sms_gw_url:
                try:
                    gw_resp = sess.get(f"{sms_gw_url}/api/messages?to={mobile}", timeout=5)
                    if gw_resp.status_code == 200:
                        msgs = gw_resp.json().get("messages", [])
                except Exception:
                    pass

            for m in reversed(msgs):
                text = str(m.get("text") or "")
                match = re.search(r"\b\d{6}\b", text)
                if match:
                    otp_code = match.group(0)
                    break
            if otp_code:
                break
            time.sleep(0.4)

        if not otp_code:
            raise RuntimeError(f"Could not retrieve OTP for {mobile}")
        r_l = sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"otp": otp_code}, allow_redirects=False, timeout=5)
        if r_l.status_code != 302:
            raise RuntimeError(f"Citizen OTP login failed ({r_l.status_code}): {r_l.text[:200]}")
    else:
        if not password:
            raise RuntimeError("Cannot perform officer login: ADMIN_PASSWORD environment variable is not set.")
        r_l = sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"username": username, "password": password}, allow_redirects=False, timeout=5)
        if r_l.status_code != 302:
            raise RuntimeError(f"Officer credentials login failed ({r_l.status_code}): Invalid credentials.")

    # 5. Consent
    consent_resp = sess.post(f"{base_portal}/oauth/consent?rid={rid}", data={"decision": "allow"}, allow_redirects=False, timeout=5)
    cb_loc = consent_resp.headers.get("Location", "")
    code = parse_qs(urlparse(cb_loc).query).get("code", [""])[0]
    if not code:
        raise RuntimeError(f"Consent did not return authorization code ({consent_resp.status_code}): {consent_resp.text[:200]}")

    # 6. Exchange code for access token
    token_resp = sess.post(f"{base_portal}/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier
    }, timeout=5)
    token_data = token_resp.json()
    if token_resp.status_code != 200 or "access_token" not in token_data:
        raise RuntimeError(f"Token exchange failed ({token_resp.status_code}): {token_data}")
    return token_data["access_token"]


async def run_mcp_flow(endpoint, token, tool_name, tool_args):
    """Connects to MCP endpoint using the official Python SDK client and invokes tool."""
    headers = {"Authorization": f"Bearer {token}"}
    async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_res = await session.initialize()
                tools_res = await session.list_tools()
                call_res = await session.call_tool(tool_name, tool_args)
                return init_res, tools_res, call_res


def check_auth_responses(base_portal, mcp_base, sms_gw_url):
    """Verify HTTP 401 unauthenticated and HTTP 403 insufficient scope behavior."""
    # 1. Unauthenticated request to /mcp/citizen -> 401
    r_unauth = requests.post(f"{mcp_base}/mcp/citizen", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
    }, timeout=5)

    # 2. Citizen token to /mcp/officer -> 403
    citizen_token = perform_oauth_code_pkce(base_portal, mcp_base, role="citizen",
                                           mobile="9990001001", sms_gw_url=sms_gw_url)
    r_wrong_role = requests.post(f"{mcp_base}/mcp/officer", headers={"Authorization": f"Bearer {citizen_token}"}, json={
        "jsonrpc": "2.0", "id": 2, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
    }, timeout=5)

    return r_unauth, r_wrong_role, citizen_token


def check_rfc9728_discovery(base_portal, mcp_base):
    """Verify RFC 9728 discovery endpoints report valid URLs."""
    endpoints = [
        f"{base_portal}/.well-known/oauth-protected-resource",
        f"{mcp_base}/.well-known/oauth-protected-resource/mcp/citizen",
        f"{mcp_base}/.well-known/oauth-protected-resource/mcp/officer",
    ]
    # In local split mode, also verify port 8010 endpoints if different
    if mcp_base != base_portal:
        endpoints.append(f"{mcp_base}/.well-known/oauth-protected-resource")

    results = {}
    for url in endpoints:
        resp = requests.get(url, timeout=5)
        results[url] = {
            "status": resp.status_code,
            "data": resp.json() if resp.status_code == 200 else resp.text
        }
    return results


async def run_citizen_journey(mcp_base, citizen_token):
    """Executes full citizen journey: prepare, submit, resubmit rejection, and status tracking."""
    prepare_payload = {
        "applicant_name": "Test Remote Citizen",
        "dob": "12/05/1954",
        "gender": "Female",
        "marital_status": "Widowed",
        "husband_name": "Late Test Citizen",
        "village": "Udaypur",
        "block": "Borgaon",
        "bank_account": "987654321098",
        "ifsc": "SBIN0003077",
        "document_filename": "age_proof.jpg",
        "document_base64": base64.b64encode(b"test document image payload").decode("ascii")
    }

    endpoint = f"{mcp_base}/mcp/citizen"
    headers = {"Authorization": f"Bearer {citizen_token}"}
    async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # 1. prepare_application
                prep_res = await session.call_tool("prepare_application", prepare_payload)
                prep_data = json.loads(prep_res.content[0].text)
                confirm_token = prep_data.get("confirmation_token")

                # 2. submit_application
                sub_res = await session.call_tool("submit_application", {"confirmation_token": confirm_token})
                sub_data = json.loads(sub_res.content[0].text)

                # 3. submit same token again (must be rejected)
                resub_res = await session.call_tool("submit_application", {"confirmation_token": confirm_token})
                resub_data = json.loads(resub_res.content[0].text)

                # 4. track status
                status_res = await session.call_tool("get_my_status", {})
                status_data = json.loads(status_res.content[0].text)

                return prep_data, sub_data, resub_data, status_data


async def main():
    base_portal = get_base_url()
    os.environ["PUBLIC_BASE_URL"] = base_portal
    admin_password = get_admin_password()
    is_local = is_local_target(base_portal)

    if is_local:
        mcp_base = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8010")
        sms_gw_url = os.environ.get("SMS_GATEWAY_URL", "http://127.0.0.1:8025")
        print(f"=== 1. Starting Local Services (Target: {base_portal}) ===")
        start_services(base_portal, mcp_base, sms_gw_url)
    else:
        mcp_base = os.environ.get("MCP_BASE_URL", base_portal)
        sms_gw_url = f"{base_portal}/__gateway"
        print(f"=== 1. Targeting Remote Deployed Server: {base_portal} ===")

    print(f"Base Portal: {base_portal}")
    print(f"MCP Base:    {mcp_base}")
    print(f"SMS Gateway: {sms_gw_url}")
    print(f"Officer Admin Password Configured: {bool(admin_password)}")

    # 2. Citizen OAuth Flow
    print("\n=== 2. Citizen OAuth 2.1 Code + PKCE Flow ===")
    citizen_mobile = "9990001001" if is_local else "9990005544"
    citizen_token = perform_oauth_code_pkce(
        base_portal, mcp_base, role="citizen",
        mobile=citizen_mobile, sms_gw_url=sms_gw_url
    )
    print("Obtained Citizen OAuth access token successfully.")

    # 3. Officer OAuth Flow (if credentials available)
    officer_token = None
    if admin_password:
        print("\n=== 3. Officer OAuth 2.1 Code + PKCE Flow ===")
        try:
            officer_token = perform_oauth_code_pkce(
                base_portal, mcp_base, role="officer",
                password=admin_password, sms_gw_url=sms_gw_url
            )
            print("Obtained Officer OAuth access token successfully.")
        except Exception as e:
            print(f"Officer OAuth flow encountered error: {e}")
    else:
        print("\n=== 3. Officer OAuth 2.1 Code + PKCE Flow ===")
        print("SKIPPED: ADMIN_PASSWORD environment variable not set.")

    # 4. MCP Official SDK Client on /mcp/citizen
    print("\n=== 4. Official MCP SDK Client on /mcp/citizen ===")
    init_c, tools_c, call_c = await run_mcp_flow(
        f"{mcp_base}/mcp/citizen",
        citizen_token,
        "get_scheme_info",
        {}
    )
    print(f"Citizen Initialize Negotiated Version: {init_c.protocol_version}")
    print(f"Citizen Tools Listed ({len(tools_c.tools)}): {[t.name for t in tools_c.tools]}")
    print(f"Citizen get_scheme_info Result Preview: {call_c.content[0].text[:100]}...")

    # 5. MCP Official SDK Client on /mcp/officer
    if officer_token:
        print("\n=== 5. Official MCP SDK Client on /mcp/officer ===")
        init_o, tools_o, call_o = await run_mcp_flow(
            f"{mcp_base}/mcp/officer",
            officer_token,
            "queue_summary",
            {}
        )
        print(f"Officer Initialize Negotiated Version: {init_o.protocol_version}")
        print(f"Officer Tools Listed ({len(tools_o.tools)}): {[t.name for t in tools_o.tools]}")
        print(f"Officer queue_summary Result Preview: {call_o.content[0].text[:100]}...")
    else:
        print("\n=== 5. Official MCP SDK Client on /mcp/officer ===")
        print("SKIPPED: Officer token not available.")

    # 6. Auth Edge Cases (401 and 403)
    print("\n=== 6. Auth Edge Cases (401 and 403) ===")
    r_unauth, r_wrong_role, _ = check_auth_responses(base_portal, mcp_base, sms_gw_url)
    print(f"Unauthenticated /mcp/citizen status: {r_unauth.status_code}")
    print(f"Unauthenticated WWW-Authenticate header: {r_unauth.headers.get('WWW-Authenticate')}")
    print(f"Citizen token on /mcp/officer status: {r_wrong_role.status_code}")
    print(f"Citizen token on /mcp/officer body: {r_wrong_role.json()}")

    # 7. RFC 9728 Discovery Endpoints
    print("\n=== 7. RFC 9728 Discovery Endpoints ===")
    disc = check_rfc9728_discovery(base_portal, mcp_base)
    for u, res in disc.items():
        if res["status"] == 200 and isinstance(res["data"], dict):
            print(f"{u} -> {res['status']}: resource={res['data'].get('resource')} scopes={res['data'].get('scopes_supported')}")
        else:
            print(f"{u} -> {res['status']}: {res['data']}")

    # 8. Full Citizen Journey Remotely
    print("\n=== 8. Full Citizen Journey Remotely ===")
    journey_mobile = f"9990{secrets.randbelow(1000000):06d}"
    j_token = perform_oauth_code_pkce(
        base_portal, mcp_base, role="citizen",
        mobile=journey_mobile, sms_gw_url=sms_gw_url
    )
    prep_data, sub_data, resub_data, status_data = await run_citizen_journey(mcp_base, j_token)
    print(f"1. prepare_application status: {prep_data.get('status')} (draft_id={prep_data.get('draft_id')})")
    print(f"2. submit_application status:  {sub_data.get('status')} (app_no={sub_data.get('application_number')})")
    print(f"3. resubmit draft status:      {resub_data.get('status')} (error={resub_data.get('error')})")
    print(f"4. get_my_status result:       {status_data.get('status')} (app_no={status_data.get('application_number')}, status={status_data.get('current_status')})")

    if officer_token:
        # Officer list_applications check
        async with mcp_sh.create_mcp_http_client(headers={"Authorization": f"Bearer {officer_token}"}) as http_client:
            async with mcp_sh.streamable_http_client(f"{mcp_base}/mcp/officer", http_client=http_client) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    list_res = await session.call_tool("list_applications", {"status": "PENDING", "limit": 10})
                    print(f"5. Officer list_applications preview: {list_res.content[0].text[:120]}...")

    # 9. Eval Dashboard Verification
    print("\n=== 9. Eval Dashboard Verification ===")
    r_dash = requests.get(f"{base_portal}/eval-dashboard", timeout=5)
    print(f"/eval-dashboard status: {r_dash.status_code}")
    print(f"Dashboard contains 'Persona Evaluation Dashboard': {'Persona Evaluation Dashboard' in r_dash.text}")


if __name__ == "__main__":
    asyncio.run(main())
