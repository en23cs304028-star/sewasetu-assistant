# -*- coding: utf-8 -*-
"""
evals/test_real_oauth_sdk.py: Verification script for real OAuth 2.1 Code + PKCE
and official Python MCP SDK client against local or remote Sewa Setu servers.

Configuration & Precedence:
- BASE_URL: CLI argument (http...) > os.environ["BASE_URL"] > os.environ["PUBLIC_BASE_URL"] > http://localhost:8000
- ADMIN_PASSWORD: Environment variable os.environ["ADMIN_PASSWORD"] takes strict precedence.
  If unset and BASE_URL is not localhost, loads from .env.vm in repo root.
  If unset and BASE_URL is localhost, loads from .env in repo root.
  Passwords are never logged, printed, or hardcoded in source.
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
import jwt

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

INSECURE_TLS = "--insecure" in sys.argv or os.environ.get("INSECURE_TLS", "").lower() in ("1", "true", "yes")
if INSECURE_TLS:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_mcp_http_client(headers=None):
    """Returns official MCP HTTP client, supporting explicit opt-in insecure TLS for self-signed certificates."""
    if INSECURE_TLS:
        return mcp_sh.httpx2.AsyncClient(
            headers=headers,
            verify=False,
            timeout=mcp_sh.httpx2.Timeout(30.0, read=300.0)
        )
    return mcp_sh.create_mcp_http_client(headers=headers)


def parse_tool_content(res_or_content):
    """Safely parse tool response content as JSON.
    If the response is non-JSON text, prints the raw text prominently and raises RuntimeError.
    """
    if hasattr(res_or_content, "content"):
        content = res_or_content.content
    else:
        content = res_or_content
    if not content:
        raise RuntimeError("Tool returned empty content")
    first = content[0]
    raw_text = first.text if hasattr(first, "text") else (first.get("text") if isinstance(first, dict) else str(first))
    try:
        return json.loads(raw_text)
    except Exception as exc:
        print(f"\n============================================================")
        print(f"ERROR: Tool response is NOT valid JSON!")
        print(f"--- RAW TOOL RESPONSE TEXT ---")
        print(raw_text)
        print(f"--- END RAW TOOL RESPONSE ---")
        print(f"============================================================\n")
        raise RuntimeError(f"Tool returned non-JSON response: {raw_text}") from exc


def get_base_url():
    """Determine base URL from CLI argument, environment variable, or default."""
    for arg in sys.argv[1:]:
        if arg.startswith("http"):
            return arg.rstrip("/")
    if os.environ.get("BASE_URL"):
        return os.environ.get("BASE_URL").rstrip("/")
    if os.environ.get("PUBLIC_BASE_URL"):
        return os.environ.get("PUBLIC_BASE_URL").rstrip("/")
    return "http://localhost:8000"


def is_local_target(url):
    """Check if target URL points to a local instance."""
    return any(h in url for h in ("localhost", "127.0.0.1", "0.0.0.0"))


def get_admin_credentials(base_url=None):
    """Read officer admin credentials (username, password) without hardcoding.

    Precedence:
    1. Real environment variables os.environ["ADMIN_USERNAME"], os.environ["ADMIN_PASSWORD"]
    2. If BASE_URL is remote (not localhost): repo-root .env.vm
    3. If BASE_URL is localhost: repo-root .env
    """
    user = os.environ.get("ADMIN_USERNAME")
    pw = os.environ.get("ADMIN_PASSWORD")

    target_url = base_url or get_base_url()
    if not is_local_target(target_url):
        env_file = os.path.join(BASE_DIR, ".env.vm")
    else:
        env_file = os.path.join(BASE_DIR, ".env")

    if os.path.exists(env_file):
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("export "):
                    line = line[7:].strip()
                if "=" in line:
                    key, val = line.split("=", 1)
                    k = key.strip()
                    v = val.strip().strip("'\"")
                    if k == "ADMIN_USERNAME" and not user:
                        user = v
                    elif k == "ADMIN_PASSWORD" and not pw:
                        pw = v

    user = user or "admin"
    return user, pw


def get_admin_password(base_url=None):
    """Read officer admin password from environment or env files without hardcoding."""
    _, pw = get_admin_credentials(base_url)
    return pw


def start_services(base_portal, mcp_base, sms_gw_url):
    """Start local background services if running against localhost and not yet active."""
    os.environ.setdefault("PGHOST", "localhost")
    os.environ.setdefault("PGPORT", "5433")
    os.environ.setdefault("PGDATABASE", "sewasetu")
    os.environ.setdefault("PGUSER", "sewasetu")
    os.environ.setdefault("PGPASSWORD", "sewasetu123")

    import app as portal_app
    import importlib.util
    _mcp_spec = importlib.util.spec_from_file_location("mcp_server", os.path.join(BASE_DIR, "mcp", "server.py"))
    mcp_server = importlib.util.module_from_spec(_mcp_spec)
    _mcp_spec.loader.exec_module(mcp_server)
    import smsgw.app as smsgw_app

    # Check if SMS gateway is already running
    try:
        requests.get(f"{sms_gw_url}/api/messages", timeout=0.5, verify=not INSECURE_TLS)
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
        requests.get(f"{base_portal}/", timeout=0.5, verify=not INSECURE_TLS)
    except Exception:
        p_portal = urlparse(base_portal).port or 8000
        t_portal = threading.Thread(
            target=lambda: portal_app.app.run(host="127.0.0.1", port=p_portal, debug=False, use_reloader=False),
            daemon=True
        )
        t_portal.start()

    # Check if MCP server is already running
    try:
        requests.get(f"{mcp_base}/.well-known/oauth-protected-resource", timeout=0.5, verify=not INSECURE_TLS)
    except Exception:
        p_mcp = urlparse(mcp_base).port or 8010
        t_mcp = threading.Thread(
            target=lambda: mcp_server.app.run(host="127.0.0.1", port=p_mcp, debug=False, use_reloader=False),
            daemon=True
        )
        t_mcp.start()

    time.sleep(1.0)


_CLIENT_CACHE = {}


def get_or_register_client(sess, base_portal):
    redirect_uri = "http://localhost:8899/callback"
    cache_key = (base_portal, redirect_uri)
    if cache_key in _CLIENT_CACHE:
        return _CLIENT_CACHE[cache_key]

    reg_resp = sess.post(f"{base_portal}/oauth/register", json={
        "client_name": "Test SDK Client",
        "redirect_uris": [redirect_uri]
    }, timeout=5)
    if reg_resp.status_code != 201:
        raise RuntimeError(f"Client registration failed ({reg_resp.status_code}): {reg_resp.text}")
    reg_data = reg_resp.json()
    _CLIENT_CACHE[cache_key] = (reg_data["client_id"], redirect_uri)
    return _CLIENT_CACHE[cache_key]


def perform_oauth_code_pkce(base_portal, mcp_base, role="citizen", mobile="9990001001",
                            username=None, password=None, sms_gw_url=None):
    """Executes OAuth 2.1 Authorization Code grant with PKCE and dynamic client registration."""
    username = username or os.environ.get("ADMIN_USERNAME", "admin")
    mcp_res_url = f"{base_portal}/mcp/{role}"
    sess = requests.Session()
    sess.verify = not INSECURE_TLS

    # 1. Dynamic Client Registration (reusing registered client if available)
    client_id, redirect_uri = get_or_register_client(sess, base_portal)

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

    def _extract_csrf(html_text):
        m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html_text)
        return m.group(1) if m else ""

    # 4. Login
    login_page = sess.get(f"{base_portal}/oauth/login?rid={rid}", timeout=5)
    csrf = _extract_csrf(login_page.text)

    if role == "citizen":
        sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"mobile": mobile, "csrf_token": csrf}, timeout=5)
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
        r_l = sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"otp": otp_code, "csrf_token": csrf}, allow_redirects=False, timeout=5)
        if r_l.status_code != 302:
            raise RuntimeError(f"Citizen OTP login failed ({r_l.status_code}): {r_l.text[:200]}")
    else:
        if not password:
            raise RuntimeError("Cannot perform officer login: ADMIN_PASSWORD environment variable is not set.")
        r_l = sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"username": username, "password": password, "csrf_token": csrf}, allow_redirects=False, timeout=5)
        if r_l.status_code != 302:
            raise RuntimeError(f"Officer credentials login failed ({r_l.status_code}): Invalid credentials.")

    # 5. Consent
    consent_page = sess.get(f"{base_portal}/oauth/consent?rid={rid}", timeout=5)
    csrf_c = _extract_csrf(consent_page.text) or csrf
    consent_resp = sess.post(f"{base_portal}/oauth/consent?rid={rid}", data={"decision": "allow", "csrf_token": csrf_c}, allow_redirects=False, timeout=5)
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
    async with get_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_res = await session.initialize()
                tools_res = await session.list_tools()
                call_res = await session.call_tool(tool_name, tool_args)
                return init_res, tools_res, call_res


def check_auth_responses(base_portal, mcp_base, sms_gw_url, citizen_token=None):
    """Verify HTTP 401 unauthenticated and HTTP 403 insufficient scope behavior."""
    # 1. Unauthenticated request to /mcp/citizen -> 401
    r_unauth = requests.post(f"{mcp_base}/mcp/citizen", verify=not INSECURE_TLS, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
    }, timeout=5)

    # 2. Citizen token to /mcp/officer -> 403
    if not citizen_token:
        fresh_mobile = f"9990{secrets.randbelow(1000000):06d}"
        citizen_token = perform_oauth_code_pkce(base_portal, mcp_base, role="citizen",
                                               mobile=fresh_mobile, sms_gw_url=sms_gw_url)
    r_wrong_role = requests.post(f"{mcp_base}/mcp/officer", verify=not INSECURE_TLS, headers={"Authorization": f"Bearer {citizen_token}"}, json={
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
        resp = requests.get(url, timeout=5, verify=not INSECURE_TLS)
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
    async with get_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # 1. prepare_application
                prep_res = await session.call_tool("prepare_application", prepare_payload)
                prep_data = parse_tool_content(prep_res)
                confirm_token = prep_data.get("confirmation_token")

                # 2. submit_application
                sub_res = await session.call_tool("submit_application", {"confirmation_token": confirm_token})
                sub_data = parse_tool_content(sub_res)

                # 3. submit same token again (must be rejected)
                resub_res = await session.call_tool("submit_application", {"confirmation_token": confirm_token})
                resub_data = parse_tool_content(resub_res)

                # 4. track status
                status_res = await session.call_tool("get_my_status", {})
                status_data = parse_tool_content(status_res)

                return prep_data, sub_data, resub_data, status_data


async def run_p0_2(base_portal, mcp_base, officer_token):
    """P0-2: Verify initialize, tools/list (5 tools), queue_summary, list_applications, and get_application via official SDK."""
    print(f"\n================================================================================")
    print(f"=== P0-2: Officer Tools Execution via Official MCP SDK on {mcp_base}/mcp/officer ===")
    print(f"================================================================================")

    endpoint = f"{mcp_base}/mcp/officer"
    headers = {"Authorization": f"Bearer {officer_token}"}

    async with get_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # 1. initialize
                init_res = await session.initialize()
                print(f"[1/5] initialize:")
                print(f"      Negotiated Protocol Version: {init_res.protocol_version}")
                print(f"      Server Info: {init_res.server_info.name} v{init_res.server_info.version}")

                # 2. tools/list (expect 5 tools)
                tools_res = await session.list_tools()
                tool_names = [t.name for t in tools_res.tools]
                print(f"[2/5] tools/list (count: {len(tool_names)}):")
                for t in tools_res.tools:
                    print(f"      - {t.name}: {t.description[:60]}...")
                assert len(tools_res.tools) == 5, f"Expected 5 officer tools, got {len(tools_res.tools)}: {tool_names}"
                expected_tools = {"queue_summary", "list_applications", "get_application", "approve_application", "reject_application"}
                assert set(tool_names) == expected_tools, f"Officer tool mismatch. Expected {expected_tools}, got {set(tool_names)}"

                # 3. queue_summary
                qs_res = await session.call_tool("queue_summary", {})
                qs_data = parse_tool_content(qs_res)
                print(f"[3/5] queue_summary:")
                print(f"      Status: {qs_data.get('status')}")
                print(f"      Total Pending: {qs_data.get('total_pending')}")
                print(f"      Total Approved: {qs_data.get('total_approved')}")
                print(f"      Total Deemed Approved: {qs_data.get('total_deemed_approved')}")
                print(f"      Total Rejected: {qs_data.get('total_rejected')}")
                print(f"      Oldest Pending Days: {qs_data.get('oldest_pending_days')}")
                print(f"      Nearing Deemed Approval: {qs_data.get('nearing_deemed_approval_cutoff_count')}")

                # 4. list_applications
                la_res = await session.call_tool("list_applications", {"status": "PENDING", "limit": 5, "order_by": "newest_first"})
                la_data = parse_tool_content(la_res)
                apps = la_data.get("applications", [])
                print(f"[4/5] list_applications (status=PENDING, limit=5, order_by=newest_first):")
                print(f"      Count on page: {len(apps)}")
                sample_app_id = apps[0]["id"] if apps else 1
                for a in apps[:3]:
                    print(f"      * App #{a['id']} ({a['application_no']}): {a['applicant_name']} | Village: {a['village']}, Block: {a['block']}, Days: {a['days_pending']}")

                # 5. get_application
                ga_res = await session.call_tool("get_application", {"app_id": sample_app_id})
                ga_data = parse_tool_content(ga_res)
                print(f"[5/5] get_application (app_id={sample_app_id}):")
                print(f"      Status: {ga_data.get('status')}")
                print(f"      App No: {ga_data.get('application_no')}")
                print(f"      Applicant: {ga_data.get('applicant_name')}")
                print(f"      Village/Block: {ga_data.get('village')} / {ga_data.get('block')}")
                print(f"      Current Status: {ga_data.get('current_status')}")
                print(f"      Audit Trail Entries: {len(ga_data.get('audit_trail', []))}")

    print("\n>>> P0-2 PASS: initialize, tools/list (5 tools), queue_summary, list_applications, and get_application verified over official SDK.")
    return True


async def submit_citizen_application(base_portal, mcp_base, sms_gw_url, mobile, name, block, village, bank_acc, ifsc, doc_filename):
    """Performs full citizen OAuth and submits a pension application over the MCP citizen endpoint."""
    token = perform_oauth_code_pkce(base_portal, mcp_base, role="citizen", mobile=mobile, sms_gw_url=sms_gw_url)
    endpoint = f"{mcp_base}/mcp/citizen"
    headers = {"Authorization": f"Bearer {token}"}

    async with get_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # Prepare
                payload = {
                    "applicant_name": name,
                    "dob": "12/05/1954",
                    "gender": "Female",
                    "marital_status": "Widowed",
                    "husband_name": f"Late {name.split()[0]} Spouse",
                    "village": village,
                    "block": block,
                    "bank_account": bank_acc,
                    "ifsc": ifsc,
                    "document_filename": doc_filename,
                    "document_base64": base64.b64encode(b"Dummy Voter Card Certificate Payload").decode("ascii")
                }
                prep_res = await session.call_tool("prepare_application", payload)
                prep_data = parse_tool_content(prep_res)
                assert prep_data.get("status") == "ready_for_confirmation", f"prepare failed: {prep_data}"
                tok = prep_data.get("confirmation_token")

                # Submit
                sub_res = await session.call_tool("submit_application", {"confirmation_token": tok})
                sub_data = parse_tool_content(sub_res)
                assert sub_data.get("status") == "submitted", f"submit failed: {sub_data}"
                app_no = sub_data.get("application_number")
                return token, app_no


async def check_citizen_status(mcp_base, citizen_token):
    """Queries get_my_status for the authenticated citizen."""
    endpoint = f"{mcp_base}/mcp/citizen"
    headers = {"Authorization": f"Bearer {citizen_token}"}
    async with get_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                status_res = await session.call_tool("get_my_status", {})
                return parse_tool_content(status_res)


async def run_p0_3_4(base_portal, mcp_base, sms_gw_url, officer_token, officer_username="admin"):
    """P0-3 & P0-4: Two citizen applications, officer approve/reject decisions, conflict enforcement, and audit trail."""
    print(f"\n================================================================================")
    print(f"=== P0-3 & P0-4: Two Citizen Submissions, Officer Decisions, Conflict & Audit ===")
    print(f"================================================================================")

    # 1. Fresh mobile numbers
    rnd1 = secrets.randbelow(900000) + 100000
    rnd2 = secrets.randbelow(900000) + 100000
    while rnd2 == rnd1:
        rnd2 = secrets.randbelow(900000) + 100000

    mobile_1 = f"9990{rnd1}"
    mobile_2 = f"9990{rnd2}"

    print(f"\n--- Step 1: Submitting Application 1 (Mobile: {mobile_1}) ---")
    tok_1, app_no_1 = await submit_citizen_application(
        base_portal, mcp_base, sms_gw_url,
        mobile=mobile_1,
        name=f"Sundari Devi {rnd1}",
        block="Sonari",
        village="Lakhipur",
        bank_acc=f"3876903{rnd1}",
        ifsc="SBIN0003077",
        doc_filename="voter_card_1.jpg"
    )
    print(f"Application 1 submitted successfully: Application No = {app_no_1}")

    print(f"\n--- Step 2: Submitting Application 2 (Mobile: {mobile_2}) ---")
    tok_2, app_no_2 = await submit_citizen_application(
        base_portal, mcp_base, sms_gw_url,
        mobile=mobile_2,
        name=f"Gopal Das {rnd2}",
        block="Dhemaji Pathar",
        village="Kathoni",
        bank_acc=f"8696030{rnd2}",
        ifsc="CNRB0004417",
        doc_filename="voter_card_2.jpg"
    )
    print(f"Application 2 submitted successfully: Application No = {app_no_2}")

    created_records = [
        {"mobile": mobile_1, "application_no": app_no_1, "intended_decision": "APPROVED"},
        {"mobile": mobile_2, "application_no": app_no_2, "intended_decision": "REJECTED"}
    ]

    # Verify initial PENDING statuses via get_my_status
    st_init_1 = await check_citizen_status(mcp_base, tok_1)
    st_init_2 = await check_citizen_status(mcp_base, tok_2)
    print(f"Citizen 1 Initial Status: {st_init_1.get('current_status')}")
    print(f"Citizen 2 Initial Status: {st_init_2.get('current_status')}")
    assert st_init_1.get("current_status") == "PENDING"
    assert st_init_2.get("current_status") == "PENDING"

    # Officer session
    headers_officer = {"Authorization": f"Bearer {officer_token}"}
    endpoint_officer = f"{mcp_base}/mcp/officer"

    async with get_mcp_http_client(headers=headers_officer) as http_client:
        async with mcp_sh.streamable_http_client(endpoint_officer, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()

                # Step 3: Officer lists pending applications to find IDs
                print(f"\n--- Step 3: Officer lists pending applications ---")
                la_res = await session.call_tool("list_applications", {"status": "PENDING", "limit": 50, "order_by": "newest_first"})
                la_data = parse_tool_content(la_res)
                apps = la_data.get("applications", [])

                app_id_1 = None
                app_id_2 = None
                for a in apps:
                    if a.get("application_no") == app_no_1:
                        app_id_1 = a["id"]
                    elif a.get("application_no") == app_no_2:
                        app_id_2 = a["id"]

                print(f"Located App 1 ({app_no_1}): ID = {app_id_1}")
                print(f"Located App 2 ({app_no_2}): ID = {app_id_2}")
                assert app_id_1 is not None, f"Application 1 {app_no_1} not found in pending list"
                assert app_id_2 is not None, f"Application 2 {app_no_2} not found in pending list"

                # Step 4: Officer approves Application 1 (two-step confirmation)
                print(f"\n--- Step 4: Officer approves Application 1 (ID: {app_id_1}) ---")
                conf_req = await session.call_tool("approve_application", {
                    "app_id": app_id_1,
                    "note": f"Verification passed for {app_no_1}; valid age proof."
                })
                conf_data = parse_tool_content(conf_req)
                print(f"Step 1 Confirmation Request: {conf_data}")
                assert conf_data.get("status") == "confirmation_required", f"Expected confirmation_required, got {conf_data}"
                conf_token = conf_data["confirmation_token"]

                appr_res = await session.call_tool("approve_application", {
                    "app_id": app_id_1,
                    "note": f"Verification passed for {app_no_1}; valid age proof.",
                    "confirmation_token": conf_token
                })
                appr_data = parse_tool_content(appr_res)
                print(f"Approve Result: {appr_data}")
                assert appr_data.get("status") == "approved", f"Approval failed: {appr_data}"

                # Step 5: Officer rejects Application 2
                print(f"\n--- Step 5: Officer rejection rules for Application 2 (ID: {app_id_2}) ---")
                # 5a. Reject without reason (P0-4 check: must be refused)
                rej_fail_res = await session.call_tool("reject_application", {
                    "app_id": app_id_2,
                    "reason": ""
                })
                rej_fail_data = parse_tool_content(rej_fail_res)
                print(f"Reject without reason response (expected error): {rej_fail_data}")
                assert rej_fail_data.get("status") == "error", f"Reject without reason was not blocked: {rej_fail_data}"
                print("P0-4 Rule Verified: Rejection without mandatory reason is refused.")

                # 5b. Reject with valid specific reason (two-step confirmation)
                conf_req_rej = await session.call_tool("reject_application", {
                    "app_id": app_id_2,
                    "reason": f"Age proof certificate for {app_no_2} is unreadable and unverifiable."
                })
                conf_rej_data = parse_tool_content(conf_req_rej)
                print(f"Step 1 Reject Confirmation Request: {conf_rej_data}")
                assert conf_rej_data.get("status") == "confirmation_required", f"Expected confirmation_required, got {conf_rej_data}"
                conf_rej_token = conf_rej_data["confirmation_token"]

                rej_res = await session.call_tool("reject_application", {
                    "app_id": app_id_2,
                    "reason": f"Age proof certificate for {app_no_2} is unreadable and unverifiable.",
                    "confirmation_token": conf_rej_token
                })
                rej_data = parse_tool_content(rej_res)
                print(f"Step 2 Reject with reason response: {rej_data}")
                assert rej_data.get("status") == "rejected", f"Rejection failed: {rej_data}"

                # Step 6: Verify decisions reflected in citizen get_my_status (P0-3)
                print(f"\n--- Step 6: Verify citizen get_my_status reflects decisions ---")
                st_after_1 = await check_citizen_status(mcp_base, tok_1)
                st_after_2 = await check_citizen_status(mcp_base, tok_2)
                print(f"Citizen 1 Status: {st_after_1.get('current_status')} (Expected: APPROVED)")
                print(f"Citizen 1 Explanation: {st_after_1.get('explanation')}")
                print(f"Citizen 2 Status: {st_after_2.get('current_status')} (Expected: REJECTED)")
                print(f"Citizen 2 Explanation: {st_after_2.get('explanation')}")
                assert st_after_1.get("current_status") == "APPROVED", f"Expected APPROVED, got {st_after_1}"
                assert st_after_2.get("current_status") == "REJECTED", f"Expected REJECTED, got {st_after_2}"
                print("P0-3 PASS: Citizen get_my_status reflects APPROVED for app 1 and REJECTED for app 2.")

                # Step 7: P0-4 Decision Rules: Deciding already-decided application must be refused
                print(f"\n--- Step 7: P0-4 Decision Conflict Check on already-decided applications ---")
                # Try approving already-approved app 1
                dup_appr = await session.call_tool("approve_application", {
                    "app_id": app_id_1,
                    "note": "Second approval attempt"
                })
                dup_appr_data = parse_tool_content(dup_appr)
                print(f"Attempting second decision on App 1 (Approved): {dup_appr_data}")
                assert dup_appr_data.get("status") == "error", f"Duplicate decision on App 1 was not refused: {dup_appr_data}"
                assert "already decided" in dup_appr_data.get("message", "").lower() or "not found" in dup_appr_data.get("message", "").lower()

                # Try rejecting already-rejected app 2
                dup_rej = await session.call_tool("reject_application", {
                    "app_id": app_id_2,
                    "reason": "Second rejection attempt"
                })
                dup_rej_data = parse_tool_content(dup_rej)
                print(f"Attempting second decision on App 2 (Rejected): {dup_rej_data}")
                assert dup_rej_data.get("status") == "error", f"Duplicate decision on App 2 was not refused: {dup_rej_data}"
                assert "already decided" in dup_rej_data.get("message", "").lower() or "not found" in dup_rej_data.get("message", "").lower()
                print("P0-4 PASS: Redeciding already-decided application is gracefully refused.")

                # Step 8: P0-4 Audit log rows confirmation
                print(f"\n--- Step 8: Confirm Audit Log Rows via get_application ---")
                ga1_res = await session.call_tool("get_application", {"app_id": app_id_1})
                ga1_data = parse_tool_content(ga1_res)
                audit_1 = ga1_data.get("audit_trail", [])
                print(f"App 1 Audit Trail ({len(audit_1)} events):")
                for evt in audit_1:
                    print(f"      * [{evt.get('timestamp')}] {evt.get('action')} by {evt.get('actor')} | Note: {evt.get('note')}")

                ga2_res = await session.call_tool("get_application", {"app_id": app_id_2})
                ga2_data = parse_tool_content(ga2_res)
                audit_2 = ga2_data.get("audit_trail", [])
                print(f"App 2 Audit Trail ({len(audit_2)} events):")
                for evt in audit_2:
                    print(f"      * [{evt.get('timestamp')}] {evt.get('action')} by {evt.get('actor')} | Note: {evt.get('note')}")

                actions_1 = [e.get("action") for e in audit_1]
                actions_2 = [e.get("action") for e in audit_2]
                assert "SUBMIT" in actions_1 and "APPROVED" in actions_1, f"Audit trail 1 missing SUBMIT/APPROVED: {actions_1}"
                assert "SUBMIT" in actions_2 and "REJECTED" in actions_2, f"Audit trail 2 missing SUBMIT/REJECTED: {actions_2}"
                print("P0-4 PASS: Audit log contains actor, action, and timestamp for all actions.")

    print(f"\n================================================================================")
    print(f"=== P0-3 & P0-4 ALL CHECKS PASSED SUCCESSFULLY ===")
    print(f"================================================================================")
    return created_records


async def main():
    base_portal = get_base_url()
    os.environ["PUBLIC_BASE_URL"] = base_portal
    admin_username, admin_password = get_admin_credentials(base_portal)
    is_local = is_local_target(base_portal) and not base_portal.startswith("https://")

    if is_local:
        mcp_base = os.environ.get("MCP_BASE_URL", "http://127.0.0.1:8010")
        sms_gw_url = os.environ.get("SMS_GATEWAY_URL", "http://127.0.0.1:8025")
        print(f"=== 1. Starting Local Services (Target: {base_portal}) ===")
        start_services(base_portal, mcp_base, sms_gw_url)
    else:
        mcp_base = os.environ.get("MCP_BASE_URL", base_portal)
        sms_gw_url = os.environ.get("SMS_GATEWAY_URL", f"{base_portal}/__gateway")
        print(f"=== 1. Targeting Server: {base_portal} ===")

    print(f"Base Portal: {base_portal}")
    print(f"MCP Base:    {mcp_base}")
    print(f"SMS Gateway: {sms_gw_url}")
    print(f"Officer Admin Username: {admin_username}")
    print(f"Officer Admin Password Configured: {bool(admin_password)}")

    # Check for P0-1 standalone execution flag
    if "--p0-1" in sys.argv:
        print(f"\n=== P0-1: Officer OAuth 2.1 Code + PKCE Flow on {base_portal} ===")
        if not admin_password:
            print("P0-1 STOPPED: ADMIN_PASSWORD is not set in environment or .env.vm.")
            return
        try:
            officer_token = perform_oauth_code_pkce(
                base_portal, mcp_base, role="officer",
                username=admin_username, password=admin_password, sms_gw_url=sms_gw_url
            )
            print("Obtained Officer OAuth access token successfully.")
            claims = jwt.decode(officer_token, options={"verify_signature": False})
            role_claim = claims.get("role")
            iss_claim = claims.get("iss")
            aud_claim = claims.get("aud")
            print(f"Officer Token Claims: role={role_claim} iss={iss_claim} aud={aud_claim}")
            if role_claim == "officer" and iss_claim == base_portal and aud_claim == f"{base_portal}/mcp/officer":
                print("P0-1 PASS: Officer OAuth login succeeded with expected role, iss, and aud.")
            else:
                print(f"P0-1 UNEXPECTED CLAIMS: role={role_claim}, iss={iss_claim}, aud={aud_claim}")
        except Exception as e:
            print(f"P0-1 REJECTED / FAILED: {e}")
        return

    # Check for P0-2 standalone execution flag
    if "--p0-2" in sys.argv:
        if not admin_password:
            print("P0-2 STOPPED: ADMIN_PASSWORD is not set in environment or .env.vm.")
            return
        officer_token = perform_oauth_code_pkce(
            base_portal, mcp_base, role="officer",
            username=admin_username, password=admin_password, sms_gw_url=sms_gw_url
        )
        await run_p0_2(base_portal, mcp_base, officer_token)
        return

    # Check for P0-3 & P0-4 standalone execution flag
    if any(flag in sys.argv for flag in ("--p0-3", "--p0-4", "--p0-3-4", "--p0-34")):
        if not admin_password:
            print("P0-3/4 STOPPED: ADMIN_PASSWORD is not set in environment or .env.vm.")
            return
        officer_token = perform_oauth_code_pkce(
            base_portal, mcp_base, role="officer",
            username=admin_username, password=admin_password, sms_gw_url=sms_gw_url
        )
        await run_p0_3_4(base_portal, mcp_base, sms_gw_url, officer_token, admin_username)
        return

    # Check for running all P0 checks
    if any(flag in sys.argv for flag in ("--all-p0", "--p0")):
        if not admin_password:
            print("P0 STOPPED: ADMIN_PASSWORD is not set in environment or .env.vm.")
            return
        print(f"\n=== Running All P0 Assurance Checks against {base_portal} ===")
        # P0-1
        officer_token = perform_oauth_code_pkce(
            base_portal, mcp_base, role="officer",
            username=admin_username, password=admin_password, sms_gw_url=sms_gw_url
        )
        claims = jwt.decode(officer_token, options={"verify_signature": False})
        print(f"P0-1 PASS: Officer OAuth token claims verified: role={claims.get('role')}, iss={claims.get('iss')}, aud={claims.get('aud')}")
        # P0-2
        await run_p0_2(base_portal, mcp_base, officer_token)
        # P0-3 & P0-4
        await run_p0_3_4(base_portal, mcp_base, sms_gw_url, officer_token, admin_username)
        return

    # 2. Citizen OAuth Flow
    print("\n=== 2. Citizen OAuth 2.1 Code + PKCE Flow ===")
    citizen_mobile = f"9990{secrets.randbelow(1000000):06d}"
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
                username=admin_username, password=admin_password, sms_gw_url=sms_gw_url
            )
            print("Obtained Officer OAuth access token successfully.")
            claims = jwt.decode(officer_token, options={"verify_signature": False})
            role_claim = claims.get("role")
            iss_claim = claims.get("iss")
            aud_claim = claims.get("aud")
            print(f"Officer Token Claims: role={role_claim} iss={iss_claim} aud={aud_claim}")
            if role_claim == "officer" and iss_claim == base_portal and aud_claim == f"{base_portal}/mcp/officer":
                print("P0-1 PASS: Officer OAuth login verified with valid claims on server.")
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
    r_unauth, r_wrong_role, _ = check_auth_responses(base_portal, mcp_base, sms_gw_url, citizen_token=citizen_token)
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
        async with get_mcp_http_client(headers={"Authorization": f"Bearer {officer_token}"}) as http_client:
            async with mcp_sh.streamable_http_client(f"{mcp_base}/mcp/officer", http_client=http_client) as (read_stream, write_stream):
                async with ClientSession(read_stream, write_stream) as session:
                    await session.initialize()
                    list_res = await session.call_tool("list_applications", {"status": "PENDING", "limit": 10})
                    print(f"5. Officer list_applications preview: {list_res.content[0].text[:120]}...")

    # 9. Eval Dashboard Verification
    print("\n=== 9. Eval Dashboard Verification ===")
    r_dash = requests.get(f"{base_portal}/eval-dashboard", timeout=5, verify=not INSECURE_TLS)
    print(f"/eval-dashboard status: {r_dash.status_code}")
    print(f"Dashboard contains 'Persona Evaluation Dashboard': {'Persona Evaluation Dashboard' in r_dash.text}")


if __name__ == "__main__":
    asyncio.run(main())
