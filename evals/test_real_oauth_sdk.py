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
os.environ.setdefault("PGHOST", "localhost")
os.environ.setdefault("PGPORT", "5433")
os.environ.setdefault("PGDATABASE", "sewasetu")
os.environ.setdefault("PGUSER", "sewasetu")
os.environ.setdefault("PGPASSWORD", "sewasetu123")
os.environ.setdefault("PUBLIC_BASE_URL", "http://localhost:8000")
os.environ.setdefault("SMS_GATEWAY_URL", "http://127.0.0.1:8025")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "SewaSetu@Assam2026!Review")

sys.path.insert(0, BASE_DIR)
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

import app as portal_app
import server as mcp_server
import smsgw.app as smsgw_app
from mcp.client.session import ClientSession
import mcp.client.streamable_http as mcp_sh


def start_services():
    # 1. SMS Gateway on 8025
    smsgw_app.DELAY_MIN = 0
    smsgw_app.DELAY_MAX = 0
    t_sms = threading.Thread(target=lambda: smsgw_app.app.run(host="127.0.0.1", port=8025, debug=False, use_reloader=False), daemon=True)
    t_sms.start()

    # 2. Portal App on 8000
    t_portal = threading.Thread(target=lambda: portal_app.app.run(host="127.0.0.1", port=8000, debug=False, use_reloader=False), daemon=True)
    t_portal.start()

    # 3. MCP Server on 8010
    t_mcp = threading.Thread(target=lambda: mcp_server.app.run(host="127.0.0.1", port=8010, debug=False, use_reloader=False), daemon=True)
    t_mcp.start()

    time.sleep(1.0)


def perform_oauth_code_pkce(role="citizen", mobile="9990001001", username="admin", password="SewaSetu@Assam2026!Review"):
    base_portal = "http://localhost:8000"
    mcp_res_url = f"{base_portal}/mcp/{role}"
    sess = requests.Session()

    # 1. Dynamic Client Registration
    reg_resp = sess.post(f"{base_portal}/oauth/register", json={
        "client_name": f"Test {role.capitalize()} Client",
        "redirect_uris": ["http://localhost:8899/callback"]
    }, timeout=5)
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

    # 4. Login
    if role == "citizen":
        sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"mobile": mobile}, timeout=5)
        otp_code = None
        for _ in range(10):
            gw_resp = sess.get(f"http://127.0.0.1:8025/api/messages?to={mobile}", timeout=5)
            msgs = gw_resp.json().get("messages", [])
            for m in reversed(msgs):
                match = re.search(r"\b\d{6}\b", m.get("text", ""))
                if match:
                    otp_code = match.group(0)
                    break
            if otp_code:
                break
            time.sleep(0.3)
        if not otp_code:
            raise RuntimeError(f"Could not retrieve OTP for {mobile}")
        sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"otp": otp_code}, allow_redirects=False, timeout=5)
    else:
        sess.post(f"{base_portal}/oauth/login?rid={rid}", data={"username": username, "password": password}, allow_redirects=False, timeout=5)

    # 5. Consent
    consent_resp = sess.post(f"{base_portal}/oauth/consent?rid={rid}", data={"decision": "allow"}, allow_redirects=False, timeout=5)
    cb_loc = consent_resp.headers.get("Location", "")
    code = parse_qs(urlparse(cb_loc).query).get("code", [""])[0]

    # 6. Exchange code for access token
    token_resp = sess.post(f"{base_portal}/oauth/token", data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier
    }, timeout=5)
    token_data = token_resp.json()
    return token_data["access_token"]


async def run_mcp_flow(endpoint, token, tool_name, tool_args):
    headers = {"Authorization": f"Bearer {token}"}
    async with mcp_sh.create_mcp_http_client(headers=headers) as http_client:
        async with mcp_sh.streamable_http_client(endpoint, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init_res = await session.initialize()
                tools_res = await session.list_tools()
                call_res = await session.call_tool(tool_name, tool_args)
                return init_res, tools_res, call_res


def check_auth_responses():
    base_url = "http://127.0.0.1:8010"
    
    # 1. Unauthenticated request to /mcp/citizen -> 401
    r_unauth = requests.post(f"{base_url}/mcp/citizen", json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
    }, timeout=5)
    
    # 2. Citizen token to /mcp/officer -> 403
    citizen_token = perform_oauth_code_pkce(role="citizen", mobile="9990001001")
    r_wrong_role = requests.post(f"{base_url}/mcp/officer", headers={"Authorization": f"Bearer {citizen_token}"}, json={
        "jsonrpc": "2.0", "id": 2, "method": "initialize",
        "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test", "version": "1.0"}}
    }, timeout=5)

    return r_unauth, r_wrong_role, citizen_token


def check_rfc9728_discovery():
    endpoints = [
        "http://localhost:8000/.well-known/oauth-protected-resource",
        "http://localhost:8000/.well-known/oauth-protected-resource/mcp/citizen",
        "http://localhost:8000/.well-known/oauth-protected-resource/mcp/officer",
        "http://127.0.0.1:8010/.well-known/oauth-protected-resource",
        "http://127.0.0.1:8010/.well-known/oauth-protected-resource/mcp/citizen",
        "http://127.0.0.1:8010/.well-known/oauth-protected-resource/mcp/officer",
    ]
    results = {}
    for url in endpoints:
        resp = requests.get(url, timeout=5)
        results[url] = {
            "status": resp.status_code,
            "data": resp.json()
        }
    return results


async def main():
    print("=== 1. Starting Services ===")
    start_services()

    print("\n=== 2. Real OAuth 2.1 Code + PKCE Flow ===")
    citizen_token = perform_oauth_code_pkce(role="citizen", mobile="9990001001")
    print("Obtained real Citizen OAuth token:", citizen_token[:15] + "..." + citizen_token[-10:])
    officer_token = perform_oauth_code_pkce(role="officer")
    print("Obtained real Officer OAuth token:", officer_token[:15] + "..." + officer_token[-10:])

    print("\n=== 3. Official MCP SDK Client on /mcp/citizen ===")
    init_c, tools_c, call_c = await run_mcp_flow(
        "http://127.0.0.1:8010/mcp/citizen",
        citizen_token,
        "get_scheme_info",
        {}
    )
    print(f"Citizen Initialize Version: {init_c.protocol_version}")
    print(f"Citizen Tools Listed: {len(tools_c.tools)} tools {[t.name for t in tools_c.tools]}")
    print(f"Citizen get_scheme_info result: {call_c.content[0].text[:120]}...")

    print("\n=== 4. Official MCP SDK Client on /mcp/officer ===")
    init_o, tools_o, call_o = await run_mcp_flow(
        "http://127.0.0.1:8010/mcp/officer",
        officer_token,
        "queue_summary",
        {}
    )
    print(f"Officer Initialize Version: {init_o.protocol_version}")
    print(f"Officer Tools Listed: {len(tools_o.tools)} tools {[t.name for t in tools_o.tools]}")
    print(f"Officer queue_summary result: {call_o.content[0].text[:120]}...")

    print("\n=== 5. Auth Edge Cases (401 and 403) ===")
    r_unauth, r_wrong_role, _ = check_auth_responses()
    print(f"Unauthenticated request status: {r_unauth.status_code}")
    print(f"Unauthenticated WWW-Authenticate header: {r_unauth.headers.get('WWW-Authenticate')}")
    print(f"Citizen token on /mcp/officer status: {r_wrong_role.status_code}")
    print(f"Citizen token on /mcp/officer body: {r_wrong_role.json()}")

    print("\n=== 6. RFC 9728 Discovery Endpoints ===")
    disc = check_rfc9728_discovery()
    for u, res in disc.items():
        print(f"{u} -> {res['status']}: resource={res['data'].get('resource')} scopes={res['data'].get('scopes_supported')}")


if __name__ == "__main__":
    asyncio.run(main())
