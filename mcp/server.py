# -*- coding: utf-8 -*-
"""
mcp/server.py: Streamable HTTP & SSE MCP Server
Exposes:
  - /.well-known/oauth-protected-resource (RFC 9728)
  - /mcp/citizen (tools for applicants, scope=citizen)
  - /mcp/officer (tools for block officers, scope=officer)
Supports standard MCP JSON-RPC 2.0 over HTTP POST and Server-Sent Events (SSE).
"""

import os
import sys
import json
import threading
from urllib.parse import urlparse
from flask import Flask, request, Response, jsonify

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "app"))
sys.path.insert(0, os.path.join(BASE_DIR, "mcp"))

import auth
import citizen
import officer

app = Flask(__name__)

# Citizen tool schemas (6 tools)
CITIZEN_TOOLS = [
    {
        "name": "get_scheme_info",
        "description": "Returns official Indira Gandhi National Old Age Pension scheme rules, minimum age, 15-day statutory SLA, deadline, and eligible blocks. Always call this to provide up-to-date scheme information to the citizen.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "get_my_status",
        "description": "Retrieves the current application status, tracking number, and next steps for the signed-in citizen. Identity is extracted automatically from the sign-in token.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
    {
        "name": "prepare_application",
        "description": "Validates applicant details and age proof document in dry-run mode. On success returns a preview and a 15-minute confirmation_token. The assistant MUST read the preview and declaration aloud to the citizen before calling submit_application.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "applicant_name": {"type": "string", "description": "Full name as in official records"},
                "dob": {"type": "string", "description": "Date of birth in DD/MM/YYYY format (must be 60 years or older)"},
                "gender": {"type": "string", "description": "Male, Female, or Other"},
                "marital_status": {"type": "string", "description": "Married, Unmarried, or Widowed"},
                "husband_name": {"type": "string", "description": "Husband's name if applicable"},
                "village": {"type": "string", "description": "Village name"},
                "block": {"type": "string", "description": "Block name (must be one of: Sonari, Rajapara, Dhemaji Pathar, Borgaon, Namti, Khelua)"},
                "bank_account": {"type": "string", "description": "Applicant's bank account number (9 to 18 digits)"},
                "ifsc": {"type": "string", "description": "Bank branch IFSC code (11 characters, e.g. SBIN0003077)"},
                "document_filename": {"type": "string", "description": "Filename of age proof (e.g. voter_id.pdf, aadhaar.jpg)"},
                "document_base64": {"type": "string", "description": "Base64 encoded binary content of age proof document (max 5 MB)"}
            },
            "required": ["applicant_name", "dob", "village", "block", "bank_account", "ifsc"]
        }
    },
    {
        "name": "submit_application",
        "description": "Submits the validated application using the confirmation_token returned by prepare_application. Accepts ONLY the confirmation_token. The assistant MUST confirm the citizen explicitly agreed before calling.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "confirmation_token": {"type": "string", "description": "Single-use confirmation token from prepare_application"}
            },
            "required": ["confirmation_token"]
        }
    },
    {
        "name": "withdraw_application",
        "description": "Withdraws the citizen's own PENDING application so they can apply afresh. Call with confirm=false to preview, then confirm=true to execute.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "confirm": {"type": "boolean", "description": "Set to true after getting explicit citizen consent to withdraw"}
            }
        }
    },
    {
        "name": "sign_out",
        "description": "Ends the session and revokes tokens. Essential for shared phones and public kiosks to protect citizen privacy.",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    }
]

# Officer tool schemas (5 tools)
OFFICER_TOOLS = [
    {
        "name": "queue_summary",
        "description": "Summarizes application queue counts by status, oldest pending days, and applications nearing the 15-day statutory deemed-approval deadline.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "block": {"type": "string", "description": "Optional block name to filter counts"}
            }
        }
    },
    {
        "name": "list_applications",
        "description": "Lists applications with pagination and sorting by urgency (default: PENDING, oldest first).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "status": {"type": "string", "description": "Status filter: PENDING, APPROVED, DEEMED_APPROVED, REJECTED, WITHDRAWN", "default": "PENDING"},
                "block": {"type": "string", "description": "Optional block name filter"},
                "order_by": {"type": "string", "description": "oldest_first or newest_first", "default": "oldest_first"},
                "page": {"type": "integer", "description": "Page number (default 1)", "default": 1},
                "limit": {"type": "integer", "description": "Applications per page (default 20)", "default": 20}
            }
        }
    },
    {
        "name": "get_application",
        "description": "Retrieves the complete case dossier for an application, including applicant details, age calculation, document upload status, informational duplicate flags, and chronological audit trail.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {"type": "integer", "description": "Application ID"}
            },
            "required": ["app_id"]
        }
    },
    {
        "name": "approve_application",
        "description": "Approves a PENDING application and records the decision in the audit trail against the officer's name. Idempotent and race-safe against the deemed-approval job.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {"type": "integer", "description": "Application ID to approve"},
                "note": {"type": "string", "description": "Optional officer verification note"}
            },
            "required": ["app_id"]
        }
    },
    {
        "name": "reject_application",
        "description": "Rejects a PENDING application. A specific recorded reason is mandatory under natural justice and scheme rules.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "app_id": {"type": "integer", "description": "Application ID to reject"},
                "reason": {"type": "string", "description": "Mandatory specific reason for rejection"}
            },
            "required": ["app_id", "reason"]
        }
    }
]


def authenticate_request(role, endpoint_path):
    """
    Enforces OAuth 2.1 token validation.
    Returns (authenticated: bool, error_response: Response or None, subject: str or None)
    """
    auth_header = request.headers.get("Authorization", "")
    metadata_url = auth.get_public_base_url() + "/.well-known/oauth-protected-resource" + endpoint_path

    if not auth_header.startswith("Bearer "):
        resp = jsonify({
            "error": "unauthorized",
            "error_description": "Valid Bearer access token required."
        })
        resp.status_code = 401
        resp.headers["WWW-Authenticate"] = 'Bearer resource_metadata="%s"' % metadata_url
        return False, resp, None

    token = auth_header.split(" ", 1)[1].strip()
    canonical_resource = auth.get_public_base_url() + endpoint_path

    valid, result = auth.verify_token(token, expected_resource=canonical_resource, expected_role=role)
    if not valid:
        is_forbidden = "forbidden" in str(result)
        status_code = 403 if is_forbidden else 401
        error_code = "insufficient_scope" if is_forbidden else "invalid_token"
        resp = jsonify({
            "error": error_code,
            "error_description": str(result)
        })
        resp.status_code = status_code
        resp.headers["WWW-Authenticate"] = 'Bearer error="%s", error_description="%s", resource_metadata="%s"' % (error_code, result, metadata_url)
        return False, resp, None

    sub = result.get("sub", "")
    return True, None, sub


# ---------------------------------------------------------------------------
# RFC 9728 Protected Resource Metadata Discovery
# ---------------------------------------------------------------------------

@app.route("/.well-known/oauth-protected-resource", methods=["GET"])
@app.route("/.well-known/oauth-protected-resource/<path:subpath>", methods=["GET"])
def protected_resource_metadata(subpath=""):
    resource_param = request.args.get("resource")
    if resource_param:
        from urllib.parse import urlparse
        path = urlparse(resource_param).path
    else:
        path = "/" + subpath.strip("/") if subpath.strip("/") else ""
    doc = auth.get_protected_resource_metadata(path)
    return jsonify(doc)


# ---------------------------------------------------------------------------
# Dispatch JSON-RPC tool calls
# ---------------------------------------------------------------------------

def handle_citizen_tool_call(tool_name, arguments, subject):
    mobile = subject.split(":", 1)[1] if ":" in subject else subject
    if tool_name == "get_scheme_info":
        return citizen.get_scheme_info()
    elif tool_name == "get_my_status":
        return citizen.get_my_status(mobile)
    elif tool_name == "prepare_application":
        return citizen.prepare_application(
            mobile=mobile,
            applicant_name=arguments.get("applicant_name", ""),
            dob=arguments.get("dob", ""),
            gender=arguments.get("gender", ""),
            marital_status=arguments.get("marital_status", ""),
            husband_name=arguments.get("husband_name", ""),
            village=arguments.get("village", ""),
            block=arguments.get("block", ""),
            bank_account=arguments.get("bank_account", ""),
            ifsc=arguments.get("ifsc", ""),
            document_filename=arguments.get("document_filename"),
            document_base64=arguments.get("document_base64")
        )
    elif tool_name == "submit_application":
        return citizen.submit_application(
            mobile=mobile,
            confirmation_token=arguments.get("confirmation_token", "")
        )
    elif tool_name == "withdraw_application":
        return citizen.withdraw_application(
            mobile=mobile,
            confirm=arguments.get("confirm", False)
        )
    elif tool_name == "sign_out":
        return citizen.sign_out(mobile)
    else:
        return {"error": "Unknown tool: %s" % tool_name}


def handle_officer_tool_call(tool_name, arguments, subject):
    username = subject.split(":", 1)[1] if ":" in subject else subject
    if tool_name == "queue_summary":
        return officer.queue_summary(block=arguments.get("block"))
    elif tool_name == "list_applications":
        return officer.list_applications(
            status=arguments.get("status", "PENDING"),
            block=arguments.get("block"),
            order_by=arguments.get("order_by", "oldest_first"),
            page=int(arguments.get("page", 1)),
            limit=int(arguments.get("limit", 20))
        )
    elif tool_name == "get_application":
        return officer.get_application(app_id=int(arguments.get("app_id", 0)))
    elif tool_name == "approve_application":
        return officer.approve_application(
            app_id=int(arguments.get("app_id", 0)),
            officer_username=username,
            note=arguments.get("note", "")
        )
    elif tool_name == "reject_application":
        return officer.reject_application(
            app_id=int(arguments.get("app_id", 0)),
            officer_username=username,
            reason=arguments.get("reason", "")
        )
    else:
        return {"error": "Unknown tool: %s" % tool_name}


SUPPORTED_PROTOCOL_VERSIONS = (
    "2024-11-05",
    "2025-03-26",
    "2025-06-18",
    "2025-11-25",
    "2026-07-28"
)


def process_jsonrpc(req_data, tools_list, tool_handler, subject):
    req_id = req_data.get("id")
    method = req_data.get("method")
    params = req_data.get("params", {}) or {}

    if method == "initialize":
        client_version = params.get("protocolVersion")
        negotiated = client_version if client_version in SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": negotiated,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "sewasetu-mcp", "version": "1.0.0"}
            }
        }
    elif method == "notifications/initialized":
        return None
    elif req_id is None:
        # Any JSON-RPC notification
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"tools": tools_list}
        }
    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments", {}) or {}
        try:
            res = tool_handler(tool_name, args, subject)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(res, ensure_ascii=False, indent=2)}]
                }
            }
        except Exception as e:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "isError": True,
                    "content": [{"type": "text", "text": "Error executing tool: %s" % e}]
                }
            }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {}
        }
    else:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": "Method not found: %s" % method}
        }


# ---------------------------------------------------------------------------
# Endpoints: /mcp/citizen and /mcp/officer (Streamable HTTP, stateless)
# ---------------------------------------------------------------------------

def _handle_mcp_request(role, endpoint_path, tools_list, tool_handler):
    if request.method == "GET":
        resp = jsonify({
            "error": "method_not_allowed",
            "message": "Streamable HTTP MCP endpoints accept POST only."
        })
        resp.status_code = 405
        resp.headers["Allow"] = "POST"
        return resp

    ok, err_resp, subject = authenticate_request(role, endpoint_path)
    if not ok:
        return err_resp

    req_data = request.get_json(force=True, silent=True) or {}
    resp_data = process_jsonrpc(req_data, tools_list, tool_handler, subject)
    if resp_data is None:
        # Notifications get HTTP 202 with no body
        resp = Response("", status=202, mimetype="application/json")
    else:
        resp = jsonify(resp_data)

    session_id = request.headers.get("Mcp-Session-Id") or request.headers.get("mcp-session-id")
    if session_id:
        resp.headers["Mcp-Session-Id"] = session_id

    return resp


@app.route("/mcp/citizen", methods=["GET", "POST"])
def mcp_citizen():
    return _handle_mcp_request("citizen", "/mcp/citizen", CITIZEN_TOOLS, handle_citizen_tool_call)


@app.route("/mcp/officer", methods=["GET", "POST"])
def mcp_officer():
    return _handle_mcp_request("officer", "/mcp/officer", OFFICER_TOOLS, handle_officer_tool_call)


if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", 8010))
    app.run(host="0.0.0.0", port=port)
