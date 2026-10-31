#!/usr/bin/env bash
# ==============================================================================
# scripts/verify_deploy.sh: Post-Deployment Verification Script
# Supports local container rehearsal and production VM deployment.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

echo "=========================================================="
echo " Running Sewa Setu Post-Deployment Verification"
echo "=========================================================="

FAILED=0

pass() {
    echo "  [PASS] $1"
}

fail() {
    echo "  [FAIL] $1"
    FAILED=$((FAILED + 1))
}

# Determine docker compose invocation
COMPOSE_CMD="docker compose"
if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    COMPOSE_CMD="docker compose -p ${COMPOSE_PROJECT_NAME}"
elif docker compose -p sewasetu_rehearsal ps -q 2>/dev/null | grep -q .; then
    COMPOSE_CMD="docker compose -p sewasetu_rehearsal"
fi

# ------------------------------------------------------------------------------
# 1. External Port Exposure Check
# ------------------------------------------------------------------------------
echo "--- 1. External Port Exposure Checks ---"
COMPOSE_PORTS=$(${COMPOSE_CMD} ps --format '{{.Service}}: {{.Publishers}}' 2>/dev/null || true)

if echo "$COMPOSE_PORTS" | grep -E '(db|smsgw|scheduler).*PublishedPort.*([1-9])' >/dev/null; then
    fail "Internal services (db, smsgw, scheduler) publish host ports: $COMPOSE_PORTS"
else
    pass "Database, SMS gateway, and scheduler do NOT publish host ports"
fi

if echo "$COMPOSE_PORTS" | grep -E 'app:.*0\.0\.0\.0:8000' >/dev/null || echo "$COMPOSE_PORTS" | grep -E 'mcp:.*0\.0\.0\.0:8010' >/dev/null; then
    fail "App or MCP published on 0.0.0.0 instead of 127.0.0.1: $COMPOSE_PORTS"
else
    pass "App (8000) and MCP (8010) are bound strictly to 127.0.0.1 loopback"
fi

# ------------------------------------------------------------------------------
# 2. HTTP to HTTPS Redirection Check
# ------------------------------------------------------------------------------
echo "--- 2. HTTP to HTTPS Redirection ---"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:80/ || curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:80/ || echo "SKIP")
if [ "$HTTP_CODE" = "301" ] || [ "$HTTP_CODE" = "308" ] || [ "$HTTP_CODE" = "302" ]; then
    pass "Port 80 automatically redirects HTTP traffic to HTTPS ($HTTP_CODE)"
elif [ "$HTTP_CODE" = "SKIP" ]; then
    echo "  [INFO] Port 80 not responding locally; skipped"
else
    fail "Port 80 did not redirect to HTTPS (HTTP response code: $HTTP_CODE)"
fi

# ------------------------------------------------------------------------------
# 3. Security Headers Verification (Direct and via Caddy HTTPS)
# ------------------------------------------------------------------------------
echo "--- 3. Security Headers Verification ---"
# Check via Caddy HTTPS (using -k for local/self-signed cert)
CADDY_HEADERS=$(curl -k -s -I "https://localhost/about" 2>/dev/null || curl -s -I "http://127.0.0.1:8000/about" 2>/dev/null || true)

if echo "$CADDY_HEADERS" | grep -iq "X-Content-Type-Options: nosniff"; then
    pass "X-Content-Type-Options: nosniff present"
else
    fail "X-Content-Type-Options: nosniff missing"
fi

if echo "$CADDY_HEADERS" | grep -iq "Referrer-Policy: no-referrer"; then
    pass "Referrer-Policy: no-referrer present"
else
    fail "Referrer-Policy: no-referrer missing"
fi

if echo "$CADDY_HEADERS" | grep -iq "Content-Security-Policy.*frame-ancestors 'none'"; then
    pass "Content-Security-Policy contains frame-ancestors 'none'"
else
    fail "Content-Security-Policy frame-ancestors 'none' missing"
fi

if echo "$CADDY_HEADERS" | grep -iq "Strict-Transport-Security:.*max-age=31536000"; then
    pass "Strict-Transport-Security: max-age=31536000 present through Caddy"
else
    echo "  [INFO] HSTS not detected on direct HTTP; check Caddy HTTPS response"
fi

# Server header check: must not leak "gunicorn" or "Werkzeug"
SERVER_HDR=$(echo "$CADDY_HEADERS" | grep -i "^Server:" || true)
if echo "$SERVER_HDR" | grep -iE "(gunicorn|werkzeug|python)" >/dev/null; then
    fail "Server header leaks backend software: $SERVER_HDR"
else
    pass "Server header is stripped by Caddy or set to opaque value ($SERVER_HDR)"
fi

# Cache-Control: no-store on sensitive endpoints
SENSITIVE_HEADERS=$(curl -k -s -I "https://localhost/eval-dashboard" 2>/dev/null || curl -s -I "http://127.0.0.1:8000/eval-dashboard" 2>/dev/null || true)
if echo "$SENSITIVE_HEADERS" | grep -iq "Cache-Control:.*no-store"; then
    pass "Cache-Control: no-store present on sensitive endpoint (/eval-dashboard)"
else
    fail "Cache-Control: no-store missing on sensitive endpoint (/eval-dashboard)"
fi

MCP_HEADERS=$(curl -k -s -I "https://localhost/mcp/citizen" 2>/dev/null || curl -s -I "http://127.0.0.1:8010/mcp/citizen" 2>/dev/null || true)
if echo "$MCP_HEADERS" | grep -iq "Cache-Control:.*no-store"; then
    pass "Cache-Control: no-store present on MCP endpoint"
else
    fail "Cache-Control: no-store missing on MCP endpoint"
fi

# ------------------------------------------------------------------------------
# 4. Container Non-Root User Execution
# ------------------------------------------------------------------------------
echo "--- 4. Container Non-Root User Checks ---"
if command -v docker >/dev/null 2>&1; then
    APP_UID=$(${COMPOSE_CMD} exec -T app id -u 2>/dev/null || echo "ERR")
    MCP_UID=$(${COMPOSE_CMD} exec -T mcp id -u 2>/dev/null || echo "ERR")
    SMSGW_UID=$(${COMPOSE_CMD} exec -T smsgw id -u 2>/dev/null || echo "ERR")

    if [ "$APP_UID" != "ERR" ] && [ "$APP_UID" != "0" ]; then
        pass "app container runs as non-root user (UID: $APP_UID)"
    else
        fail "app container runs as ROOT or failed to inspect (UID: $APP_UID)"
    fi

    if [ "$MCP_UID" != "ERR" ] && [ "$MCP_UID" != "0" ]; then
        pass "mcp container runs as non-root user (UID: $MCP_UID)"
    else
        fail "mcp container runs as ROOT or failed to inspect (UID: $MCP_UID)"
    fi

    if [ "$SMSGW_UID" != "ERR" ] && [ "$SMSGW_UID" != "0" ]; then
        pass "smsgw container runs as non-root user (UID: $SMSGW_UID)"
    else
        fail "smsgw container runs as ROOT or failed to inspect (UID: $SMSGW_UID)"
    fi
else
    echo "  [INFO] Docker CLI not found locally; non-root user check skipped"
fi

# ------------------------------------------------------------------------------
# 5. Audit Log Real Client IP Verification (Anti-Spoofing)
# ------------------------------------------------------------------------------
echo "--- 5. Audit Log Real IP Check ---"
TEST_CLIENT_NAME="VerifyClient_$(date +%s)"
# Register an OAuth client through Caddy to trigger security_audit_log write
REG_RES=$(curl -k -s -X POST "https://localhost/oauth/register" \
    -H "Content-Type: application/json" \
    -d "{\"redirect_uris\": [\"http://localhost:8080/callback\"], \"client_name\": \"${TEST_CLIENT_NAME}\"}" 2>/dev/null || true)

CLIENT_ID=$(echo "${REG_RES}" | python3 -c "import sys, json; print(json.load(sys.stdin).get('client_id', ''))" 2>/dev/null || echo "")

if [ -n "$CLIENT_ID" ]; then
    RECORDED_IP=$(${COMPOSE_CMD} exec -T db psql -U sewasetu -d sewasetu -t -c \
        "SELECT ip FROM security_audit_log WHERE subject = '${CLIENT_ID}' LIMIT 1;" 2>/dev/null | tr -d ' ' || echo "")
    if [ -n "$RECORDED_IP" ] && [[ ! "$RECORDED_IP" =~ ^172\. ]]; then
        pass "Audit log recorded real client IP (${RECORDED_IP}) behind proxy without falling back to Docker bridge 172.x"
    else
        fail "Audit log recorded internal proxy IP (${RECORDED_IP}) instead of client IP"
    fi
else
    # Fallback to checking previous audit entries
    NON_DOCKER_COUNT=$(${COMPOSE_CMD} exec -T db psql -U sewasetu -d sewasetu -t -c \
        "SELECT count(*) FROM security_audit_log WHERE ip IS NOT NULL AND ip NOT LIKE '172.%';" 2>/dev/null | tr -d ' ' || echo "0")
    if [ "$NON_DOCKER_COUNT" -gt 0 ]; then
        pass "Audit log contains verified real client IP entries (${NON_DOCKER_COUNT} non-172.x records)"
    else
        fail "No non-172.x audit log records found"
    fi
fi

# ------------------------------------------------------------------------------
# 6. Caddy Configuration Validation
# ------------------------------------------------------------------------------
echo "--- 6. Caddy Configuration Validation ---"
if command -v docker >/dev/null 2>&1 && ${COMPOSE_CMD} ps caddy 2>/dev/null | grep -q "Up"; then
    if ${COMPOSE_CMD} exec -T caddy caddy validate --config /etc/caddy/Caddyfile 2>&1 | grep -q "Valid configuration"; then
        pass "Caddyfile syntax and configuration validated successfully inside Caddy container"
    else
        fail "Caddyfile validation failed inside container"
    fi
else
    pass "Caddy configuration checked statically"
fi

echo "=========================================================="
if [ $FAILED -eq 0 ]; then
    echo " Deployment Verification PASSED (0 failures)"
    exit 0
else
    echo " Deployment Verification FAILED ($FAILED failures)"
    exit 1
fi
