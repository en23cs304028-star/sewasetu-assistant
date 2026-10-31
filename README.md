# Sewa Setu — Old Age Pension Portal & Model Context Protocol (MCP) Server

Department of Social Welfare, Government of Purvanchal. Maintained in-house.

---

## 1. Quick Start (Local Development)

```bash
ADMIN_PASSWORD=pick-something docker compose up --build
```

- **Web Portal:** http://localhost:8000
- **Citizen Status Portal:** http://localhost:8000/status (mobile number + date of birth password as DDMMYYYY)
- **Departmental Officer Login:** http://localhost:8000/admin (username `admin`, password from `ADMIN_PASSWORD`)
- **Evaluation Dashboard:** http://localhost:8000/eval-dashboard (view persona evaluation runs and defect resolution logs)
- **SMS Gateway Console:** http://localhost:8000/__gateway/ (simulated carrier inbox, readable at `/__gateway/api/messages?to=<mobile>`)
- **Database:** PostgreSQL 15, seeded from `seed/seed.sql` on first boot (~100,000 production records)

---

## 2. Model Context Protocol (MCP) Endpoints

Sewa Setu implements two streamable HTTP MCP servers (version `2024-11-05` / `2026-07-28` compatible) protected by OAuth 2.1 RS256 Bearer tokens and RFC 9728 metadata discovery:

- **Citizen Endpoint (`/mcp/citizen`):** 6 tools for applicants:
  1. `get_scheme_info`: Statutory scheme rules, eligibility age (60+), 15-day SLA, and required documents.
  2. `get_my_status`: Case tracking, status explanation in Hindi & English, and remaining SLA days.
  3. `prepare_application`: Full validation dry-run, generating a single-use 15-minute `confirmation_token` bound to a SHA-256 hash of the draft in PostgreSQL.
  4. `submit_application`: Atomically commits the draft using the `confirmation_token`.
  5. `withdraw_application`: Statutory withdrawal of a pending application (`confirm=True`).
  6. `sign_out`: Immediate session termination and database token revocation for public kiosk terminals.

- **Officer Endpoint (`/mcp/officer`):** 5 tools for departmental triage:
  1. `queue_summary`: Queue metrics broken down by status, oldest pending days, and SLA urgency cutoff (>= 13 days).
  2. `list_applications`: Paginated queue listing with urgency sorting.
  3. `get_application`: Complete case dossier with chronological audit log and informational fraud flags (e.g. shared Jan Dhan accounts).
  4. `approve_application`: Two-step confirmation flow requiring dry-run token preview before final approval.
  5. `reject_application`: Two-step confirmation flow requiring mandatory non-empty recorded justification under natural justice rules.

- **RFC 9728 Discovery:** `GET /.well-known/oauth-protected-resource` (and subpaths `/mcp/citizen` and `/mcp/officer`).

---

## 3. Production Deployment with Caddy (Automatic HTTPS)

The production stack uses Caddy 2 for automated Let's Encrypt TLS termination, HTTP/2 support, reverse proxying, and HTTP security headers (HSTS, CSP, X-Content-Type-Options: nosniff, Referrer-Policy: no-referrer).

```bash
PUBLIC_BASE_URL=https://sewasetu.example.in \
DOMAIN=sewasetu.example.in \
ADMIN_PASSWORD=strong-admin-password \
POSTGRES_PASSWORD=strong-db-password \
docker compose --profile caddy up --build -d
```

### Production Security Architecture
- **Non-Root Containers:** All services run as unprivileged users (`appuser` UID 10001, Caddy UID 1000, Postgres UID 999).
- **Dropped Capabilities:** `cap_drop: [ALL]` across all services; Caddy granted strictly `NET_BIND_SERVICE` for low ports (80/443).
- **Strict Network Isolation:** Internal database, app, and MCP services communicate over Docker bridge network; only ports 80 and 443 are exposed publicly.
- **Client IP Behind Proxy:** Trusted proxy CIDR checking (`TRUSTED_PROXY_CIDRS`) parses `X-Forwarded-For` right-most entries, preventing IP-spoofing bypasses.
- **Durable Drafts & Concurrency Safety:** Draft applications stored in PostgreSQL `confirmation_tokens` with PostgreSQL advisory locks (`pg_advisory_lock(42424242)`) to eliminate multi-worker startup race conditions.

---

## 4. Running Tests & Evaluations

### Automated Test Suite (168 Tests)
The comprehensive test suite verifies core services, MCP HTTP transport, concurrency safety, and full red-team penetration suites (Threats A through H):

```bash
python3 -m unittest discover tests
```

### Persona Evaluation Harness (14 Scenarios)
The evaluation suite asserts exact statutory outcomes, edge cases (e.g., exact 60-year boundary birthday, shared Jan Dhan bank accounts, prompt injection refusal, and kiosk sign-outs):

```bash
python3 evals/runner.py
```
View the rendered dashboard at `/eval-dashboard`.

---

## 5. Operations & Maintenance

- **Clear Login Lockouts:**
  ```bash
  docker compose exec app python scripts/clear_lockouts.py --ip <ip_address>
  # or clear specific user:
  docker compose exec app python scripts/clear_lockouts.py --username admin
  ```

- **Run Data Retention Cleanup (OTPs, Expired Tokens, Old Audit Logs):**
  ```bash
  docker compose exec app python scripts/retention_cleanup.py
  ```

- **Initialize / Verify Schema:**
  ```bash
  docker compose exec app python scripts/init_db.py
  ```

- **Verify Deployment Health:**
  ```bash
  ./scripts/verify_deploy.sh
  ```

---

## 6. Directory Layout

```text
app/                  Flask portal application, OAuth 2.1 AS, services.py domain logic, and templates
  config/app.ini      Portal scheme configuration (60 yr min age, 15 day SLA, eligible blocks)
  scripts/            Operational scripts (deemed_approval, clear_lockouts, retention_cleanup, init_db)
  services.py         Authoritative pure-Python domain module (zero Flask dependencies)
mcp/                  Standalone streamable HTTP MCP server
  citizen.py          Citizen tool implementations (6 tools)
  officer.py          Officer tool implementations (5 tools)
  auth.py             OAuth 2.1 RS256 token verification, RFC 9728 discovery, session revocation
  server.py           Streamable HTTP JSON-RPC 2.0 dispatcher
seed/seed.sql         100,000-row production snapshot for local testing
smsgw/                Simulated SMS gateway for OTP delivery and notifications
evals/                14-persona evaluation specifications, results, and test harnesses
tests/                168 automated tests (unit, wire-level HTTP, concurrency, and security attack suite)
  security/           Red-team penetration suites covering Threats A through H and SSRF mitigations
Caddyfile             Production reverse proxy, TLS termination, and security headers
docker-compose.yml    Multi-service production container orchestration
```
