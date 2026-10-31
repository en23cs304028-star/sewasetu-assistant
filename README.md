# Sewa Setu — Old Age Pension Portal & MCP Server

**Department of Social Welfare, Government of Purvanchal**  
*Authoritative System of Record & Model Context Protocol (MCP) Interface*

---

## 1. Executive Summary & Design Philosophy

Sewa Setu is an enterprise-grade public service delivery portal for the Indira Gandhi National Old Age Pension Scheme, engineered to serve both human citizens and autonomous AI agents through separate, hardened interfaces.

```
                                  Internet
                                     |
                                     v (Port 80/443: TLS, HSTS, CSP)
                       +---------------------------+
                       |    Caddy 2 Reverse Proxy  |
                       +-------------+-------------+
                                     |
         +---------------------------+---------------------------+
         | (Port 8000: Web & OAuth)                              | (Port 8010: Streamable HTTP MCP)
         v                                                       v
+------------------+                                   +-------------------+
|  Flask Portal    |                                   |  MCP Server       |
|  - Web UI        |                                   |  - /mcp/citizen   |
|  - OAuth 2.1 AS  |                                   |  - /mcp/officer   |
|  - /eval-dashboard                                   |  - RFC 9728 Meta  |
+--------+---------+                                   +---------+---------+
         |                                                       |
         +---------------------------+---------------------------+
                                     |
                                     v
                        +--------------------------+
                        |     app/services.py      |
                        | (Pure-Python Domain Core)|
                        +------------+-------------+
                                     |
                     +---------------+---------------+
                     v                               v
          +--------------------+           +--------------------+
          |   PostgreSQL 15    |           |    SMS Gateway     |
          |  (Advisory Locked  |           |   (Mock Telecom)   |
          |   State & Drafts)  |           +--------------------+
          +--------------------+
```

### Core Engineering Principles
1. **Single Source of Truth (`app/services.py`):** Zero validation or business logic lives in route handlers or MCP tool wrappers. All age math, database queries, state machines, and audit logging live in a standalone, pure-Python domain core without Flask dependencies. Web forms and LLM tools invoke identical functions, guaranteeing zero behavioral drift.
2. **Physical Endpoint Separation:** Rather than dynamic tool filtering on a single endpoint, citizen tools (`/mcp/citizen`) and officer tools (`/mcp/officer`) are deployed to separate URL routes with dedicated OAuth scopes. An applicant's agent has zero visibility into officer tools, eliminating prompt-injection attack vectors.
3. **Stateless Streamable HTTP over Stateful SSE:** While the Model Context Protocol supports Server-Sent Events (SSE), persistent streaming connections silently drop across high-latency mobile networks and cloud load balancers. Sewa Setu standardizes on stateless HTTP POST with JSON-RPC 2.0 and database-persisted confirmation tokens, ensuring multi-worker Gunicorn resilience and zero sticky-session dependencies.
4. **Defensive Governance & Friction:** High-impact operations (citizen submissions, officer approvals, rejections) mandate a two-step preview/confirmation token pattern. Rejections strictly mandate recorded justifications under natural justice rules.

---

## 2. End-to-End Workflow Architecture

### 2.1 Citizen Lifecycle: Two-Phase Commit via Cryptographic Tokens
In naive agent implementations, tools accept boolean flags (e.g. `confirmed_by_citizen=True`) or re-accept raw input fields upon final submission. In real-world multi-turn LLM conversations, models hallucinate, alter critical fields (like bank accounts), or fall prey to prompt injection (Persona 08).

Sewa Setu enforces a strict **Two-Phase Commit**:

```
[Citizen / Agent]                    [Citizen MCP Server]               [PostgreSQL DB]
       |                                       |                               |
       | 1. prepare_application(data...)       |                               |
       |-------------------------------------->|                               |
       |                                       | Run statutory validation      |
       |                                       | Hash payload: SHA256(data)    |
       |                                       | Store draft with 15m TTL      |
       |                                       |------------------------------>| INSERT INTO confirmation_tokens
       | 2. Return confirmation_token          |                               |
       |<--------------------------------------|                               |
       |    (Format: <draft_id>.<sha256>)      |                               |
       |                                       |                               |
       | [Citizen reads & confirms aloud]      |                               |
       |                                       |                               |
       | 3. submit_application(token)          |                               |
       |-------------------------------------->|                               |
       |                                       | Fetch draft & verify hash     |
       |                                       |<------------------------------| SELECT payload, hash FROM confirmation_tokens
       |                                       | Commit application & user     |
       |                                       |------------------------------>| INSERT INTO applications
       |                                       | Delete single-use token       |
       |                                       |------------------------------>| DELETE FROM confirmation_tokens
       | 4. Return Application Number          |                               |
       |<--------------------------------------|                               |
```

- **Statutory Eligibility Rules:** Minimum 60 years of age on submission date; valid Assam mobile number; proof-of-age document (PDF/JPG up to 5 MB); active scheme window open; and zero existing active applications (`PENDING`, `APPROVED`, or `DEEMED_APPROVED`).
- **Leap-Year-Proof Age Math:** Division by `365.25` or floating-point approximations misclassify applicants born on leap years. Age is calculated using strict calendar tuple comparison:
  ```python
  age = (today.year - dob.year) - ((today.month, today.day) < (dob.month, dob.day))
  ```
- **Shared Jan Dhan Accounts:** Rather than rejecting applicants sharing family accounts (common among rural elderly), the validator accepts the submission and sets an informational flag for reviewing officers (`[FLAG] Duplicate bank account: X other application(s) share this account`).
- **Withdrawal & Re-Application:** Citizens can withdraw pending applications (`withdraw_application(confirm=True)`). Once marked `WITHDRAWN`, the unique constraint relaxes, allowing the citizen to re-apply immediately with corrected details.

### 2.2 Officer Workflow & SLA Queue Governance
Departmental officers triage applications under the statutory 15-day service-level agreement (Assam Right to Public Services Act):

1. **Queue Inspection:** `queue_summary` reports queue counts, oldest pending days, and flags urgent applications nearing the 15-day cutoff (`nearing_deemed_approval >= 13 days`).
2. **Case Dossier:** `get_application` surfaces the applicant's complete dossier, calculated calendar age, uploaded document path, chronological audit log, and duplicate account warnings.
3. **Two-Step Officer Confirmation:**
   - Calling `approve_application(app_id, note)` or `reject_application(app_id, reason)` without a token executes a dry-run and returns a short-lived (5 min) `confirmation_token`.
   - The second call with `confirmation_token` executes the transition.
4. **Mandatory Rejection Justification:** Rejections with empty or whitespace-only reasons are rejected by `services.decide_application` under statutory natural justice requirements.
5. **Atomic Deemed Approval Cron (`scripts/deemed_approval.py`):** Applications pending past 15 days are automatically approved nightly. The query uses an atomic update to eliminate race conditions:
   ```sql
   UPDATE applications 
   SET status = 'DEEMED_APPROVED', decided_at = %s, decided_by = 'system:rtps-cron' 
   WHERE status = 'PENDING' AND submitted_at < %s 
   RETURNING id, application_no, mobile;
   ```

---

## 3. How the MCP Server Works Under the Hood

### 3.1 Transport & Wire Protocol
The server implements the Model Context Protocol (`protocolVersion: "2024-11-05"` and `2026-07-28"` compatible) directly over Flask HTTP POST:
- **Wire Format:** Standard JSON-RPC 2.0 requests (`{"jsonrpc": "2.0", "id": 1, "method": "...", "params": {...}}`).
- **Initialization Handshake:** `initialize` negotiates capabilities, protocol version, and server identity (`sewasetu-mcp v1.0.0`).
- **Tool Listing:** `tools/list` returns typed JSON schemas describing input parameters, required fields, and tool docstrings.
- **Tool Invocation:** `tools/call` executes the handler inside a try/except envelope, returning `{"content": [{"type": "text", "text": "..."}]}`.

### 3.2 RFC 9728 Protected Resource Discovery
When an unauthenticated client requests `/mcp/citizen` or `/mcp/officer`, the server responds with:
```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer resource_metadata="https://sewasetu.example.in/.well-known/oauth-protected-resource"
```
The metadata endpoint publishes supported scopes, authorization server URLs, and canonical audience URIs (`<PUBLIC_BASE_URL>/mcp/citizen` and `<PUBLIC_BASE_URL>/mcp/officer`).

### 3.3 Token Validation Pipeline
Every MCP call undergoes strict cryptographic verification in `mcp/auth.py`:
1. **Algorithm Lockdown:** Only `RS256` is accepted. Symmetric key confusion (`HS256`) and `alg: none` are strictly rejected.
2. **Key ID (`kid`) Lookup:** Public keys are fetched from `oauth_keys` in PostgreSQL. Requests with unknown or missing `kid` fail immediately with HTTP 401 (no fallback to default keys).
3. **Mandatory Claims:** Asserts presence and validity of `iss`, `aud`, `exp`, `nbf`, `sub`, `role`, and `jti`.
4. **Audience & Role Binding:** Asserts `claims["aud"]` matches the canonical endpoint URL and `claims["role"]` matches the requested endpoint scope (`citizen` or `officer`). Cross-role invocations return HTTP 403 Forbidden.
5. **Database-Backed Revocation Check:** Queries `oauth_revocations` table in PostgreSQL for blacklisted `jti` identifiers. Fails closed (HTTP 503/401) if PostgreSQL is unreachable.

### 3.4 Concurrency & Multi-Worker Gunicorn Safety
- **Advisory Locks on Startup:** When multiple Gunicorn workers boot simultaneously, parallel `CREATE TABLE IF NOT EXISTS` statements cause PostgreSQL catalog lock errors. Startup logic acquires an advisory lock:
  ```python
  cur.execute("SELECT pg_advisory_lock(42424242);")
  ```
- **Durable Drafts Table:** Confirmation tokens are stored in PostgreSQL with indexed TTLs, avoiding memory-partitioning bugs where worker A creates a token that worker B cannot find.

---

## 4. Security Hardening Matrix

| Threat Category | Vulnerability Mitigated | Technical Implementation |
| :--- | :--- | :--- |
| **Authentication** | Access token replay across workers | Mandatory `jti` tracking and revocation blacklist in PostgreSQL (`oauth_revocations`). |
| **OAuth 2.1** | Refresh token theft & replay | Refresh token rotation with family reuse detection (revokes entire token chain). |
| **DCR Abuse** | Unauthenticated dynamic client flood | Global 500-client cap and per-IP rate limiting (10 registrations/hour). |
| **SSRF Mitigation** | Malicious client metadata URLs | DNS pre-resolution blocking loopback, RFC 1918 private IPs, link-local (169.254.169.254), and Docker service names before fetching; HTTPS only; 64 KB cap; 3s timeout. |
| **Proxy Spoofing** | IP-spoofing rate limit bypasses | Configurable `TRUSTED_PROXY_CIDRS` inspects right-most `X-Forwarded-For` only when connecting peer is trusted. |
| **Brute Force** | Officer account denial-of-service | Lockout keyed on `(IP, username)` (5 failures -> 15 min lockout). Real officers cannot be locked out by third-party attackers. |
| **PII Protection** | Account number exposure | Bank accounts masked in responses and logs (`XXXX1234`). |
| **Timing Attacks** | Username enumeration via timing | Constant-time password hash verification (`hmac.compare_digest`). |
| **Least Privilege** | Container breakout | All containers drop all capabilities (`cap_drop: [ALL]`); Caddy granted strictly `NET_BIND_SERVICE`; non-root users (`appuser` UID 10001). |

---

## 5. Operations & Production Playbook

### Running Locally
```bash
ADMIN_PASSWORD=pick-something docker compose up --build
```
- **Web Portal:** http://localhost:8000
- **Citizen Status Portal:** http://localhost:8000/status
- **Departmental Admin:** http://localhost:8000/admin (`admin` / `ADMIN_PASSWORD`)
- **Evaluation Dashboard:** http://localhost:8000/eval-dashboard
- **Simulated SMS Gateway:** http://localhost:8000/__gateway/

### Deploying to Production (Caddy Automatic HTTPS)
```bash
PUBLIC_BASE_URL=https://sewasetu.example.in \
DOMAIN=sewasetu.example.in \
ADMIN_PASSWORD=strong-admin-password \
POSTGRES_PASSWORD=strong-db-password \
docker compose --profile caddy up --build -d
```

### Administrative CLI Commands
```bash
# Clear IP or username rate limit lockouts
docker compose exec app python scripts/clear_lockouts.py --ip 1.2.3.4
docker compose exec app python scripts/clear_lockouts.py --username admin

# Run data retention cleanup (expired tokens, old audit logs)
docker compose exec app python scripts/retention_cleanup.py

# Verify deployment health & security headers
./scripts/verify_deploy.sh
```

---

## 6. Verification Suites

### Automated Unit, Protocol & Penetration Suite (168 Tests)
```bash
python3 -m unittest discover tests
```
*Executes all 168 script-generated tests spanning domain logic, wire HTTP JSON-RPC POST, multi-process race conditions, and red-team penetration suites (Threats A through H). Pass rate: 100% OK.*

### Persona Evaluation Harness (14 Personas)
```bash
python3 evals/runner.py
```
*Executes 14 scripted persona scenarios against a mocked database (Tier 1 deterministic rule-engine checks), verifying schema rules, boundary ages, prompt injection refusals, and kiosk session revocations. Pass rate: 14/14 (100.0%). (Tier 2 model-driven evaluations require headless LLM credentials and remain pending).*
