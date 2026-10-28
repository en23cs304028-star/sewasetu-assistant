# 3-Minute Video Walkthrough Script (Loom)

**Total Duration:** 3:00 (180 seconds)  
**Presenter:** Engineering Lead / AI Pair Programmer  
**System:** Sewa Setu Assistant (Citizen & Officer MCP Servers)  

---

### [00:00 - 00:30] Introduction & Unified Architecture (30s)
- **On Screen:** Split screen showing the Sewa Setu Portal homepage on the left and the RFC 9728 discovery endpoint (`/.well-known/oauth-protected-resource`) on the right.
- **Spoken Audio:**
  > "Namaste. This is the Sewa Setu Assistant—an AI-enabled interface for Assam's Old Age Pension Scheme.
  > Instead of bolting on an isolated chatbot with duplicated business logic, we engineered two streamable Model Context Protocol servers: Citizen MCP with six tools and Officer MCP with five tools.
  > Both channels share a single authoritative Python domain module in `app/services.py`, with zero Flask dependencies. Whether an application comes through the web portal or through an LLM agent, it runs through the exact same validation and state pipeline."

---

### [00:30 - 01:00] Citizen Journey & Server-Side Confirmation Tokens (30s)
- **On Screen:** Terminal running `python3 -m unittest tests/test_http_mcp.py` showing wire-level JSON-RPC calls over real HTTP: `initialize`, `tools/list`, and `tools/call`.
- **Spoken Audio:**
  > "Here is our wire-level JSON-RPC interaction over HTTP.
  > Rather than relying on naive boolean flags like `confirmed_by_citizen=True`, which are vulnerable to hallucination and prompt injection, we implemented a server-side confirmation token pattern.
  > When `prepare_application` runs, it dry-runs full validation and returns a 15-minute, single-use `confirmation_token` bound to a hash of that exact draft data.
  > `submit_application` accepts only that token. The assistant physically cannot mutate data between citizen consent and final creation."

---

### [01:00 - 01:30] Edge Cases & Seed Data Findings (30s)
- **On Screen:** Code and test inspection of Persona 07 (Boundary Age 60) and Persona 05 (Shared Jan Dhan Bank Account).
- **Spoken Audio:**
  > "Real governance data contains critical traps.
  > First: boundary age. Renu Ali turned 60 this year. Using floating-point day math or dividing by 365.25 fails on leap years; our calendar logic checks exact day and month boundaries.
  > Second: duplicate bank accounts. In rural communities, elderly women frequently share a son's Jan Dhan account. Rather than hard-rejecting these citizens at the door, our validator allows submission and flags the record for the reviewing officer."

---

### [01:30 - 02:00] Officer Workflow & Atomic Deemed Approval (30s)
- **On Screen:** Officer queue triage showing `approve_application`, rejection requiring mandatory non-empty reason, and the atomic deemed approval SQL query.
- **Spoken Audio:**
  > "For block officers, the Officer MCP server enables SLA-aware queue triage.
  > Rejections strictly mandate a recorded justification under natural justice principles.
  > Furthermore, we resolved a critical race condition in the statutory 15-day deemed approval cron: using `UPDATE ... RETURNING id, application_no, mobile`, status transitions and audit log insertions commit atomically in a single transaction, eliminating audit trail drift."

---

### [02:00 - 02:30] Two-Tier Evaluation Dashboard (30s)
- **On Screen:** Web browser displaying the live `/eval-dashboard` route on the portal, showing Tier 1 Deterministic Protocol Checks and Tier 2 Headless Claude Code Agent status.
- **Spoken Audio:**
  > "Here is our live evaluation dashboard at `/eval-dashboard`.
  > We maintain complete engineering honesty with a two-tier evaluation framework:
  > Tier 1 executes 14 deterministic protocol and database boundary assertions—verifying schema rules, state transitions, prompt injection isolation, and kiosk session logouts with a 100% pass rate.
  > Tier 2 integrates our headless Claude Code harness using Haiku with a 10-turn cap, testing multi-turn conversational agents over the real HTTP endpoint."

---

### [02:30 - 03:00] Real Tradeoff & Production Deployment (30s)
- **On Screen:** `Caddyfile`, `docker-compose.yml`, and GitHub repository commit log.
- **Spoken Audio:**
  > "If there's one technical decision we would change, it's abandoning stateful Server-Sent Events in favor of pure Stateless HTTP POST. Persistent SSE connections frequently break over rural 2G/3G mobile networks and cloud load balancers; stateless HTTP with confirmation tokens proved far more resilient.
  > The system is fully containerized with Docker Compose and Caddy for HTTPS reverse proxying, tested with 39 unit and wire tests, and version-controlled on GitHub.
  > Thank you for reviewing."

---

### Demo Checklist Before Recording
1. Start portal: `python3 app/app.py` (port 8000).
2. Start MCP server: `python3 mcp/server.py` (port 8010).
3. Browser Tab 1: `http://localhost:8000/eval-dashboard`.
4. Browser Tab 2: `http://localhost:8000/admin/queue` (login: `admin` / `<ADMIN_PASSWORD from env>`).
5. Terminal: Run `python3 -m unittest discover tests` (39 tests pass).
