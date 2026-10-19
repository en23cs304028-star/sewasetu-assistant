# 3-Minute Video Walkthrough Script (Loom)

**Total Duration:** 3:00 (180 seconds)  
**Presenter:** Engineering Lead / AI Pair Programmer  
**System:** Sewa Setu Assistant (Citizen & Officer MCP Servers)  

---

### [00:00 - 00:30] Introduction & Architecture Overview (30s)
- **On Screen:** Split screen showing the Sewa Setu Portal homepage (`http://localhost:8000`) on the left and the MCP endpoint discovery document (`/.well-known/oauth-protected-resource`) on the right.
- **Spoken Audio:**
  > "Namaste and welcome. This is the Sewa Setu Assistant—an AI-driven interface for Assam's Old Age Pension Scheme.
  > Instead of bolting on an isolated chatbot with duplicated validation rules, we engineered two streamable Model Context Protocol servers: one for Citizens, exposing six conversational tools, and one for Block Officers, exposing five triage tools.
  > Both channels share a single source of truth in `app/services.py`, with zero Flask dependencies, authenticated via RFC 9728 OAuth 2.1 Bearer tokens. Let's look at how this works in practice."

---

### [00:30 - 01:00] Citizen Journey & Server-Side Confirmation (30s)
- **On Screen:** Terminal or Claude Code client executing the Citizen flow for Sundari Bai (Persona 01). Show `prepare_application` returning a preview and confirmation token, followed by `submit_application(confirmation_token)`.
- **Spoken Audio:**
  > "Here is our Citizen flow in action. Notice how we avoid passing naive boolean flags like `confirmed_by_citizen=True`, which are vulnerable to hallucination and prompt injection.
  > Instead, calling `prepare_application` performs dry-run validation and stores the draft server-side, returning a short-lived, single-use `confirmation_token` bound to a hash of that exact data.
  > The assistant must read the preview and statutory declaration aloud to the citizen. Once confirmed, `submit_application` takes ONLY the token, writes the application, sends an immediate confirmation SMS via the gateway, and creates an immutable audit row."

---

### [01:00 - 01:30] Edge Cases & Data Traps (30s)
- **On Screen:** Evaluation logs showing Persona 07 (Renu Ali - Boundary Age 60) and Persona 05 (Gopal Das - Duplicate Bank Account).
- **Spoken Audio:**
  > "Real-world governance data contains subtle traps.
  > First: boundary age. Renu Ali turned exactly 60 this year. Using naive day math or 365.25 calculations causes boundary errors on leap years; our calendar logic checks exact day and month boundaries against scheme rules.
  > Second: duplicate bank accounts. In rural communities, elderly women frequently share a son's Jan Dhan account. Instead of rejecting these applications at the door, we allow submission and flag them as an informational warning for the reviewing officer."

---

### [01:30 - 02:00] Officer MCP & Atomic Deemed Approval (30s)
- **On Screen:** Terminal executing Officer MCP tools: `queue_summary`, `list_applications`, and `approve_application`. Show Postgres query verifying the audit row.
- **Spoken Audio:**
  > "On the administrative side, the Officer MCP server lets block officers triage pending applications with statutory SLA visibility.
  > Notice that decisions require non-empty notes on rejection to prevent unexplained denials.
  > Furthermore, we fixed a critical audit race condition in the statutory 15-day deemed approval cron: using `UPDATE ... RETURNING id, application_no, mobile`, approvals and audit logs are committed atomically in the same transaction."

---

### [02:00 - 02:30] Evaluation Dashboard & 100% Pass Rate (30s)
- **On Screen:** Web browser displaying the live `/eval-dashboard` route on the portal with 14/14 persona cards, pass rate statistics, and detailed execution transcripts.
- **Spoken Audio:**
  > "Here is our live evaluation dashboard at `/eval-dashboard`.
  > We ran 14 end-to-end evaluations spanning conversational happy paths, underage rejections, withdrawn-then-reapplied lifecycles, adversarial prompt injection attempts, and kiosk session logouts.
  > Every run asserts directly against PostgreSQL tables and SMS queues. All 14 test personas pass with 100% compliance, leaving the database completely clean."

---

### [02:30 - 03:00] The Tradeoff & Production Readiness (30s)
- **On Screen:** Architecture diagram from `DESIGN-NOTE.md` and GitHub repository commit history (`git log --oneline`).
- **Spoken Audio:**
  > "If there's one architectural decision we would evolve in the next version, it would be adding an IVR phone bridge. Elderly rural citizens often speak local dialects and cannot type in English or Assamese; an IVR gateway connecting speech-to-text directly to our MCP tools would achieve universal accessibility.
  > The code is fully modular, packaged with Docker Compose, tested with 33 unit tests, and pushed to our private GitHub repository.
  > Thank you for watching."

---

### Quick Check & Demo Checklist for Recording
1. `docker compose up` running (or `python app/app.py` on 8000 + `python mcp/server.py` on 8010).
2. Browser tab 1: `http://localhost:8000/eval-dashboard`.
3. Browser tab 2: `http://localhost:8000/admin/queue` (login: `admin` / `change-me-before-deploying`).
4. Terminal ready with Claude Code or `python evals/runner.py`.
