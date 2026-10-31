# Sewa Setu Assistant — Architecture & Design Decisions

## 1. System Overview
The Sewa Setu Assistant provides two Model Context Protocol (MCP) servers—**Citizen MCP** (6 tools) and **Officer MCP** (5 tools)—operating over the Government of Purvanchal's Old Age Pension Portal. Built according to RFC 9728 (OAuth 2.1 Protected Resource Metadata) over streamable HTTP, the architecture unifies web portal routes and conversational LLM interfaces into a single authoritative validation pipeline.

```
                      +---------------------------------------+
                      |       Citizen / Officer Client        |
                      |     (Claude Code / Web Interface)     |
                      +-------------------+-------------------+
                                          | Bearer Token (RS256)
                                          v
+-----------------------+     +-------------------------------+
|  Sewa Setu Portal     |     |   Streamable HTTP MCP Server  |
|  - Web UI (Port 8000) |     |   (RFC 9728, Port 8010)       |
|  - OAuth 2.1 Auth Svr |     |   - /mcp/citizen (6 tools)    |
|  - /eval-dashboard    |     |   - /mcp/officer (5 tools)    |
+-----------+-----------+     +---------------+---------------+
            \                                /
             \                              /
              v                            v
          +------------------------------------+
          |       app/services.py              |
          |  (Unified Pure-Python Domain Logic)|
          +-----------------+------------------+
                            |
           +----------------+----------------+
           v                                 v
   +---------------+                 +---------------+
   | PostgreSQL DB |                 |  SMS Gateway  |
   +---------------+                 +---------------+
```

---

## 2. Three Design Decisions That Mattered Most

### Decision 1: Single Validation Path (`app/services.py`) Without Importing Flask
- **Context:** The original portal coupled validation, database connections, and session handling inside Flask route handlers in `app.py`. Duplicating validation logic in the MCP servers would cause subtle discrepancies, where an LLM accepts an application the portal rejects. Importing `app.py` directly caused side effects (database connections, logging handlers, app context requirements).
- **Solution:** We extracted all business rules into a standalone, pure-Python module (`app/services.py`):
  - `validate_application()`, `create_application()`, `decide_application()`, `withdraw_application()`, and `send_sms()`.
- **Impact:** Both web routes in `app.py` and MCP tools in `mcp/` invoke the exact same Python functions. Bug fixes (e.g., non-empty rejection reasons) and scheme window updates apply identically across web and conversational channels.

### Decision 2: Server-Side Confirmation Tokens Instead of LLM Booleans
- **Context:** In naive agent designs, the assistant passes `confirmed_by_citizen=True` or repeats all form fields upon submission. This is vulnerable to model hallucination, data distortion during multi-turn chat, and prompt injection (Persona 08 - Vikram).
- **Solution:** `prepare_application` runs the full validator in dry-run mode and stores the draft server-side, returning a short-lived (15 min), single-use `confirmation_token` bound to a SHA-256 hash of that exact data. `submit_application` accepts *only* this `confirmation_token`.
- **Impact:** The assistant is physically incapable of mutating data between citizen agreement and final write. If an adversarial user attempts prompt injection, the token either expires or references the unmodified draft.

### Decision 3: Informational Flags Over Hard Rejection for Shared Bank Accounts
- **Context:** The original specification suggested rejecting applications if a bank account number already existed in the database.
- **Investigation & Finding:** Seed data analysis revealed that in rural Assam, elderly citizens frequently share a family bank account (e.g., a son's or spouse's Jan Dhan account) because they lack personal accounts. Hard rejection would disenfranchise vulnerable citizens.
- **Solution:** We preserved applicant submission for duplicate accounts, but surfaced an explicit warning (`[FLAG] Duplicate bank account: X other application(s) share this account`) in the officer's `get_application` tool.
- **Impact:** Accessible for citizens; transparent for officers during fraud triage.

---

## 3. One Decision I Would Make Differently: Abandoning Stateful SSE in Favor of Pure Stateless HTTP POST
- **The Initial Choice:** We initially implemented Server-Sent Events (SSE) alongside HTTP POST to support streaming MCP clients.
- **The Tradeoff & Failure Mode:** In real network testing, SSE requires long-lived stateful TCP connections, keepalive heartbeats (`: keepalive\n\n`), and in-memory message queues (`SSE_SESSIONS`). When running behind cloud reverse proxies (like Caddy/Nginx) or over unstable mobile data networks in rural areas, SSE connections silently drop, leaving queue buffers abandoned and clients hanging. Furthermore, container restarts kill active SSE streams.
- **What I Would Do Differently:** Standardize exclusively on **Stateless Streamable HTTP POST** with standard JSON-RPC 2.0 request/response cycles. Stateless HTTP POST eliminates sticky sessions, scales horizontally across any number of workers without shared memory, survives container restarts seamlessly, and works through every cloud load balancer out-of-the-box.

---

## 4. Evaluation & Verification Architecture: Two-Tier Methodology
To maintain rigorous engineering honesty, our evaluation suite separates deterministic code assertions from model-driven agent evaluations:
- **Tier 1: Deterministic Protocol & Database Assertions (14 Scenarios):**
  - Asserts exact schema rules, calendar boundary age calculation (Renu Ali, born May 1966), duplicate submission prevention, withdrawal-then-reapply lifecycle, officer rejection note enforcement, and atomic deemed-approval race prevention (`UPDATE ... RETURNING id`).
- **Tier 2: Headless LLM Agent Evaluation (`evals/claude_harness.py`):**
  - Uses Claude Code in headless mode (`claude -p --model haiku --max-turns 10`) configured with an MCP config pointing to the live streamable HTTP endpoint.
  - When API credentials are configured, it executes live conversational turns and verifies end-to-end multi-turn tool calling.
- **Live Status Dashboard (`/eval-dashboard`):** Real-time portal view reporting both tiers with complete transparency, transcripts, and before-and-after change notes.

---

## 5. Security & Governance Considerations

### Officer Confirmation & Two-Step Token Tradeoffs
The two-step confirmation token pattern (`decide_application` requiring a preview call followed by confirmation with `confirmation_token`) introduces valuable friction, dedicated audit trails, and per-officer rate limits. However, an autonomous LLM agent equipped with full tool-calling autonomy can simply execute the preparation step and immediately pass the resulting confirmation token to execute the action in sequence. Therefore, the server-side token alone cannot prevent a compromised or misbehaving agent from completing destructive operations without human intervention; robust defense relies on client-side confirmation prompts (e.g. MCP client interactive user approvals for destructive tools). Enforcing true out-of-band human confirmation via web portal approval before finalizing high-impact decisions remains essential future work.

### Database Migration Role vs Runtime Role
Currently, application startup invokes `services.ensure_all_tables(conn)` which runs DDL statements (`CREATE TABLE IF NOT EXISTS`, `CREATE INDEX IF NOT EXISTS`) using the default application runtime database connection. In a hardened defense-in-depth architecture, this represents a privilege conflict: runtime services should operate strictly under a least-privilege role possessing only DML permissions (`SELECT`, `INSERT`, `UPDATE`, `DELETE`), preventing any potential SQL injection vulnerability from modifying or dropping schema objects. Separating database lifecycle management into a dedicated migration container or CI/CD job using a high-privilege migration role (`sewasetu_migrator`), while restricting runtime containers to a DML-only role (`sewasetu_app`), is planned as future work.

