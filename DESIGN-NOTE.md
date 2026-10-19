# Sewa Setu Assistant — Architecture & Design Decisions

## 1. System Overview
The Sewa Setu Assistant provides two Model Context Protocol (MCP) servers—**Citizen MCP** and **Officer MCP**—operating over the Government of Purvanchal's Old Age Pension Portal. Built according to RFC 9728 (OAuth 2.1 Protected Resource Metadata) over streamable HTTP with SSE support, the system bridges elderly citizens and block officers with zero data duplication and guaranteed state integrity.

```
                      +---------------------------------------+
                      |       Citizen / Officer Client        |
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
- **Context:** The original portal had validation and business logic tightly coupled inside Flask route handlers in `app.py`. Duplicating validation logic in the MCP server would inevitably cause drift, where an LLM accepts an application the portal rejects (or vice-versa). Importing `app.py` directly caused side effects (database connections, logging handlers, app context requirements).
- **Solution:** We extracted all core business rules into a standalone, pure-Python module (`app/services.py`):
  - `validate_application()`, `create_application()`, `decide_application()`, `withdraw_application()`, and `send_sms()`.
- **Impact:** Both web routes in `app.py` and MCP tools in `mcp/` invoke the exact same Python functions. Bug fixes (e.g., non-empty rejection reasons) and scheme window updates apply identically across web and conversational channels.

### Decision 2: Server-Side Confirmation Tokens Instead of LLM Booleans
- **Context:** In naive agentic designs, the assistant passes `confirmed_by_citizen=True` or repeats all form fields upon submission. This is vulnerable to hallucination, data distortion during multi-turn chat, and prompt injection (Persona 8).
- **Solution:** `prepare_application` runs the full validator in dry-run mode and saves a draft bound to a cryptographic SHA-256 hash of the exact fields. It returns a 15-minute, single-use `confirmation_token` alongside a citizen preview and declaration. `submit_application` accepts *only* this `confirmation_token`.
- **Impact:** The assistant is physically incapable of mutating data between citizen agreement and final write. If an adversarial user attempts prompt injection, the token either expires or references the unmodified draft.

### Decision 3: Informational Flags Over Hard Rejection for Shared Bank Accounts
- **Context:** Initial specifications proposed rejecting applications if the bank account number already existed in the database.
- **Investigation & Finding:** Seed data analysis revealed that in rural communities, elderly citizens frequently share a family bank account (e.g., a son's or spouse's Jan Dhan account) because they lack personal accounts. Hard rejection would disenfranchise vulnerable citizens.
- **Solution:** We preserved applicant submission for duplicate accounts, but surfaced an explicit warning (`[FLAG] Duplicate bank account: X other application(s) share this account`) in the officer's `get_application` tool.
- **Impact:** Accessible for citizens; transparent for officers during fraud triage.

---

## 3. One Decision I Would Make Differently
- **The Decision:** Relying entirely on text-based chat over Web / Streamable HTTP.
- **The Tradeoff:** While the MCP JSON-RPC protocol over HTTP is standard and works seamlessly with LLMs like Claude, elderly pension applicants in rural Assam predominantly speak Assamese or local dialects and many cannot read or write text.
- **What I Would Do Instead:** Integrate an open-source Indian voice stack (e.g., Bhashini ASR/TTS or Whisper Indic fine-tunes) directly with an Asterisk / FreeSWITCH IVR telephone gateway. An elderly citizen would dial a toll-free number from an ordinary feature phone, converse naturally in Assamese or Hindi, and the IVR bridge would invoke the exact same 6 MCP tools.

---

## 4. Evaluation & Verification Summary
- **14 Realistic Personas Evaluated:** 100% pass rate (14/14).
  - *Data-trap boundary cases:* Boundary age 60 (Renu Ali, born May 1966), duplicate prevention, withdrawn-then-reapply (Kamla Devi), prompt injection resilience (Vikram), shared kiosk signout (Bipul Mahanta).
  - *Officer workflows:* Queue triage, approval with SMS, rejection requiring non-empty rationale, conflict detection on already-decided applications.
- **Zero Race Conditions:** Deemed-approval cron script uses atomic `UPDATE ... RETURNING id, application_no, mobile` to guarantee audit trail consistency.
- **Live Dashboard:** Real-time visibility at `/eval-dashboard` showing execution transcripts, database assertions, and pass/fail status.
