# Sewa Setu Portal: Step 0 Verification Notes

These notes answer each question from the actual codebase and seed dataset before making any modifications.

---

### 1. Age Proof Upload Handling
- **What `upload.html` and the upload handler in `app/app.py` do**:
  - `upload.html` is an HTML multipart form with an `<input type="file" name="document">`.
  - The handler in `app/app.py:upload()` inspects:
    1. Presence of file: `f is None or f.filename == ""`
    2. File extension: `filename.rsplit(".", 1)[-1] in ("pdf", "jpg", "jpeg", "png")`
    3. File size: `len(content) > 5 * 1024 * 1024` (max 5 MB limit)
  - It does **not** inspect internal file content (no magic byte check, no OCR or image analysis).
  - Storage location: `os.path.join(UPLOAD_DIR, "%s_%s" % (session["verified_mobile"], filename))`, where `UPLOAD_DIR` is loaded from `app.ini` (`[app] upload_dir = /var/sewasetu/uploads`).
  - Container writability: The Dockerfile creates the directory (`RUN mkdir -p /var/sewasetu/uploads /var/log/sewasetu`), and `docker-compose.yml` mounts a dedicated Docker named volume `uploads:/var/sewasetu/uploads`. It is fully writable.
  - In `validate_application()`, the check is simply:
    ```python
    if not cleaned["doc_path"]:
        errors.append("age proof document is required")
    ```

---

### 2. Password Reset (`reset.html` & `reset_password()`)
- **What it resets**: It looks up `portal_users WHERE mobile = %s`, finds the applicant's date of birth in `applications WHERE mobile = %s LIMIT 1`, and updates `portal_users.password_hash` to `hash_password(dob.strftime("%d%m%Y"))`.
- **OTP / DOB Bypass Analysis**:
  - It does **not** bypass the DOB-as-password rule; it resets the password *back* to the citizen's DOB (`DDMMYYYY`).
  - However, **no OTP is required** to trigger this endpoint in the web portal. Anyone knowing a registered mobile can trigger an SMS with the reset message.
  - **Assistant Guardrail**: Do not expose this unauthenticated reset in the MCP server. Citizens in MCP authenticate via OAuth OTP.

---

### 3. Officers & Block Scoping
- **Schema & OAuth verification**:
  - `app/schema.sql` contains **no** `officers` table and **no** block-to-officer mapping table.
  - There is only the single departmental `admin` login (`ADMIN_USERNAME` and `ADMIN_PASSWORD` from environment variables) and program tokens generated at `/admin/tokens`.
  - In `app/oauth.py`, officer authentication checks credentials against `ADMIN_USERNAME` / `ADMIN_PASSWORD` and mints tokens with `subject="officer:<username>"`.
- **Decision**: In strict adherence to the corrections instruction ("If no mapping exists, drop block-scoped officers entirely"), block-scoped authorization is dropped. Block filtering is retained only as an informational/search parameter for queue triage.

---

### 4. `audit_log` Columns
- **Existing Schema**:
  ```sql
  CREATE TABLE audit_log (
      id             SERIAL PRIMARY KEY,
      application_id INTEGER,
      action         VARCHAR(20),  -- SUBMIT, WITHDRAW, APPROVED, REJECTED, DEEMED_APPROVED
      actor          VARCHAR(50),  -- e.g. applicant:<mobile>, admin:<username>, system:rtps-cron
      note           VARCHAR(500), -- rejection/approval reasons or system notes
      at             TIMESTAMP
  );
  ```
- **Channel Field**: There is **no** `channel` column.
- **Decision**: Reuse existing columns without modifying the database schema. The actor remains `applicant:<mobile>` or `officer:<username>`. Where helpful for audit provenance, prefix the `note` field with `[mcp-citizen]` or `[mcp-officer]`.

---

### 5. SMS Sending Mechanism
- **Portal Implementation**:
  - Implemented in `app/app.py:send_sms(mobile, text)`:
    ```python
    def send_sms(mobile, text):
        try:
            requests.post(SMS_GATEWAY_URL + "/api/send",
                          json={"to": mobile, "text": text}, timeout=5)
        except Exception as e:
            app.logger.error("sms gateway error: %s" % e)
    ```
  - `SMS_GATEWAY_URL` is read from `config/app.ini` (`http://smsgw:8025`).
  - Calls are made on:
    1. Submission confirmation
    2. OTP generation (`/apply` and `/oauth/login`)
    3. Password reset
    4. Nightly deemed approval (`scripts/deemed_approval.py`)
- **Decision**: Extract `send_sms` directly into `app/services.py` so both `app.py` and MCP servers call the identical function.

---

### 6. JWT Claims in `app/oauth.py`
- **Claim Keys Minted in `mint_access_token()`**:
  - `iss`: Issuer URL (`PUBLIC_BASE_URL` or `http://localhost:8000`)
  - `sub`: Subject identifier (`citizen:<mobile>` or `officer:<username>`)
  - `aud`: Requested resource URL (canonical endpoint URL)
  - `scope`: `citizen` or `officer`
  - `role`: `citizen` or `officer`
  - `client_id`: Registered client ID
  - `iat`: Epoch integer timestamp
  - `exp`: Epoch integer expiration
  - `jti`: 24-character random hex token ID
  - `kind`: `"access"` or `"program"`
  - `session_ends`: Optional integer epoch timestamp (stamped when token is minted from a session)
- **Session Identification**: Access tokens do not contain a distinct `"session_id"` claim. Revocation works by subject or refresh token hash in `oauth_refresh_tokens`.

---

### 7. Scheme Rules & Configuration Sources
- In `app/config/app.ini`:
  - `[pension] min_age = 60`
  - `[pension] sla_days = 15`
  - `[pension] scheme_deadline = 2026-10-31 23:59`
- In `app/app.py`:
  - `BLOCKS = ["Sonari", "Rajapara", "Dhemaji Pathar", "Borgaon", "Namti", "Khelua"]`
- `validate_application()` checks:
  1. Required fields: `applicant_name`, `village`, `block`, `bank_account`, `dob`, `doc_path`
  2. Block in `BLOCKS`
  3. Bank account digits: `re.fullmatch(r"\d{9,18}", ...)`
  4. IFSC: `re.fullmatch(r"[A-Z]{4}0[A-Z0-9]{6}", ...)`
  5. Age on today: `age_on(dob, now_ist().date()) >= min_age`
  6. Deadline: `now_ist() <= scheme_deadline`
- **Decision**: `get_scheme_info` will read directly from `config/app.ini` and shared `BLOCKS`, guaranteeing zero drift.

---

### 8. Seed Data Analysis
From querying `seed/seed.sql` (100,000 records snapshot):
- **Status Breakdown**:
  - `APPROVED`: 82,900
  - `DEEMED_APPROVED`: 9,000
  - `REJECTED`: 7,000
  - `PENDING`: 700
  - `WITHDRAWN`: 400
- **Real Blocks & Sample Villages**:
  - **Borgaon**: Milanpur, Udaypur, Borgaon Centre
  - **Dhemaji Pathar**: Kathoni, Nalbari Gaon, Bordoloni
  - **Khelua**: Khelua Gaon, Chengelimara, Sialmari
  - **Namti**: Namti Chariali, Hatipara, Panidihing
  - **Rajapara**: Dighaljan, Rajapara Gaon, Teliagaon
  - **Sonari**: Bhekulajan, Lakhipur, Kakotibari, Namdang
- **Duplicate Bank Accounts in Seed**: 0 (all 100k generated accounts are unique).
- **Withdrawn-then-Reapplied Mobiles in Seed**: 0 (each mobile appears at most once in seed).
- **Boundary-Age Applicants (Exactly 60 in Oct 2026)**:
  - 3,429 applicants born between Nov 1965 and Oct 1966.
  - Examples:
    - Renu Ali (DOB: 1966-05-22, Village: Teliagaon, Block: Rajapara, Mobile: 8394209464)
    - Anima Bora (DOB: 1966-04-03, Village: Rajapara Gaon, Block: Rajapara, Mobile: 8337737615)
    - Junu Bora (DOB: 1966-06-04, Village: Chengelimara, Block: Khelua, Mobile: 6489841372)
- **Data-trap / Persona Source**: Persona names, villages, and boundary cases will be drawn directly from these authentic distributions.
