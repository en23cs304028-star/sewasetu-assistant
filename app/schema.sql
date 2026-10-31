-- Sewa Setu Old Age Pension Portal - schema
-- NOTE: seed.sql (shipped separately) loads after this and contains the
-- production data. Do not re-run against a live database.

CREATE TABLE IF NOT EXISTS applications (
    id              SERIAL PRIMARY KEY,
    application_no  VARCHAR(20),
    applicant_name  VARCHAR(100),
    mobile          VARCHAR(15),
    dob             DATE,
    gender          VARCHAR(10),
    marital_status  VARCHAR(20),
    husband_name    VARCHAR(100),
    husband_employer VARCHAR(100),
    village         VARCHAR(100),
    block           VARCHAR(50),
    bank_account    VARCHAR(30),
    ifsc            VARCHAR(15),
    doc_path        VARCHAR(200),
    status          VARCHAR(20) DEFAULT 'PENDING',
    submitted_at    TIMESTAMP,
    decided_at      TIMESTAMP,
    decided_by      VARCHAR(50)
);

-- Status portal accounts (created at submission time)
CREATE TABLE IF NOT EXISTS portal_users (
    mobile        VARCHAR(15) PRIMARY KEY,
    password_hash VARCHAR(80)
);

CREATE TABLE IF NOT EXISTS otps (
    id         SERIAL PRIMARY KEY,
    mobile     VARCHAR(15),
    code       VARCHAR(6),
    created_at TIMESTAMP,
    attempts   INT DEFAULT 0,
    used_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_mobile ON applications(mobile);
CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_application_mobile ON applications (mobile) WHERE status IN ('PENDING', 'APPROVED', 'DEEMED_APPROVED');

-- Who did what to an application, and when (submit / withdraw / approve / reject / deemed).
CREATE TABLE IF NOT EXISTS audit_log (
    id             SERIAL PRIMARY KEY,
    application_id INTEGER,
    action         VARCHAR(20),
    actor          VARCHAR(50),
    note           VARCHAR(500),
    at             TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_app ON audit_log(application_id);
CREATE INDEX IF NOT EXISTS idx_app_status_submitted ON applications(status, submitted_at);

-- Security events log: auth failures, lockouts, token rejections/revocations, client registrations.
CREATE TABLE IF NOT EXISTS security_audit_log (
    id         SERIAL PRIMARY KEY,
    event_type VARCHAR(64) NOT NULL,
    subject    VARCHAR(128),
    ip         VARCHAR(64),
    user_agent TEXT,
    details    JSONB,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sec_audit_event ON security_audit_log (event_type);
CREATE INDEX IF NOT EXISTS idx_sec_audit_created ON security_audit_log (created_at);

-- OAuth 2.1 authorization server (third-party applications acting for a citizen or officer)
CREATE TABLE IF NOT EXISTS oauth_keys (
    kid         VARCHAR(32) PRIMARY KEY,
    private_pem TEXT,
    created_at  TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_clients (
    id            SERIAL PRIMARY KEY,
    client_id     VARCHAR(300) UNIQUE,
    client_name   VARCHAR(100),
    redirect_uris JSONB,
    secret_hash   VARCHAR(64),
    kind          VARCHAR(10),           -- dcr | cimd
    created_at    TIMESTAMP,
    fetched_at    TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_requests (          -- an authorization in progress (login -> consent)
    id             VARCHAR(64) PRIMARY KEY,
    params         JSONB,
    subject        VARCHAR(80),
    role           VARCHAR(10),
    pending_mobile VARCHAR(15),
    created_at     TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_codes (
    code_hash      VARCHAR(64) PRIMARY KEY,
    client_id      VARCHAR(300),
    redirect_uri   VARCHAR(500),
    scope          VARCHAR(20),
    code_challenge VARCHAR(128),
    resource       VARCHAR(300),
    subject        VARCHAR(80),
    role           VARCHAR(10),
    created_at     TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (   -- one row per sign-in; expires_at is the session's absolute end
    token_hash  VARCHAR(64) PRIMARY KEY,
    client_id   VARCHAR(300),
    client_name VARCHAR(100),
    subject    VARCHAR(80),
    role       VARCHAR(10),
    scope      VARCHAR(20),
    resource   VARCHAR(300),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS oauth_program_tokens (     -- admin-issued, long-lived, for unattended use
    id         SERIAL PRIMARY KEY,
    jti        VARCHAR(32) UNIQUE,
    label      VARCHAR(100),
    subject    VARCHAR(80),
    audience   VARCHAR(300),
    issued_by  VARCHAR(50),
    created_at TIMESTAMP,
    expires_at TIMESTAMP,
    revoked_at TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_revocations (
    jti        VARCHAR(64) PRIMARY KEY,
    subject    VARCHAR(80),
    revoked_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_revocations_subject ON oauth_revocations (subject);

CREATE TABLE IF NOT EXISTS oauth_session_revocations (
    subject    VARCHAR(80) PRIMARY KEY,
    revoked_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key           VARCHAR(128) PRIMARY KEY,
    count         INT DEFAULT 1,
    first_attempt TIMESTAMP DEFAULT NOW(),
    last_attempt  TIMESTAMP DEFAULT NOW()
);

-- Durable citizen draft applications (multi-process safe, canonical hash bound)
CREATE TABLE IF NOT EXISTS drafts (
    draft_id        VARCHAR(64) PRIMARY KEY,
    citizen_id      VARCHAR(64) NOT NULL,
    payload         JSONB NOT NULL,
    payload_hash    VARCHAR(64) NOT NULL,
    scheme_version  VARCHAR(32) NOT NULL DEFAULT 'v1.0',
    status          VARCHAR(20) NOT NULL DEFAULT 'prepared',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    submitted_at    TIMESTAMPTZ,
    application_id  INTEGER REFERENCES applications(id) ON DELETE SET NULL,
    CONSTRAINT chk_draft_status CHECK (status IN ('prepared', 'submitted', 'withdrawn', 'expired'))
);

CREATE INDEX IF NOT EXISTS idx_drafts_citizen_id ON drafts (citizen_id);
CREATE INDEX IF NOT EXISTS idx_drafts_expires_at ON drafts (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS uq_drafts_application_id ON drafts (application_id) WHERE application_id IS NOT NULL;

-- Single-use officer confirmation tokens for two-step approve/reject decisions
CREATE TABLE IF NOT EXISTS confirmation_tokens (
    token_hash      VARCHAR(64) PRIMARY KEY,
    application_id  INTEGER NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    decision        VARCHAR(20) NOT NULL,
    officer_subject VARCHAR(80) NOT NULL,
    reason          VARCHAR(500),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL,
    used_at         TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_conf_tokens_app ON confirmation_tokens (application_id);


