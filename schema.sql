CREATE TABLE IF NOT EXISTS generated_codes (
    id BIGSERIAL PRIMARY KEY,

    code_hash CHAR(64) NOT NULL UNIQUE,

    words TEXT NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS generated_codes_created_at_idx
ON generated_codes (created_at DESC);


CREATE TABLE IF NOT EXISTS auth_sessions (
    id BIGSERIAL PRIMARY KEY,

    session_hash CHAR(64) NOT NULL UNIQUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    expires_at TIMESTAMPTZ NOT NULL
);


CREATE INDEX IF NOT EXISTS auth_sessions_expires_at_idx
ON auth_sessions (expires_at);


CREATE TABLE IF NOT EXISTS rate_limits (
    rate_key TEXT PRIMARY KEY,

    attempts INTEGER NOT NULL DEFAULT 0,

    window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


CREATE INDEX IF NOT EXISTS rate_limits_window_idx
ON rate_limits (window_started_at);
