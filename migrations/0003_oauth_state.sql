-- Transient OAuth / OID4VCI state.

-- Pending authorization-code requests, awaiting student login at the mock IdP.
CREATE TABLE auth_sessions (
    id                    TEXT PRIMARY KEY,
    redirect_uri          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    credential_config_id  TEXT NOT NULL,
    state                 TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE authorization_codes (
    code                  TEXT PRIMARY KEY,
    student_id            UUID NOT NULL REFERENCES students(id),
    redirect_uri          TEXT NOT NULL,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    credential_config_id  TEXT NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed              BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE pre_authorized_codes (
    code                  TEXT PRIMARY KEY,
    student_id            UUID NOT NULL REFERENCES students(id),
    credential_config_id  TEXT NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL,
    consumed              BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE access_tokens (
    token                 TEXT PRIMARY KEY,
    student_id            UUID NOT NULL REFERENCES students(id),
    credential_config_id  TEXT NOT NULL,
    expires_at            TIMESTAMPTZ NOT NULL
);

CREATE TABLE c_nonces (
    nonce       TEXT PRIMARY KEY,
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed    BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE credential_offers (
    id          TEXT PRIMARY KEY,
    offer_json  JSONB NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
