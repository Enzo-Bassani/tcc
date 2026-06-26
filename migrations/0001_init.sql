-- Students and the credentials issued to them.

CREATE TABLE students (
    id              UUID PRIMARY KEY,
    external_sub    TEXT UNIQUE NOT NULL,   -- IdP "sub" (mock IdP username for now)
    student_number  TEXT UNIQUE NOT NULL,
    full_name       TEXT NOT NULL,
    date_of_birth   DATE,
    course_title    TEXT NOT NULL,
    field_of_study  TEXT NOT NULL,
    degree_level    TEXT NOT NULL,
    conclusion_date DATE NOT NULL,
    gpa             DOUBLE PRECISION,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE issued_credentials (
    jti             UUID PRIMARY KEY,
    student_id      UUID NOT NULL REFERENCES students(id),
    vct             TEXT NOT NULL,
    status_list_id  TEXT NOT NULL,
    status_index    INTEGER NOT NULL,
    claims_json     JSONB NOT NULL,         -- pre-disclosure claims, for audit/re-issue
    issued_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ,
    UNIQUE (status_list_id, status_index)
);
