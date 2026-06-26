-- One IETF Token Status List per credential type per year (e.g. "diploma-2026").

CREATE TABLE status_lists (
    id          TEXT PRIMARY KEY,
    vct         TEXT NOT NULL,
    bits        BYTEA NOT NULL,             -- raw bitstring, LSB-first
    next_index  INTEGER NOT NULL DEFAULT 0, -- next free entry
    size_bits   INTEGER NOT NULL DEFAULT 131072,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
