# SSI system (issuer + verifier) — TCC

A Self-Sovereign Identity system for a course-conclusion project (TCC), built in Rust as a
**cargo workspace**:

- **Issuer** (`issuer_backend`, root) — issues academic diplomas as **SD-JWT Verifiable
  Credentials** over **OID4VCI**, with a `did:web` identity and IETF Token Status List
  revocation (axum + sqlx + PostgreSQL).
- **`ssi-core`** (`crates/ssi-core`) — the shared SSI engine (JWS EdDSA+ES256, SD-JWT, DCQL,
  OID4VP, status lists, `did:web`); native **and** WebAssembly.
- **Verifier** — a universal **OID4VP 1.0** verifier whose cryptographic checks run entirely
  in the browser (`crates/verifier-wasm` + the static app in `web/`), bridged to wallets by a
  dumb transport relay (`crates/relay`).
- **Wallet** (`wallet/`, Kotlin/Android — a separate Gradle build) — the **holder**: receives
  credentials over OID4VCI, stores them, and presents them over OID4VP. Its SSI engine is a
  pure-Kotlin port of `wallet_sim`, proven byte-compatible with the verifier by the conformance
  oracle in `crates/wallet-core`. See `wallet/README.md`.

## Quick start

```sh
# 1. Start PostgreSQL
docker compose up -d

# 2. Run the server (creates keys/ and runs migrations on first start)
cargo run

# 3. Offline demo — print a sample diploma SD-JWT, no database needed
cargo run -- issue-test
```

The server listens on `http://localhost:8080` by default. Configure via
`config/default.toml` or `ISSUER__*` environment variables
(e.g. `ISSUER__DATABASE_URL=...`).

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET  | `/health` | Liveness |
| GET  | `/.well-known/did.json` | did:web document |
| GET  | `/.well-known/jwks.json` | Issuer public key |
| GET  | `/.well-known/openid-credential-issuer` | OID4VCI issuer metadata |
| GET  | `/.well-known/oauth-authorization-server` | OAuth AS metadata |
| POST | `/credential-offer` | Mint a Credential Offer (admin, Basic auth) |
| GET  | `/credential-offer/{id}` | Fetch a Credential Offer |
| GET  | `/authorize` | OAuth authorization endpoint |
| POST | `/token` | Token endpoint (auth-code + pre-authorized) |
| POST | `/nonce` | Issue a `c_nonce` |
| POST | `/credential` | Issue the SD-JWT VC |
| GET  | `/status-lists/{id}` | Token Status List JWT |
| POST | `/admin/credentials/{jti}/revoke` | Revoke (admin, Basic auth) |
| GET/POST | `/mock-idp/login` | Mock university SSO |

## Testing

The whole system is tested across the workspace. **Only the issuer's integration tests need a
database**; the entire engine + verifier suite runs with nothing installed but Rust. Tests
that need a DB **skip cleanly** (printing a SKIP notice) when `TEST_DATABASE_URL` is unset, so
the commands below never fail for lack of Postgres.

### Run everything

The whole suite is one command (via [`just`](https://github.com/casey/just)):

```sh
just test        # Rust workspace + DB-backed issuer tests + clippy + Kotlin wallet suite
```

This is the canonical "did I break anything?" check after any code change; it starts
Postgres, sets `TEST_DATABASE_URL`, and re-runs the Kotlin conformance oracle for you. Run
`just --list` for granular recipes (`test-rust`, `test-db`, `test-wallet`, `clippy`, `db-up`);
the recipes live in `justfile`.

### What the tests cover

`just test` wraps these underlying commands; run them directly to scope a single area:


| Command | Database? | Covers |
|---------|-----------|--------|
| `cargo test -p ssi-core` | no | Engine units (JWS EdDSA+ES256, SD-JWT, DCQL matching, status, did:web) **and** `tests/engine.rs`: full issue→present→validate for EdDSA + ES256, plus revoked / wrong-nonce (replay) / tampered-signature / `inspect` failure modes. |
| `cargo test -p relay --test e2e` | no | Verifier over the real relay (HTTP): valid round-trip, revoked → invalid, unsatisfiable DCQL → no presentation, and **issuer↔verifier interop** (a real diploma minted by the issuer crate validates in the verifier). |
| `cargo test -p relay --test walkthrough -- --nocapture` | no | The **narrated OID4VP presentation walkthrough** — every message + the decoded presentation and verification report (see below). |
| `cargo test -p issuer_backend --lib` | no | Issuer unit tests (did:web document generation). |
| `cargo test -p issuer_backend` | **yes** | Issuer OID4VCI integration: `tests/e2e.rs` (pre-authorized + auth-code flows: offer → token → credential → verify → revoke → confirm status bit) and the issuer walkthrough. Skips without `TEST_DATABASE_URL`. |

### The two narrated walkthroughs

These print the full protocol exchange step by step (require `-- --nocapture`); they are the
best way to *see* each protocol and are handy for the thesis/defense:

```sh
# OID4VP — verifier requesting and validating a presentation (no database)
cargo test -p relay --test walkthrough -- --nocapture

# OID4VCI — issuer issuing a credential (needs a database)
TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend \
  cargo test -p issuer_backend --test walkthrough -- --nocapture
```

### Run a single test

```sh
cargo test -p ssi-core es256_issuer_verifies
cargo test -p relay --test e2e issuer_interop_real_diploma_verifies
cargo test -p issuer_backend --test e2e pre_authorized_flow_issues_and_revokes
```

### Lint

```sh
cargo clippy --workspace --all-targets   # kept warning-free
```

> Note: the browser demo's WebAssembly bundle (`web/pkg/`) is a build artifact, not committed.
> It is not needed to run the tests; build it only to run the demo
> (`wasm-pack build crates/verifier-wasm --target web --out-dir ../../web/pkg`).

## Manual verification

```sh
curl localhost:8080/.well-known/did.json
curl localhost:8080/.well-known/openid-credential-issuer

# Pre-authorized flow
curl -u admin:admin -X POST localhost:8080/credential-offer \
  -H 'content-type: application/json' \
  -d '{"student_number":"2020000001","grant":"pre_authorized"}'
```

## Security note

The issuer signing key is stored **in plaintext** under `keys/` — acceptable for
this TCC prototype only. A production deployment must use a KMS/HSM and integrate
the real university SSO in place of the mock IdP.
