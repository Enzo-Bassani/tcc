# SSI for Academic Diplomas — issuer · verifier · wallet

A **Self-Sovereign Identity (SSI)** system that issues academic diplomas as
**Verifiable Credentials** and verifies them — built as a course-conclusion project
(TCC, UFSC). It implements the full holder ↔ issuer ↔ verifier triangle on open
standards: diplomas are minted as **SD-JWT VCs** over **OID4VCI**, held in a mobile
wallet, and presented over **OID4VP 1.0** with selective disclosure.

The cryptographic engine is written once in Rust (`ssi-core`) and reused everywhere —
natively on the issuer, compiled to **WebAssembly** in the browser verifier, and
re-implemented in Kotlin for the wallet, with a conformance oracle proving the two
ports are byte-compatible.

## Components

| Component | Where | What it is |
|-----------|-------|------------|
| **Issuer** | `src/`, root crate `issuer_backend` | Issues diplomas as SD-JWT VCs over **OID4VCI**, with a `did:web` identity and IETF Token Status List revocation (axum + sqlx + PostgreSQL). |
| **`ssi-core`** | `crates/ssi-core` | The shared SSI engine — JWS (EdDSA + ES256), SD-JWT, DCQL, OID4VP, status lists, `did:web`. Native **and** WebAssembly. |
| **Verifier** | `crates/verifier-wasm` + `web/` | A universal **OID4VP 1.0** verifier whose crypto runs **entirely in the browser** (WASM), bridged to wallets by a dumb transport relay (`crates/relay`). |
| **Wallet** | `wallet/` (Kotlin/Android) | The **holder**: receives credentials over OID4VCI, stores them, and presents them over OID4VP. Its engine is a pure-Kotlin port of `ssi-core`, proven byte-compatible by the oracle in `crates/wallet-core`. See [`wallet/README.md`](wallet/README.md). |

## Dependencies

To build and run the backend (issuer + verifier + relay) and the Rust test suite:

- **Rust** (stable, edition 2024) + `cargo`
- **Docker** + Docker Compose — runs PostgreSQL 16 (the only datastore)
- **`wasm-pack`** — builds the browser verifier's WebAssembly bundle
- **[`just`](https://github.com/casey/just)** — task runner for all the recipes below
- *Optional:* `qrencode` (terminal QR codes for offers), `curl`, `python3`, a browser

To build and run the **wallet** you additionally need a **JDK 17** and the **Android
SDK** (+ an emulator). The pure-Kotlin engine and its tests run with **only a JDK** —
no Android stack required.

> **Setup instructions for all of the above are in [`docs/INSTALL.md`](docs/INSTALL.md).**

## Quick start — deploy and use

```sh
just deploy        # Postgres + WASM verifier + issuer + relay, all in the background
```

This auto-detects a LAN IP, builds the WASM verifier, launches the issuer
(`:8080`) and the relay/verifier app (`:8090`), and waits until both are healthy.
Logs go to `.dev-logs/`; stop everything with `just teardown`.

Then issue and present a diploma:

```sh
just offer-qr      # mint a credential offer for a seeded student, as a terminal QR
just verifier      # open the browser verifier (served by the relay) to request a presentation
```

Scan the offer QR with the wallet (`just wallet` builds/installs it on an emulator —
see [`wallet/README.md`](wallet/README.md)) to receive the diploma, then scan the
verifier's request QR to present it. Handy admin helpers: `just credentials` (list
issued), `just revoke <jti>` / `just revoke-last`, `just health`. Run `just --list`
for the full set.

> **No wallet/emulator?** You can see a diploma SD-JWT without a database or a phone:
> `cargo run -- issue-test` prints a sample credential offline.

## Running the tests

The whole system is tested across the cargo workspace plus the Kotlin wallet suite.
**One command runs everything:**

```sh
just test          # Rust workspace + DB-backed issuer tests + clippy + Kotlin conformance
```

This is the canonical "did I break anything?" check: it starts Postgres, sets
`TEST_DATABASE_URL`, runs the full Rust suite and clippy, and re-runs the Kotlin
conformance oracle.

Scope to a single area with the underlying recipes (`just --list`):

| Recipe | Database? | Covers |
|--------|-----------|--------|
| `just test-rust` | no | Whole Rust workspace: engine units, full issue→present→validate (EdDSA + ES256), revoked / replay / tamper failure modes, verifier-over-relay E2E, issuer↔verifier interop. |
| `just test-db` | **yes** | Issuer OID4VCI integration (pre-authorized + auth-code flows → token → credential → verify → revoke) and the full-stack HTTP E2E. Skips cleanly without `TEST_DATABASE_URL`. |
| `just clippy` | no | Lint across the workspace (kept warning-free). |
| `just test-wallet` | no | Kotlin wallet suite + the cross-language conformance oracle. |

### Narrated protocol walkthroughs

Two tests print the full protocol exchange step by step — the best way to *see* each
flow:

```sh
# OID4VP — verifier requesting and validating a presentation (no database)
cargo test -p relay --test walkthrough -- --nocapture

# OID4VCI — issuer issuing a credential (needs a database)
TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend \
  cargo test -p issuer_backend --test walkthrough -- --nocapture
```

## Configuration

The issuer reads `config/default.toml`, overridable by `ISSUER__*` environment
variables (e.g. `ISSUER__DATABASE_URL=...`, `ISSUER__ISSUER_URL=...`). It listens on
`http://localhost:8080` by default.

## Security note

This is a **prototype**. The issuer signing key is stored **in plaintext** under
`keys/`, and the university SSO is a mock IdP — both acceptable for a TCC only. A
production deployment must use a KMS/HSM for the signing key and integrate the real
institutional SSO.
