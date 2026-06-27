# Justfile for the SSI system (issuer + verifier + wallet).
# Run `just` to list recipes. Requires: cargo, docker compose, a JDK, and the Android
# SDK on PATH (adb/emulator) for the wallet recipes.
#
# Typical workflows:
#   just test            # full automated suite — run after ANY code change
#   just deploy          # bring up the backend (Postgres + WASM + issuer + relay)
#   just redeploy        # restart the backend after issuer/relay/WASM changes
#   just wallet          # build + install + launch the wallet on the emulator (boots one if needed)
#   just teardown        # stop the backend
#
# `just test` is the canonical "did I break anything?" check. A bare `cargo test
# --workspace` is NOT enough: it silently SKIPS the issuer integration tests when
# TEST_DATABASE_URL is unset, and Gradle caches the Kotlin conformance run.

db_url := "postgres://issuer:issuer@localhost:5432/issuer_backend"

# Admin-API target for the manual-testing helpers below. The issuer binds 0.0.0.0 under
# `just deploy`, so localhost reaches it from this machine regardless of $HOST.
# Override per-invocation, e.g. `ISSUER_URL=http://<lan-ip>:8080 just offer`.
issuer := env_var_or_default("ISSUER_URL", "http://localhost:8080")
relay  := env_var_or_default("RELAY_URL", "http://localhost:8090")
admin  := env_var_or_default("ADMIN", "admin:admin")

# List available recipes
default:
    @just --list

# Start PostgreSQL (needed for the DB-backed issuer tests)
db-up:
    docker compose up -d

# Rust workspace tests (engine + verifier + relay + wallet-core) — no DB needed
test-rust:
    cargo test --workspace

# REQUIRED — the `test-rust` workspace run skips these silently when TEST_DATABASE_URL is unset.
# Issuer DB-backed integration tests (OID4VCI flows + revoke) plus the full-stack
# E2E (real HTTP issuance → live relay → verifier), which also needs the DB.
test-db: db-up
    TEST_DATABASE_URL={{db_url}} cargo test -p issuer_backend
    TEST_DATABASE_URL={{db_url}} cargo test -p relay --test fullstack

# Build the host Rust native lib (libwallet_ffi) + generate the UniFFI Kotlin
# bindings into :ssi. Needed before the :ssi JVM tests (RustSsiEngine + parity)
# load the lib via JNA. No NDK, no emulator — runs on a plain host.
wallet-ffi-host:
    cargo build -p wallet-ffi
    cargo run -q -p wallet-ffi --features cli --bin uniffi-bindgen -- generate \
        --library target/debug/libwallet_ffi.so --language kotlin \
        --out-dir wallet/ssi/src/main/kotlin --no-format

# Cross-compile the per-ABI Android .so (arm64-v8a + x86_64) into the app's
# jniLibs and regenerate the bindings. Requires the NDK + cargo-ndk + the rustup
# Android targets (aarch64-linux-android, x86_64-linux-android). See wallet/README.md.
wallet-ffi-android:
    cargo ndk -t arm64-v8a -t x86_64 -o wallet/app/src/main/jniLibs \
        build -p wallet-ffi --release
    cargo run -q -p wallet-ffi --features cli --bin uniffi-bindgen -- generate \
        --library target/aarch64-linux-android/release/libwallet_ffi.so \
        --language kotlin --out-dir wallet/ssi/src/main/kotlin --no-format

# --rerun-tasks because Gradle doesn't track the Rust oracle binary as an input (else UP-TO-DATE).
# Kotlin wallet suite + Rust conformance oracle (builds the host FFI lib first)
test-wallet: wallet-ffi-host
    cd wallet && ./gradlew :ssi:test --rerun-tasks

# Clippy across the workspace (kept warning-free)
clippy:
    cargo clippy --workspace --all-targets

# Regenerate the committed SD-JWT VC Type Metadata artifact (type-metadata/UniversityDiploma-v1.json)
# from diploma::type_metadata(). A test fails if the committed file drifts from the code.
type-metadata:
    cargo run -- type-metadata

# Run the FULL automated suite (Rust + DB + clippy + Kotlin) — run after any change.
test: db-up test-rust test-db clippy test-wallet
    @echo "==> All tests passed."

# Override the LAN IP with `HOST=1.2.3.4 just deploy`; otherwise it is auto-detected. Issuer +
# relay run in the background (logs under .dev-logs/, stop with `just teardown`).
# Launch the whole backend (Postgres + WASM verifier + issuer + relay) for local E2E
deploy:
    #!/usr/bin/env bash
    set -euo pipefail
    HOST="${HOST:-$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -1)}"
    [ -n "$HOST" ] || { echo "could not detect a LAN IP — set HOST=<ip> and retry" >&2; exit 1; }
    echo "==> HOST=$HOST"
    mkdir -p .dev-logs
    echo "==> Starting PostgreSQL"
    docker compose up -d
    echo "==> Building the verifier engine to WASM (web/pkg)"
    wasm-pack build crates/verifier-wasm --target web --out-dir ../../web/pkg
    echo "==> Launching issuer on $HOST:8080"
    ISSUER__ISSUER_URL="http://$HOST:8080" ISSUER__BIND_ADDR="0.0.0.0:8080" \
        nohup cargo run >.dev-logs/issuer.log 2>&1 & echo $! >.dev-logs/issuer.pid
    echo "==> Launching relay on $HOST:8090"
    RELAY_BIND="0.0.0.0:8090" RELAY_BASE_URL="http://$HOST:8090" \
        nohup cargo run -p relay >.dev-logs/relay.log 2>&1 & echo $! >.dev-logs/relay.pid
    echo "==> Waiting for both to report healthy (first build can take a while)…"
    for _ in $(seq 1 180); do
        if curl -sf -o /dev/null "http://$HOST:8080/health" && curl -sf -o /dev/null "http://$HOST:8090/"; then
            echo "==> UP  ·  verifier: http://$HOST:8090  ·  issuer: http://$HOST:8080"
            echo "    logs: .dev-logs/{issuer,relay}.log   ·   stop: just teardown"
            echo "    wallet/emulator: see wallet/README.md"
            exit 0
        fi
        sleep 1
    done
    echo "services did not become healthy in time — check .dev-logs/*.log" >&2
    exit 1

# Stop the locally-deployed system (issuer + relay + Postgres) started by `just deploy`.
teardown:
    #!/usr/bin/env bash
    set -uo pipefail
    for svc in issuer relay; do
        if [ -f ".dev-logs/$svc.pid" ]; then kill "$(cat ".dev-logs/$svc.pid")" 2>/dev/null || true; rm -f ".dev-logs/$svc.pid"; fi
    done
    # `cargo run` execs the server as a child, so also match the built binaries directly.
    pkill -f 'target/debug/issuer_backend' 2>/dev/null || true
    pkill -f 'target/debug/relay' 2>/dev/null || true
    docker compose down
    echo "==> Stopped issuer + relay + Postgres."

# Restart the backend to pick up issuer/relay/WASM code changes (teardown + deploy).
redeploy: teardown deploy

# Override the AVD with `AVD=Name just emulator`; auto-picks the first one otherwise.
# Boot the Android emulator (idempotent — no-op if a device is already connected)
emulator:
    #!/usr/bin/env bash
    set -euo pipefail
    if adb get-state >/dev/null 2>&1; then echo "==> Device already connected:"; adb devices; exit 0; fi
    AVD="${AVD:-$(emulator -list-avds | head -1)}"
    [ -n "$AVD" ] || { echo "no AVD found — create one in Android Studio" >&2; exit 1; }
    mkdir -p .dev-logs
    echo "==> Booting emulator: $AVD"
    nohup emulator -avd "$AVD" >.dev-logs/emulator.log 2>&1 &
    echo "==> Waiting for boot…"
    adb wait-for-device
    until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ]; do sleep 2; done
    echo "==> Emulator ready."

# THE wallet iterate loop: run after any wallet code change to see it on the emulator. Boots an
# emulator first if none is connected. The debug build permits cleartext to any host, so no
# per-host network-config edits are needed (decision W8).
# Build + install + launch the wallet (debug) on the emulator
wallet: emulator
    #!/usr/bin/env bash
    set -euo pipefail
    echo "==> Building + installing the wallet (debug)"
    ( cd wallet && ./gradlew installDebug )
    echo "==> Launching com.tcc.wallet"
    adb shell am start -n com.tcc.wallet/.MainActivity >/dev/null
    echo "==> Wallet updated on the emulator."

# Use when resource changes don't show up because Gradle's up-to-date cache served a stale
# APK — does a clean uninstall + reinstall.
# Force a clean wallet reinstall, then launch
wallet-fresh: emulator
    #!/usr/bin/env bash
    set -euo pipefail
    adb uninstall com.tcc.wallet >/dev/null 2>&1 || true
    ( cd wallet && ./gradlew clean :app:installDebug )
    adb shell am start -n com.tcc.wallet/.MainActivity >/dev/null
    echo "==> Wallet freshly reinstalled on the emulator."

# Seeded students: Alice 2020000001, Bob 2020000002. Grant: pre_authorized (default) | authorization_code.
# Mint a credential offer (admin) — usage: `just offer` · `just offer 2020000002` · `just offer 2020000001 authorization_code`
offer student='2020000001' grant='pre_authorized':
    #!/usr/bin/env bash
    set -euo pipefail
    resp=$(curl -fsS -u {{admin}} -X POST "{{issuer}}/credential-offer" \
        -H 'content-type: application/json' \
        -d '{"student_number":"{{student}}","grant":"{{grant}}"}')
    echo "$resp" | { command -v python3 >/dev/null 2>&1 && python3 -m json.tool || cat; }
    link=$(printf '%s' "$resp" | grep -oP '"openid_link"\s*:\s*"\K[^"]+' || true)
    [ -n "$link" ] && { echo; echo "openid_link (paste into the wallet's \"Offer link or JSON\"):"; echo "$link"; } || true

# Mint an offer and render its openid_link as a scannable QR in the terminal (needs `qrencode`)
# — point the wallet's "Scan QR" (Receive) at it. The presentation-request QR is rendered by
# the browser verifier itself (`just verifier`). usage: `just offer-qr` · `just offer-qr 2020000002`
offer-qr student='2020000001' grant='pre_authorized':
    #!/usr/bin/env bash
    set -euo pipefail
    command -v qrencode >/dev/null 2>&1 || { echo "qrencode not found — install it (e.g. \`sudo pacman -S qrencode\`)" >&2; exit 1; }
    resp=$(curl -fsS -u {{admin}} -X POST "{{issuer}}/credential-offer" \
        -H 'content-type: application/json' \
        -d '{"student_number":"{{student}}","grant":"{{grant}}"}')
    link=$(printf '%s' "$resp" | grep -oP '"openid_link"\s*:\s*"\K[^"]+' || true)
    [ -n "$link" ] || { echo "no openid_link in response: $resp" >&2; exit 1; }
    echo "$link"; echo
    qrencode -t ANSIUTF8 "$link"

# Like `offer-qr` but for the OID4VCI authorization-code flow (browser SSO + PKCE): the wallet
# scans this, then opens a Custom Tab to the mock IdP — log in with alice/alice (or bob/bob).
# usage: `just offer-qr-auth` · `just offer-qr-auth 2020000002`
offer-qr-auth student='2020000001':
    @just offer-qr {{student}} authorization_code

# Revoke an issued credential by its jti — usage: `just revoke <JTI>` (get one from `just credentials`)
revoke jti:
    curl -fsS -u {{admin}} -X POST "{{issuer}}/admin/credentials/{{jti}}/revoke" -w 'HTTP %{http_code}\n'

# Revoke the most recently issued credential (convenience wrapper over `just revoke`)
revoke-last:
    #!/usr/bin/env bash
    set -euo pipefail
    jti=$(just last-jti)
    [ -n "$jti" ] || { echo "no issued credentials found (issue one with \`just offer\` and receive it)" >&2; exit 1; }
    echo "==> Revoking latest credential: $jti"
    just revoke "$jti"

# Print the jti of the most recently issued credential (helper for scripting)
last-jti:
    @docker compose exec -T -e PGPASSWORD=issuer postgres \
        psql -U issuer -d issuer_backend -tAc \
        "select jti from issued_credentials order by issued_at desc limit 1;" | tr -d '[:space:]'

# List issued credentials (jti · student · status index · issued · revoked) from the DB
credentials:
    @docker compose exec -T -e PGPASSWORD=issuer postgres \
        psql -U issuer -d issuer_backend -c \
        "select c.jti, s.student_number, c.status_index, c.issued_at, c.revoked_at from issued_credentials c join students s on s.id = c.student_id order by c.issued_at desc;"

# Open the verifier (the browser app served by the relay) in Firefox
verifier:
    #!/usr/bin/env bash
    set -euo pipefail
    url="{{relay}}/"
    if ! curl -s -o /dev/null --max-time 2 "$url"; then
        echo "⚠️  relay not reachable at $url — start the backend with \`just deploy\` first" >&2
    fi
    echo "==> Opening $url in Firefox"
    nohup firefox "$url" >/dev/null 2>&1 &
    disown 2>/dev/null || true

# Probe the running backend (issuer health · relay · the CORS header the browser verifier needs)
health:
    #!/usr/bin/env bash
    set -uo pipefail
    echo "issuer  {{issuer}}/health  -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 3 {{issuer}}/health || echo DOWN)"
    echo "relay   {{relay}}/         -> $(curl -s -o /dev/null -w '%{http_code}' --max-time 3 {{relay}}/ || echo DOWN)"
    printf 'CORS on status-list       -> '
    curl -s -D - -o /dev/null --max-time 3 {{issuer}}/status-lists/diploma-2026 | grep -i access-control-allow-origin | tr -d '\r' || echo '(none — issuer down?)'
