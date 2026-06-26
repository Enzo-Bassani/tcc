# TCC Wallet (Kotlin/Android)

The **holder** of the SSI triangle: receives credentials from the issuer over
**OID4VCI**, stores them and the holder key that binds them, and presents them to
the verifier over **OID4VP 1.0** — disclosing only what is asked. It is built to be
byte-for-byte compatible with this repo's issuer and verifier.

> **First Android/Kotlin project?** Read "Toolchain" then "Run the tests" below —
> you can see the core working with **only a JDK + Gradle**, before installing the
> full Android stack.

## Layout

```
wallet/
├── ssi/   ← pure Kotlin/JVM SSI engine + protocol clients. NO Android deps, so it
│           builds and tests with just a JDK. This is the compatibility-critical code.
│   ├── src/main/kotlin/com/tcc/wallet/ssi/        Bytes, HolderKey, Jws, SdJwt, Dcql,
│   │     SsiEngine, KotlinSsiEngine, net/{Http,Oid4vciClient,Oid4vpPresenter,OfferLink}
│   └── src/test/kotlin/com/tcc/wallet/ssi/        EngineUnitTest, ConformanceTest
└── app/   ← the thin Android shell (Jetpack Compose UI, key/credential storage) on top of :ssi
```

The engine is the same idea as Rust `ssi-core`: framework-agnostic and reusable.
The Android-specific bits (UI, storage, deep links) live only in `:app`.

## How compatibility is guaranteed

The engine logic is a faithful port of the reference holder `ssi_core::wallet_sim`.
The guard against drift is the Rust **conformance oracle** in
[`../crates/wallet-core`](../crates/wallet-core): `ConformanceTest` (in `:ssi`)
generates a holder key, asks the oracle to `mint` a credential bound to it, builds
a VP Token with the Kotlin engine, and asks the oracle to `verify` it with the
**real** `ssi_core::oid4vp::validate_vp_token`. Green = the wallet is compatible.
(This has already been run during development — the Kotlin VP Token verifies
`valid == true`, and a revoked credential is correctly rejected.)

---

## Toolchain — what to install

| Tool | Why | Install (Arch) |
|------|-----|----------------|
| **JDK 17** | Kotlin compiles to JVM bytecode; the Android build needs it. | `pacman -S jdk17-openjdk` |
| **Android Studio** | The IDE; bundles the SDK manager, the emulator, and Gradle. | AUR `android-studio`, JetBrains Toolbox, or the official tarball |
| **Android SDK 34 + Platform-Tools + an emulator image** | Compile the APK; run it. | First launch of Android Studio → SDK Manager |
| **Rust + cargo** | Only to run the cross-language `ConformanceTest` (already in this repo). | already installed here |

Once Android Studio is installed, **open the `wallet/` folder** — it will sync
Gradle automatically and create the Gradle wrapper. From the CLI you can instead
install Gradle (`pacman -S gradle`) and run `gradle wrapper` once to generate
`./gradlew`.

> The version catalog (`gradle/libs.versions.toml`) pins a known-good AGP 8.5.2 /
> Kotlin 2.0.20 / compileSdk 34 baseline. If Android Studio's AGP Upgrade Assistant
> offers newer versions, accepting them is fine.

---

## Run the tests

The SSI engine tests need **no Android SDK and no device** — `:ssi` is a plain JVM
module:

```sh
cd wallet
./gradlew :ssi:test            # engine unit tests + the Rust conformance oracle
```

`ConformanceTest` shells out to `cargo` (this repo's `wallet-core`). If `cargo`
isn't on `PATH` it is **skipped**, not failed. `EngineUnitTest` always runs.

The Rust side has its own copy of the loop (no Kotlin needed):

```sh
cargo test -p wallet-core      # mint → wallet_sim → verify, + revoked/tampered cases
```

---

## Build & run the app

```sh
cd wallet
./gradlew assembleDebug        # → app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug         # build + install onto a running emulator/phone
```

Or just press **Run ▶** in Android Studio with an emulator/device selected.

### Networking — read this, it bites immediately
The app talks to the issuer (`:8080`) and relay (`:8090`) running on your dev host.

- **Emulator:** the host is reachable at **`10.0.2.2`**, not `localhost`. Start the
  services so their advertised URLs use it:
  ```sh
  ISSUER__ISSUER_URL=http://10.0.2.2:8080 ISSUER__BIND_ADDR=0.0.0.0:8080 cargo run
  RELAY_BIND=0.0.0.0:8090 RELAY_BASE_URL=http://10.0.2.2:8090 cargo run -p relay
  ```
- **Physical phone:** use your host's **LAN IP** everywhere instead of `10.0.2.2`.
  No network-config edit is needed — the debug build permits cleartext to any host
  (dev-only — see decision W8).

---

## End-to-end demo (emulator)

1. Start Postgres + issuer + relay (with the `10.0.2.2` env vars above) and build the
   verifier demo: `wasm-pack build crates/verifier-wasm --target web --out-dir ../../web/pkg`, then `cargo run -p relay` serves it on `:8090`.
2. **Issue:** mint an offer and copy its `openid_link`:
   ```sh
   curl -u admin:admin -X POST http://localhost:8080/credential-offer \
     -H 'content-type: application/json' \
     -d '{"student_number":"2020000001","grant":"pre_authorized"}'
   ```
   In the wallet, tap **Scan QR** under "Receive a credential" and scan a QR of that
   `openid_link` (e.g. `qrencode -o offer.png "<openid_link>"`), or paste it into
   **"Offer link or JSON"** → **Receive credential**.
3. **Present:** in the `web/` verifier, start a request — it renders the relay
   `request_uri` as a QR. In the wallet tap **Scan QR** under "Present a credential" and
   scan it (or copy the `request_uri` and paste it into **"Relay request_uri"**) →
   **Fetch** → review the requested claims → **Consent & present**. The verifier shows `valid`.

> QR scanning (CameraX + ML Kit) is the primary path; pasting the link or arriving via an
> `openid-credential-offer://` / `openid4vp://` deep link remain as fallbacks. The first
> scan prompts for the camera permission. For QR scanning on the **emulator**, set the AVD's
> back camera to **Webcam0** (Extended controls → Camera) and hold the QR up to your webcam;
> a physical phone pointed at the on-screen QR is simpler.
>
> On a **16 KB-page** emulator image you'll see a harmless "not 16 KB compatible" dialog —
> CameraX 1.3.4's `libimage_processing_util_jni.so` is 4 KB-aligned, so the app runs in
> page-size-compat mode. It's cosmetic (no effect on a 4 KB image or current phones); the fix
> would be CameraX ≥ 1.4.x, which requires `compileSdk ≥ 35`, deferred for this prototype.
