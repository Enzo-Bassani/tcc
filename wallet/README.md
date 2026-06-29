**English** · [Português](README.pt-BR.md)

# TCC Wallet — the holder

The **mobile holder** of the [SSI diploma system](../README.md): a Kotlin/Android app
that receives academic diplomas as **SD-JWT Verifiable Credentials** over **OID4VCI**,
stores them on the device, and presents them over **OID4VP 1.0** with selective
disclosure. It is the third corner of the holder ↔ issuer ↔ verifier triangle — the only
party that ever holds the credential and the holder key that binds it.

Its SSI engine is the Rust `ssi-core` itself, loaded on the phone through a **UniFFI**
facade (`crates/wallet-ffi`) — there is no separate Kotlin crypto port, so the wallet
emits the exact same wire bytes as the issuer and verifier by construction. A
cross-language conformance oracle (`crates/wallet-core`) still guards the seam it can
break — the FFI boundary and the Kotlin app shell: a presentation the wallet builds must
make the *real* Rust verifier report `valid == true`, or the build fails.

## Two modules

The project is split so the SSI logic can be tested **without an emulator** — the `:ssi`
layer has no Android dependencies and runs on a plain JDK (over the host build of the
native engine).

| Module | Stack | What it is |
|--------|-------|------------|
| **`:ssi`** | Kotlin/JVM (no Android) | The app-facing SSI layer: the `SsiEngine` interface + `RustSsiEngine` (the UniFFI binding to `ssi-core`), the holder-key and ES256 wire helpers, and the protocol clients — the OID4VCI issuance client, the OID4VP presenter, offer-link parsing, and scan dispatch. The crypto is **not** here; it lives in Rust. Builds and tests with a **JDK + `cargo`** (to build the host FFI lib the oracle loads). |
| **`:app`** | Android (Jetpack Compose) | The phone shell that wraps `:ssi`: the Compose UI, QR scanning, on-device storage, the hardware-backed holder key, deep-link/redirect plumbing, and the per-ABI `libwallet_ffi.so` under `jniLibs/`. Depends on `:ssi`. |

The crypto lives in Rust (`ssi-core`, reached over UniFFI); `:ssi` is the Kotlin glue and
protocol clients, and `:app` only adds the phone — keys in secure hardware, a camera, a
file, and a screen.

## What it does

### Receiving a diploma — OID4VCI 1.0

`Oid4vciClient` drives the issuance handshake (discovery → token → nonce → credential)
and hands the compact SD-JWT VC back to be stored. Both OID4VCI grants are supported:

- **Pre-authorized code** — a single round-trip; the offer QR carries the code, no
  browser needed.
- **Authorization code** — a browser round-trip to the issuer's `/authorize` → mock
  university SSO, with **PKCE S256** and an RFC 9207 `iss` mix-up check. Split across the
  browser trip: the wallet opens a Chrome Custom Tab and resumes on the
  `com.tcc.wallet://oid4vci` redirect.

The holder-binding proof (`openid4vci-proof+jwt`) is signed by the device key, so its
public JWK becomes the credential's `cnf`. A received credential is **validated before
it is ever stored** (see [Issuer trust](#issuer-trust-at-receipt) below) — an
untrustworthy credential is rejected, never persisted.

### Presenting a diploma — OID4VP 1.0

`Oid4vpPresenter` answers a verifier's request over this repo's transport relay. The
signed Authorization Request arrives **by value in the QR**
(`openid4vp://?client_id=<did:jwk>&request=<JAR JWT>`), so the wallet:

1. verifies the request's **did:jwk JAR** signature against the QR's `client_id` (its
   trust anchor);
2. resolves which held credentials satisfy the **DCQL** query, and which claims each
   would disclose;
3. builds the **VP Token** — selecting only the requested disclosures and appending a
   key-binding JWT bound to the verifier's nonce, audience, and `sd_hash`;
4. **JWE-encrypts** the response to the verifier's ephemeral key (`direct_post.jwt`) and
   POSTs the opaque ciphertext to the request's `response_uri`.

The consent screen shows both what the verifier explicitly asked for **and** the
issuer-signed claims that travel with every presentation and cannot be withheld (the
credential type, issuer, validity window, revocation pointer, key binding), so the holder
sees the full disclosure before sharing.

### Issuer trust at receipt

Trust checking is the wallet's side of the HAIP §6.1.1 `x5c` model, run by `ssi-core`'s
`issuer_trust` over the FFI — the same logic the verifier uses. Before a credential (or
signed issuer metadata) is accepted it must: carry an `x5c` chain, verify its **ES256**
signature under the leaf certificate, chain up to a locally-held trusted root
(leaf-not-CA, no self-signed cert in `x5c`), and bind its `iss` claim to the leaf. The
bundled anchor is the mock **ICP-Brasil** root — the same default the verifier uses.

### The holder key

An **ES256 (P-256)** key — the HAIP §7 baseline, and the algorithm Android Keystore can
hardware-back. The `HolderKey` interface is the seam between key material and the
protocol (callers only ever need `sign` and `publicJwk`), and the key stays entirely on
the Kotlin side of the FFI: the engine signs through a `ForeignSigner` callback
(`KotlinHolderSigner`), so the private scalar never crosses into Rust. Two backings:

- **`KeystoreHolderKey`** (`:app`) — generated **non-exportable** in the Android Keystore,
  **StrongBox-preferred** with a TEE fallback. The private scalar never leaves secure
  hardware; this is what ships in the wallet and gives the ARF/EUDI device-binding
  guarantee.
- **`SoftwareHolderKey`** (`:ssi`) — a BouncyCastle key with the scalar in memory, used by
  the conformance oracle and anywhere that must run on a plain JDK.

Both emit identical JOSE raw `R‖S` signatures (transcoded from DER via Nimbus), so a
Keystore-signed token verifies exactly like a software-signed one.

## The UI

A single-activity **Jetpack Compose** app. The whole interface — home list, credential
detail, the receive and present sheets, QR scanner, and raw-JSON viewer — is driven
entirely by the real `:ssi` flows through one `WalletViewModel`; nothing is mocked.

- **QR scanning** uses CameraX with ML Kit's **bundled** barcode decoder (no Google Play
  Services dependency).
- **Storage** is deliberately minimal: the list of SD-JWT strings in a private JSON file
  (`WalletStore`). The holder key is *not* in that file — it lives in the Keystore.
- **Entry points** are unified: a scanned QR, a pasted link, or a deep link
  (`openid-credential-offer://`, `openid4vp://`) is classified by `ScanDispatch` and routed
  to issuance or presentation automatically.

## Building and testing

The toolchain (JDK 17, Android SDK, an emulator, plus the NDK + `cargo-ndk` for the
native engine) is covered in [`../docs/INSTALL.md`](../docs/INSTALL.md). All recipes run
from the **prototype root** (`cd ..`):

| Recipe | Needs | What it does |
|--------|-------|--------------|
| `just wallet-ffi-host` | `cargo` | Build the host `libwallet_ffi` + generate the UniFFI Kotlin bindings — the prerequisite for the `:ssi` conformance test on a plain JVM. |
| `just wallet-ffi-android` | NDK + `cargo-ndk` + rustup targets | Cross-compile `libwallet_ffi.so` for arm64 + x86_64 into `app/src/main/jniLibs/` and regenerate the bindings — the prerequisite for the APK. |
| `just test-wallet` | JDK + `cargo` | Builds the host FFI lib, then runs the `:ssi` suite — the pure-Kotlin unit tests (offer-link parsing, OID4VCI auth-code, scan dispatch) **and** the cross-language conformance oracle over the UniFFI engine. |
| `just wallet` | JDK + Android SDK + emulator + NDK | Build + install + launch the app on an emulator (boots one if none is connected). Auto-builds the native engine into `jniLibs/` on first use if it's missing (a presence check — rerun `just wallet-ffi-android` yourself after a `crates/wallet-ffi` change). The iterate-loop recipe. |
| `just wallet-fresh` | JDK + Android SDK + emulator + NDK | Clean reinstall, then launch (same auto-build guard). |
| `just emulator` | Android SDK | Boot an emulator (idempotent). |

The conformance test shells out to `cargo` to drive the Rust `wallet-conformance` CLI
**and** loads the host `libwallet_ffi` over JNA; if `cargo` isn't on `PATH` or the host
lib hasn't been built it is **skipped, not failed**, so `:ssi` still builds on a machine
without the Rust workspace. The pure-Kotlin unit tests always run. `just test-wallet` is
also folded into the top-level `just test`.

The same engine round-trip runs purely in Rust as `cargo test -p wallet-ffi` (no Kotlin,
no Android). The one path the host tests can't cover — loading the native lib **on-device**
and signing with an AndroidKeyStore key through the `ForeignSigner` callback — is the
instrumented `RustEngineInstrumentedTest` in `:app` (needs an emulator/device and the
`jniLibs` built).

### See a full flow end to end

Bring up the backend and mint an offer, then drive the phone:

```sh
cd ..
just deploy               # Postgres + WASM verifier + issuer + relay
just offer-qr             # a credential-offer QR for a seeded student
just wallet               # build + launch the wallet on an emulator (auto-builds the native engine)
```

Scan the offer QR (Receive) to get the diploma, then `just verifier` and scan its request
QR (Present) to share it. The debug build permits cleartext to any host, so the emulator
talks to the LAN-IP backend without extra setup.

## One engine, over UniFFI

The wallet used to carry a hand-written Kotlin port of `ssi_core::wallet_sim`, kept honest
by the conformance oracle. That port is gone: `RustSsiEngine` now binds the shared Rust
engine directly through **UniFFI** (`crates/wallet-ffi`, a thin facade over `wallet_sim`
plus the holder and issuer-trust helpers), so the phone runs the exact SD-JWT / JWS / JWE /
DCQL / `x5c` code as the issuer and verifier. Wire-compatibility is therefore by
construction rather than by parity testing.

The `SsiEngine` interface remains as the seam between the app and the engine, so the
backing could be swapped again without touching the app. The holder key deliberately stays
on the Kotlin side — signing is a `ForeignSigner` callback (`KotlinHolderSigner` over
`HolderKey`), so the non-exportable Keystore key never crosses the FFI. What the oracle
now guards is that boundary and the Kotlin app shell, not a second implementation.

## Security note

This is a **prototype** for a TCC. The holder key is properly hardware-backed and
non-exportable, but the trust anchor is a **mock ICP-Brasil root**, the issuer's SSO is a
mock IdP, and the pending authorization-code state is kept in memory (not persisted across
process death). A production wallet would anchor at the real national PKI and integrate the
institution's actual SSO. See the [system README](../README.md#security-note) for the
backend's equivalent caveats.
