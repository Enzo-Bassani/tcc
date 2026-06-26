# TCC Wallet — the holder

The **mobile holder** of the [SSI diploma system](../README.md): a Kotlin/Android app
that receives academic diplomas as **SD-JWT Verifiable Credentials** over **OID4VCI**,
stores them on the device, and presents them over **OID4VP 1.0** with selective
disclosure. It is the third corner of the holder ↔ issuer ↔ verifier triangle — the only
party that ever holds the credential and the holder key that binds it.

Its SSI engine is a **pure-Kotlin port of the Rust `ssi-core`**, written to produce the
exact same wire bytes the native engine does. A cross-language conformance oracle
(`crates/wallet-core`) proves the two ports agree: a presentation built in Kotlin must
make the *real* Rust verifier report `valid == true`, or the build fails.

## Two modules

The project is split so the SSI logic can be tested **without an emulator** — the engine
has no Android dependencies and runs on a plain JDK.

| Module | Stack | What it is |
|--------|-------|------------|
| **`:ssi`** | Kotlin/JVM (no Android) | The framework-agnostic SSI engine + protocol clients: SD-JWT, DCQL selective disclosure, JWS/JWE, the OID4VCI issuance client, the OID4VP presenter, and `x5c` issuer-trust validation. Builds and tests with **only a JDK** — including the Rust conformance oracle. |
| **`:app`** | Android (Jetpack Compose) | The phone shell that wraps `:ssi`: the Compose UI, QR scanning, on-device storage, the hardware-backed holder key, and deep-link/redirect plumbing. Depends on `:ssi`. |

Everything cryptographic lives in `:ssi`; `:app` only adds the phone — keys in secure
hardware, a camera, a file, and a screen.

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

`IssuerTrust` is the wallet's side of the HAIP §6.1.1 `x5c` model — a mirror of the
verifier's `ssi_core::x509`. Before a credential (or signed issuer metadata) is accepted
it must: carry an `x5c` chain, verify its **ES256** signature under the leaf certificate,
chain up to a locally-held trusted root (leaf-not-CA, no self-signed cert in `x5c`), and
bind its `iss` claim to the leaf. The bundled anchor is the mock **ICP-Brasil** root —
the same default the verifier uses.

### The holder key

An **ES256 (P-256)** key — the HAIP §7 baseline, and the algorithm Android Keystore can
hardware-back. The `HolderKey` interface is the seam between key material and the
protocol (callers only ever need `sign` and `publicJwk`), with two backings:

- **`KeystoreHolderKey`** (`:app`) — generated **non-exportable** in the Android Keystore,
  **StrongBox-preferred** with a TEE fallback. The private scalar never leaves secure
  hardware; this is what ships in the wallet and gives the ARF/EUDI device-binding
  guarantee.
- **`SoftwareHolderKey`** (`:ssi`) — a BouncyCastle key with the scalar in memory, used by
  the conformance oracle and anywhere that must run on a plain JDK.

Both emit identical JOSE raw `R‖S` signatures, so a Keystore-signed token verifies exactly
like a software-signed one.

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

The toolchain (JDK 17, Android SDK, an emulator) is covered in
[`../docs/INSTALL.md`](../docs/INSTALL.md). All recipes run from the **prototype root**
(`cd ..`):

| Recipe | Needs | What it does |
|--------|-------|--------------|
| `just test-wallet` | **JDK only** | Runs the `:ssi` suite — engine units, DCQL/SD-JWT, JWE round-trips, OID4VCI client, `x5c` issuer trust, **and** the cross-language conformance oracle. |
| `just wallet` | JDK + Android SDK + emulator | Build + install + launch the app on an emulator (boots one if none is connected). The iterate-loop recipe. |
| `just wallet-fresh` | JDK + Android SDK + emulator | Clean reinstall, then launch. |
| `just emulator` | Android SDK | Boot an emulator (idempotent). |

The conformance test shells out to `cargo` to drive the Rust `wallet-conformance` CLI; if
`cargo` isn't on `PATH` it is **skipped, not failed**, so `:ssi` still builds on a machine
without the Rust workspace. `just test-wallet` is also folded into the top-level
`just test`.

### See a full flow end to end

Bring up the backend and mint an offer, then drive the phone:

```sh
cd ..
just deploy        # Postgres + WASM verifier + issuer + relay
just offer-qr      # a credential-offer QR for a seeded student
just wallet        # build + launch the wallet on an emulator
```

Scan the offer QR (Receive) to get the diploma, then `just verifier` and scan its request
QR (Present) to share it. The debug build permits cleartext to any host, so the emulator
talks to the LAN-IP backend without extra setup.

## Engine parity, and the road to Rust

`KotlinSsiEngine` is the **Phase 1** implementation — a faithful hand-port of
`ssi_core::wallet_sim`. The `SsiEngine` interface exists so the implementation can be
swapped without touching the app: a **Phase 2** `RustSsiEngine` would call `ssi-core`
directly over UniFFI for exact, no-second-port parity. The same conformance oracle guards
both, so the swap is provable rather than hoped-for.

## Security note

This is a **prototype** for a TCC. The holder key is properly hardware-backed and
non-exportable, but the trust anchor is a **mock ICP-Brasil root**, the issuer's SSO is a
mock IdP, and the pending authorization-code state is kept in memory (not persisted across
process death). A production wallet would anchor at the real national PKI and integrate the
institution's actual SSO. See the [system README](../README.md#security-note) for the
backend's equivalent caveats.
