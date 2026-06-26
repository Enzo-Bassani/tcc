**English** · [Português](INSTALL.pt-BR.md)

# Installing the toolchain

How to set up a local environment to build, test, and run this system. Commands are
shown for **Arch Linux** (`pacman`); on other distributions install the equivalent
packages from your package manager or the upstream installers linked below.

There are two tiers:

1. **Backend + Rust tests** — issuer, browser verifier, relay, and the whole Rust
   suite. This is all you need for `just deploy` and `just test`'s Rust half.
2. **Wallet** — the Kotlin/Android holder, which additionally needs a JDK and the
   Android SDK.

---

## 1. Backend + Rust tests

### Rust (stable, edition 2024)

```sh
sudo pacman -S --needed rustup
rustup default stable
```

Or use the upstream installer from <https://rustup.rs>. The workspace uses Rust
edition 2024, so a recent stable toolchain is required.

### Docker + Docker Compose

```sh
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker.service
sudo usermod -aG docker "$USER"     # log out/in for this to take effect
```

PostgreSQL 16 runs as a container (`docker-compose.yml`); it is the only datastore.
`just db-up` / `just deploy` start it for you.

### wasm-pack

Builds the verifier engine to WebAssembly for the browser app.

```sh
cargo install wasm-pack
```

### just

The task runner for every recipe in the README (`just deploy`, `just test`, …).

```sh
sudo pacman -S --needed just
```

### Optional helpers

```sh
sudo pacman -S --needed qrencode    # render credential-offer QR codes in the terminal
```

`curl`, `python3`, and a browser (the `just verifier` recipe opens Firefox) are also
used by some convenience recipes but are not required for the core flows.

### Verify

```sh
cargo run -- issue-test     # prints a sample diploma SD-JWT, no database needed
just test-rust              # the full Rust suite (no DB required)
just deploy                 # brings up Postgres + verifier + issuer + relay
just teardown               # stops them again
```

---

## 2. Wallet (Kotlin/Android)

Only needed to build and run the mobile holder. The pure-Kotlin SSI engine and its
tests build with **just a JDK** — you can run `just test-wallet` without the full
Android stack.

| Tool | Why | Install (Arch) |
|------|-----|----------------|
| **JDK 17** | Kotlin compiles to JVM bytecode; the Android build needs it. | `pacman -S jdk17-openjdk` |
| **Android Studio** | IDE bundling the SDK manager, emulator, and Gradle. | AUR `android-studio`, JetBrains Toolbox, or the official tarball |
| **Android SDK 34 + Platform-Tools + an emulator image** | Compile and run the APK. | First launch of Android Studio → SDK Manager |

Once Android Studio is installed, **open the `wallet/` folder** — it syncs Gradle and
creates the Gradle wrapper automatically. From the CLI you can instead install Gradle
(`pacman -S gradle`) and run `gradle wrapper` once to generate `./gradlew`. Make sure
`adb` and `emulator` are on your `PATH` for the `just wallet` / `just emulator`
recipes.

Full details — including how to run the conformance oracle with only a JDK — are in
[`../wallet/README.md`](../wallet/README.md).

### Verify

```sh
just test-wallet            # Kotlin suite + cross-language conformance oracle (JDK only)
just wallet                 # build + install + launch on an emulator (needs the SDK)
```
