[English](INSTALL.md) · **Português**

# Instalando a toolchain

Como preparar um ambiente local para compilar, testar e executar este sistema. Os comandos são
mostrados para **Arch Linux** (`pacman`); em outras distribuições, instale os pacotes
equivalentes pelo seu gerenciador de pacotes ou pelos instaladores upstream indicados abaixo.

Há dois níveis:

1. **Backend + testes Rust** — emissor, verificador em navegador, relay e toda a suíte Rust.
   É tudo o que você precisa para o `just deploy` e para a metade Rust do `just test`.
2. **Carteira** — o titular em Kotlin/Android, que adicionalmente precisa de um JDK e do
   Android SDK.

---

## 1. Backend + testes Rust

### Rust (stable, edition 2024)

```sh
sudo pacman -S --needed rustup
rustup default stable
```

Ou use o instalador upstream em <https://rustup.rs>. O workspace usa a edition 2024 do Rust,
então é necessária uma toolchain stable recente.

### Docker + Docker Compose

```sh
sudo pacman -S --needed docker docker-compose
sudo systemctl enable --now docker.service
sudo usermod -aG docker "$USER"     # faça logout/login para que isso tenha efeito
```

O PostgreSQL 16 roda como um container (`docker-compose.yml`); ele é o único datastore.
`just db-up` / `just deploy` o iniciam para você.

### wasm-pack

Compila o motor do verificador para WebAssembly para o app em navegador.

```sh
cargo install wasm-pack
```

### just

O executor de tarefas para cada receita no README (`just deploy`, `just test`, …).

```sh
sudo pacman -S --needed just
```

### Auxiliares opcionais

```sh
sudo pacman -S --needed qrencode    # renderiza QR codes de oferta de credencial no terminal
```

`curl`, `python3` e um navegador (a receita `just verifier` abre o Firefox) também são usados
por algumas receitas de conveniência, mas não são necessários para os fluxos principais.

### Verificar

```sh
cargo run -- issue-test     # imprime um SD-JWT de diploma de exemplo, sem banco de dados
just test-rust              # a suíte Rust completa (sem banco de dados)
just deploy                 # sobe Postgres + verificador + emissor + relay
just teardown               # os encerra novamente
```

---

## 2. Carteira (Kotlin/Android)

Necessária apenas para compilar e executar o titular móvel. O motor SSI em Kotlin puro e seus
testes compilam **apenas com um JDK** — você pode rodar `just test-wallet` sem a stack Android
completa.

| Ferramenta | Por quê | Instalar (Arch) |
|------|-----|----------------|
| **JDK 17** | O Kotlin compila para bytecode da JVM; a build Android precisa dele. | `pacman -S jdk17-openjdk` |
| **Android Studio** | IDE que embute o gerenciador de SDK, o emulador e o Gradle. | AUR `android-studio`, JetBrains Toolbox ou o tarball oficial |
| **Android SDK 34 + Platform-Tools + uma imagem de emulador** | Compilar e executar o APK. | Primeira execução do Android Studio → SDK Manager |

Uma vez instalado o Android Studio, **abra a pasta `wallet/`** — ele sincroniza o Gradle e cria
o Gradle wrapper automaticamente. Pela CLI, você pode em vez disso instalar o Gradle
(`pacman -S gradle`) e rodar `gradle wrapper` uma vez para gerar o `./gradlew`. Garanta que
`adb` e `emulator` estejam no seu `PATH` para as receitas `just wallet` / `just emulator`.

Os detalhes completos — incluindo como rodar o oráculo de conformidade apenas com um JDK — estão
em [`../wallet/README.md`](../wallet/README.pt-BR.md).

### Verificar

```sh
just test-wallet            # suíte Kotlin + oráculo de conformidade entre linguagens (só JDK)
just wallet                 # compila + instala + executa em um emulador (precisa do SDK)
```
