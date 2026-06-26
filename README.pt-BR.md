[English](README.md) · **Português**

# SSI para Diplomas Acadêmicos — emissor · verificador · carteira

Um sistema de **Identidade Auto-Soberana (SSI)** que emite diplomas acadêmicos como
**Credenciais Verificáveis** e os verifica — desenvolvido como Trabalho de Conclusão de
Curso (TCC, UFSC). Ele implementa por completo o triângulo titular ↔ emissor ↔ verificador
sobre padrões abertos: diplomas são emitidos como **SD-JWT VCs** sobre **OID4VCI**, guardados
em uma carteira móvel e apresentados sobre **OID4VP 1.0** com divulgação seletiva.

O motor criptográfico é escrito uma única vez em Rust (`ssi-core`) e reaproveitado em todos os
lugares — nativamente no emissor, compilado para **WebAssembly** no verificador em navegador e
reimplementado em Kotlin para a carteira, com um oráculo de conformidade que prova que as duas
portas são byte a byte compatíveis.

## Componentes

| Componente | Onde | O que é |
|-----------|-------|------------|
| **Emissor** | `src/`, crate raiz `issuer_backend` | Emite diplomas como SD-JWT VCs sobre **OID4VCI**, com identidade `did:web` e revogação via IETF Token Status List (axum + sqlx + PostgreSQL). |
| **`ssi-core`** | `crates/ssi-core` | O motor SSI compartilhado — JWS (EdDSA + ES256), SD-JWT, DCQL, OID4VP, status lists, `did:web`. Nativo **e** WebAssembly. |
| **Verificador** | `crates/verifier-wasm` + `web/` | Um verificador **OID4VP 1.0** universal cuja criptografia roda **inteiramente no navegador** (WASM), interligado às carteiras por um relay de transporte simplório (`crates/relay`). |
| **Carteira** | `wallet/` (Kotlin/Android) | O **titular**: recebe credenciais sobre OID4VCI, as armazena e as apresenta sobre OID4VP. Seu motor é uma porta em Kotlin puro do `ssi-core`, comprovadamente byte a byte compatível pelo oráculo em `crates/wallet-core`. Veja [`wallet/README.md`](wallet/README.pt-BR.md). |

## Dependências

Para compilar e executar o backend (emissor + verificador + relay) e a suíte de testes em Rust:

- **Rust** (stable, edition 2024) + `cargo`
- **Docker** + Docker Compose — executa o PostgreSQL 16 (o único datastore)
- **`wasm-pack`** — compila o pacote WebAssembly do verificador em navegador
- **[`just`](https://github.com/casey/just)** — executor de tarefas para todas as receitas abaixo
- *Opcional:* `qrencode` (QR codes no terminal para ofertas), `curl`, `python3`, um navegador

Para compilar e executar a **carteira** você precisa adicionalmente de um **JDK 17** e do
**Android SDK** (+ um emulador). O motor em Kotlin puro e seus testes rodam **somente com um
JDK** — sem necessidade da stack Android.

> **As instruções de instalação de tudo isso estão em [`docs/INSTALL.md`](docs/INSTALL.pt-BR.md).**

## Início rápido — implantar e usar

```sh
just deploy        # Postgres + verificador WASM + emissor + relay, tudo em segundo plano
```

Isso detecta automaticamente um IP da LAN, compila o verificador WASM, sobe o emissor
(`:8080`) e o app de relay/verificador (`:8090`) e aguarda até que ambos estejam saudáveis.
Os logs vão para `.dev-logs/`; pare tudo com `just teardown`.

Em seguida, emita e apresente um diploma:

```sh
just offer-qr      # gera uma oferta de credencial para um aluno semeado, como QR no terminal
just verifier      # abre o verificador em navegador (servido pelo relay) para solicitar uma apresentação
```

Escaneie o QR da oferta com a carteira (`just wallet` a compila/instala em um emulador —
veja [`wallet/README.md`](wallet/README.pt-BR.md)) para receber o diploma e, então, escaneie o
QR de requisição do verificador para apresentá-lo. Auxiliares administrativos úteis:
`just credentials` (lista as emitidas), `just revoke <jti>` / `just revoke-last`,
`just health`. Execute `just --list` para o conjunto completo.

> **Sem carteira/emulador?** Você pode ver um SD-JWT de diploma sem banco de dados nem celular:
> `cargo run -- issue-test` imprime uma credencial de exemplo offline.

## Executando os testes

O sistema inteiro é testado ao longo do workspace cargo somado à suíte da carteira em Kotlin.
**Um único comando executa tudo:**

```sh
just test          # workspace Rust + testes do emissor com banco + clippy + conformidade Kotlin
```

Esta é a verificação canônica de "quebrei alguma coisa?": ela inicia o Postgres, define
`TEST_DATABASE_URL`, executa toda a suíte Rust e o clippy, e reexecuta o oráculo de
conformidade Kotlin.

Limite a uma área específica com as receitas subjacentes (`just --list`):

| Receita | Banco? | Cobre |
|--------|-----------|--------|
| `just test-rust` | não | Todo o workspace Rust: unidades do motor, fluxo completo emitir→apresentar→validar (EdDSA + ES256), modos de falha de revogação / replay / adulteração, E2E do verificador via relay, interop emissor↔verificador. |
| `just test-db` | **sim** | Integração OID4VCI do emissor (fluxos pré-autorizado + código de autorização → token → credencial → verificar → revogar) e o E2E HTTP de ponta a ponta. Pula de forma limpa sem `TEST_DATABASE_URL`. |
| `just clippy` | não | Lint ao longo do workspace (mantido livre de avisos). |
| `just test-wallet` | não | Suíte da carteira Kotlin + o oráculo de conformidade entre linguagens. |

### Demonstrações narradas do protocolo

Dois testes imprimem a troca completa do protocolo passo a passo — a melhor forma de *ver* cada
fluxo:

```sh
# OID4VP — verificador solicitando e validando uma apresentação (sem banco de dados)
cargo test -p relay --test walkthrough -- --nocapture

# OID4VCI — emissor emitindo uma credencial (precisa de banco de dados)
TEST_DATABASE_URL=postgres://issuer:issuer@localhost:5432/issuer_backend \
  cargo test -p issuer_backend --test walkthrough -- --nocapture
```

## Configuração

O emissor lê `config/default.toml`, sobrescrevível por variáveis de ambiente `ISSUER__*`
(p. ex. `ISSUER__DATABASE_URL=...`, `ISSUER__ISSUER_URL=...`). Por padrão, escuta em
`http://localhost:8080`.

## Nota de segurança

Isto é um **protótipo**. A chave de assinatura do emissor é armazenada **em texto plano** sob
`keys/`, e o SSO da universidade é um IdP simulado — ambos aceitáveis apenas para um TCC. Uma
implantação em produção deve usar um KMS/HSM para a chave de assinatura e integrar o SSO
institucional real.
