[English](README.md) · **Português**

# Carteira do TCC — o titular

O **titular móvel** do [sistema de diplomas SSI](../README.pt-BR.md): um app Kotlin/Android que
recebe diplomas acadêmicos como **Credenciais Verificáveis SD-JWT** sobre **OID4VCI**, as
armazena no dispositivo e as apresenta sobre **OID4VP 1.0** com divulgação seletiva. É o terceiro
vértice do triângulo titular ↔ emissor ↔ verificador — a única parte que de fato detém a
credencial e a chave do titular que a vincula.

Seu motor SSI é o próprio `ssi-core` em Rust, carregado no celular por meio de uma fachada
**UniFFI** (`crates/wallet-ffi`) — não há porta separada em Kotlin, então a carteira emite
exatamente os mesmos bytes de fio que o emissor e o verificador por construção. Um oráculo de
conformidade entre linguagens (`crates/wallet-core`) ainda guarda a costura que ele pode quebrar
— a fronteira FFI e a casca do app em Kotlin: uma apresentação construída pela carteira precisa
fazer o verificador *real* em Rust reportar `valid == true`, ou a build falha.

## Dois módulos

O projeto é dividido de modo que a lógica SSI possa ser testada **sem um emulador** — a camada
`:ssi` não tem dependências do Android e roda em um JDK comum (sobre a build de host do motor
nativo).

| Módulo | Stack | O que é |
|--------|-------|------------|
| **`:ssi`** | Kotlin/JVM (sem Android) | A camada SSI voltada ao app: a interface `SsiEngine` + `RustSsiEngine` (o vínculo UniFFI com o `ssi-core`), os auxiliares de chave do titular e de codificação ES256, e os clientes de protocolo — o cliente de emissão OID4VCI, o apresentador OID4VP, o parsing de link de oferta e o roteamento de leitura. A criptografia **não** está aqui; ela vive em Rust. Compila e testa com **JDK + `cargo`** (para compilar a biblioteca FFI do host que o oráculo carrega). |
| **`:app`** | Android (Jetpack Compose) | A casca de celular que envolve o `:ssi`: a UI Compose, leitura de QR, armazenamento no dispositivo, a chave do titular com respaldo em hardware, o encanamento de deep links/redirecionamentos e a `libwallet_ffi.so` por ABI sob `jniLibs/`. Depende do `:ssi`. |

A criptografia vive em Rust (`ssi-core`, alcançado via UniFFI); o `:ssi` é a cola Kotlin e os
clientes de protocolo, e o `:app` apenas adiciona o celular — chaves em hardware seguro, uma
câmera, um arquivo e uma tela.

## O que ela faz

### Recebendo um diploma — OID4VCI 1.0

O `Oid4vciClient` conduz o handshake de emissão (descoberta → token → nonce → credencial) e
devolve o SD-JWT VC compacto para ser armazenado. Ambos os grants do OID4VCI são suportados:

- **Código pré-autorizado** — uma única ida e volta; o QR da oferta carrega o código, sem
  necessidade de navegador.
- **Código de autorização** — uma ida e volta pelo navegador até o `/authorize` do emissor → SSO
  universitário simulado, com **PKCE S256** e uma verificação de mix-up de `iss` da RFC 9207.
  Dividido ao longo da viagem pelo navegador: a carteira abre uma Chrome Custom Tab e retoma no
  redirecionamento `com.tcc.wallet://oid4vci`.

A prova de vínculo com o titular (`openid4vci-proof+jwt`) é assinada pela chave do dispositivo,
de modo que sua JWK pública se torna o `cnf` da credencial. Uma credencial recebida é **validada
antes de ser sequer armazenada** (veja [Confiança no emissor](#confiança-no-emissor-no-recebimento)
abaixo) — uma credencial não confiável é rejeitada, nunca persistida.

### Apresentando um diploma — OID4VP 1.0

O `Oid4vpPresenter` responde à requisição de um verificador sobre o relay de transporte deste
repositório. A Authorization Request assinada chega **por valor no QR**
(`openid4vp://?client_id=<did:jwk>&request=<JAR JWT>`), de modo que a carteira:

1. verifica a assinatura do **JAR did:jwk** da requisição contra o `client_id` do QR (sua âncora
   de confiança);
2. resolve quais credenciais detidas satisfazem a consulta **DCQL** e quais claims cada uma
   divulgaria;
3. constrói o **VP Token** — selecionando apenas as divulgações solicitadas e anexando um JWT de
   key-binding vinculado ao nonce, à audiência e ao `sd_hash` do verificador;
4. **criptografa em JWE** a resposta para a chave efêmera do verificador (`direct_post.jwt`) e faz
   POST do texto cifrado opaco para o `response_uri` da requisição.

A tela de consentimento mostra tanto o que o verificador pediu explicitamente **quanto** os claims
assinados pelo emissor que viajam com toda apresentação e não podem ser retidos (o tipo da
credencial, o emissor, a janela de validade, o ponteiro de revogação, o key-binding), de modo que
o titular veja a divulgação completa antes de compartilhar.

### Confiança no emissor no recebimento

A verificação de confiança é o lado da carteira no modelo `x5c` do HAIP §6.1.1, executada pelo
`issuer_trust` do `ssi-core` através da FFI — a mesma lógica que o verificador usa. Antes de uma
credencial (ou metadados de emissor assinados) ser aceita, ela precisa: carregar uma cadeia
`x5c`, verificar sua assinatura **ES256** sob o certificado folha, encadear até uma raiz confiável
mantida localmente (folha-não-CA, sem certificado autoassinado no `x5c`) e vincular seu claim
`iss` à folha. A âncora embutida é a raiz simulada da **ICP-Brasil** — o mesmo padrão que o
verificador usa.

### A chave do titular

Uma chave **ES256 (P-256)** — a linha de base do HAIP §7, e o algoritmo que o Android Keystore
consegue respaldar em hardware. A interface `HolderKey` é a costura entre o material da chave e o
protocolo (os chamadores só precisam de `sign` e `publicJwk`), e a chave permanece inteiramente do
lado Kotlin da FFI: o motor assina através de um callback `ForeignSigner` (`KotlinHolderSigner`),
de modo que o escalar privado nunca cruza para o Rust. Dois respaldos:

- **`KeystoreHolderKey`** (`:app`) — gerada **não exportável** no Android Keystore,
  **com preferência por StrongBox** e fallback para TEE. O escalar privado nunca deixa o hardware
  seguro; é isso que vai na carteira e dá a garantia de vínculo com o dispositivo do ARF/EUDI.
- **`SoftwareHolderKey`** (`:ssi`) — uma chave BouncyCastle com o escalar em memória, usada pelo
  oráculo de conformidade e em qualquer lugar que precise rodar em um JDK comum.

Ambas emitem assinaturas JOSE `R‖S` puras idênticas (transcodificadas do DER via Nimbus), de modo
que um token assinado pelo Keystore verifica exatamente como um assinado por software.

## A UI

Um app **Jetpack Compose** de atividade única. Toda a interface — lista inicial, detalhe da
credencial, as folhas de recebimento e apresentação, leitor de QR e o visualizador de JSON bruto —
é conduzida inteiramente pelos fluxos reais do `:ssi` através de um único `WalletViewModel`; nada é
simulado.

- **A leitura de QR** usa CameraX com o decodificador de código de barras **embutido** do ML Kit
  (sem dependência do Google Play Services).
- **O armazenamento** é deliberadamente mínimo: a lista de strings SD-JWT em um arquivo JSON
  privado (`WalletStore`). A chave do titular *não* está nesse arquivo — ela mora no Keystore.
- **Os pontos de entrada** são unificados: um QR escaneado, um link colado ou um deep link
  (`openid-credential-offer://`, `openid4vp://`) é classificado pelo `ScanDispatch` e roteado
  automaticamente para emissão ou apresentação.

## Compilando e testando

A toolchain (JDK 17, Android SDK, um emulador, mais o NDK + `cargo-ndk` para o motor nativo) é
coberta em [`../docs/INSTALL.md`](../docs/INSTALL.pt-BR.md). Todas as receitas rodam a partir da
**raiz do protótipo** (`cd ..`):

| Receita | Precisa | O que faz |
|--------|-------|--------------|
| `just wallet-ffi-host` | `cargo` | Compila a `libwallet_ffi` do host + gera os bindings UniFFI em Kotlin — o pré-requisito para o teste de conformidade do `:ssi` numa JVM comum. |
| `just wallet-ffi-android` | NDK + `cargo-ndk` + alvos rustup | Compila `libwallet_ffi.so` para arm64 + x86_64 em `app/src/main/jniLibs/` e regenera os bindings — o pré-requisito para o APK. |
| `just test-wallet` | JDK + `cargo` | Compila a lib FFI do host e então roda a suíte `:ssi` — os testes unitários em Kotlin puro (parsing de link de oferta, código de autorização OID4VCI, roteamento de leitura) **e** o oráculo de conformidade entre linguagens sobre o motor UniFFI. |
| `just wallet` | JDK + Android SDK + emulador + NDK | Compila + instala + executa o app em um emulador (sobe um se nenhum estiver conectado). Compile o motor nativo antes com `just wallet-ffi-android`. A receita do laço de iteração. |
| `just wallet-fresh` | JDK + Android SDK + emulador + NDK | Reinstalação limpa, depois executa. |
| `just emulator` | Android SDK | Sobe um emulador (idempotente). |

O teste de conformidade invoca o `cargo` para conduzir a CLI `wallet-conformance` em Rust **e**
carrega a `libwallet_ffi` do host via JNA; se o `cargo` não estiver no `PATH` ou a lib do host não
tiver sido compilada, ele é **pulado, não falhado**, de modo que o `:ssi` ainda compila em uma
máquina sem o workspace Rust. Os testes unitários em Kotlin puro sempre rodam. O `just test-wallet`
também está dobrado dentro do `just test` de nível superior.

A mesma ida e volta do motor roda puramente em Rust como `cargo test -p wallet-ffi` (sem Kotlin,
sem Android). O único caminho que os testes de host não cobrem — carregar a lib nativa
**no dispositivo** e assinar com uma chave do AndroidKeyStore através do callback `ForeignSigner` —
é o teste instrumentado `RustEngineInstrumentedTest` em `:app` (precisa de emulador/dispositivo e
dos `jniLibs` compilados).

### Veja um fluxo completo de ponta a ponta

Suba o backend e gere uma oferta, depois conduza o celular:

```sh
cd ..
just deploy               # Postgres + verificador WASM + emissor + relay
just offer-qr             # um QR de oferta de credencial para um aluno semeado
just wallet-ffi-android   # compila o motor nativo em jniLibs (uma vez)
just wallet               # compila + executa a carteira em um emulador
```

Escaneie o QR da oferta (Receber) para obter o diploma, depois `just verifier` e escaneie seu QR
de requisição (Apresentar) para compartilhá-lo. A build de debug permite texto não cifrado para
qualquer host, então o emulador conversa com o backend no IP da LAN sem configuração extra.

## Um motor, sobre UniFFI

A carteira costumava carregar uma porta manual em Kotlin do `ssi_core::wallet_sim`, mantida honesta
pelo oráculo de conformidade. Essa porta se foi: o `RustSsiEngine` agora vincula o motor Rust
compartilhado diretamente via **UniFFI** (`crates/wallet-ffi`, uma fachada fina sobre o
`wallet_sim` mais os auxiliares de holder e de confiança no emissor), de modo que o celular roda o
exato código de SD-JWT / JWS / JWE / DCQL / `x5c` do emissor e do verificador. A compatibilidade
de fio é, portanto, por construção em vez de por testes de paridade.

A interface `SsiEngine` permanece como a costura entre o app e o motor, de modo que o respaldo
poderia ser trocado de novo sem tocar no app. A chave do titular deliberadamente permanece do lado
Kotlin — a assinatura é um callback `ForeignSigner` (`KotlinHolderSigner` sobre `HolderKey`), de
modo que a chave não exportável do Keystore nunca cruza a FFI. O que o oráculo agora guarda é essa
fronteira e a casca do app em Kotlin, não uma segunda implementação.

## Nota de segurança

Isto é um **protótipo** para um TCC. A chave do titular é devidamente respaldada em hardware e não
exportável, mas a âncora de confiança é uma **raiz simulada da ICP-Brasil**, o SSO do emissor é um
IdP simulado e o estado pendente de código de autorização é mantido em memória (não persistido
através da morte do processo). Uma carteira em produção se ancoraria na PKI nacional real e
integraria o SSO efetivo da instituição. Veja o [README do sistema](../README.pt-BR.md#nota-de-segurança)
para as ressalvas equivalentes do backend.
