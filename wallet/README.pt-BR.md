[English](README.md) · **Português**

# Carteira do TCC — o titular

O **titular móvel** do [sistema de diplomas SSI](../README.pt-BR.md): um app Kotlin/Android que
recebe diplomas acadêmicos como **Credenciais Verificáveis SD-JWT** sobre **OID4VCI**, as
armazena no dispositivo e as apresenta sobre **OID4VP 1.0** com divulgação seletiva. É o terceiro
vértice do triângulo titular ↔ emissor ↔ verificador — a única parte que de fato detém a
credencial e a chave do titular que a vincula.

Seu motor SSI é uma **porta em Kotlin puro do `ssi-core` em Rust**, escrita para produzir
exatamente os mesmos bytes de fio que o motor nativo produz. Um oráculo de conformidade entre
linguagens (`crates/wallet-core`) prova que as duas portas concordam: uma apresentação construída
em Kotlin precisa fazer o verificador *real* em Rust reportar `valid == true`, ou a build falha.

## Dois módulos

O projeto é dividido de modo que a lógica SSI possa ser testada **sem um emulador** — o motor não
tem dependências do Android e roda em um JDK comum.

| Módulo | Stack | O que é |
|--------|-------|------------|
| **`:ssi`** | Kotlin/JVM (sem Android) | O motor SSI agnóstico de framework + clientes de protocolo: SD-JWT, divulgação seletiva DCQL, JWS/JWE, o cliente de emissão OID4VCI, o apresentador OID4VP e a validação de confiança no emissor via `x5c`. Compila e testa **apenas com um JDK** — incluindo o oráculo de conformidade em Rust. |
| **`:app`** | Android (Jetpack Compose) | A casca de celular que envolve o `:ssi`: a UI Compose, leitura de QR, armazenamento no dispositivo, a chave do titular com respaldo em hardware e o encanamento de deep links/redirecionamentos. Depende do `:ssi`. |

Tudo o que é criptográfico mora no `:ssi`; o `:app` apenas adiciona o celular — chaves em
hardware seguro, uma câmera, um arquivo e uma tela.

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

`IssuerTrust` é o lado da carteira no modelo `x5c` do HAIP §6.1.1 — um espelho do
`ssi_core::x509` do verificador. Antes de uma credencial (ou metadados de emissor assinados) ser
aceita, ela precisa: carregar uma cadeia `x5c`, verificar sua assinatura **ES256** sob o
certificado folha, encadear até uma raiz confiável mantida localmente (folha-não-CA, sem
certificado autoassinado no `x5c`) e vincular seu claim `iss` à folha. A âncora embutida é a raiz
simulada da **ICP-Brasil** — o mesmo padrão que o verificador usa.

### A chave do titular

Uma chave **ES256 (P-256)** — a linha de base do HAIP §7, e o algoritmo que o Android Keystore
consegue respaldar em hardware. A interface `HolderKey` é a costura entre o material da chave e o
protocolo (os chamadores só precisam de `sign` e `publicJwk`), com dois respaldos:

- **`KeystoreHolderKey`** (`:app`) — gerada **não exportável** no Android Keystore,
  **com preferência por StrongBox** e fallback para TEE. O escalar privado nunca deixa o hardware
  seguro; é isso que vai na carteira e dá a garantia de vínculo com o dispositivo do ARF/EUDI.
- **`SoftwareHolderKey`** (`:ssi`) — uma chave BouncyCastle com o escalar em memória, usada pelo
  oráculo de conformidade e em qualquer lugar que precise rodar em um JDK comum.

Ambas emitem assinaturas JOSE `R‖S` puras idênticas, de modo que um token assinado pelo Keystore
verifica exatamente como um assinado por software.

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

A toolchain (JDK 17, Android SDK, um emulador) é coberta em
[`../docs/INSTALL.md`](../docs/INSTALL.pt-BR.md). Todas as receitas rodam a partir da **raiz do
protótipo** (`cd ..`):

| Receita | Precisa | O que faz |
|--------|-------|--------------|
| `just test-wallet` | **só JDK** | Roda a suíte `:ssi` — unidades do motor, DCQL/SD-JWT, idas e voltas de JWE, cliente OID4VCI, confiança no emissor via `x5c` **e** o oráculo de conformidade entre linguagens. |
| `just wallet` | JDK + Android SDK + emulador | Compila + instala + executa o app em um emulador (sobe um se nenhum estiver conectado). A receita do laço de iteração. |
| `just wallet-fresh` | JDK + Android SDK + emulador | Reinstalação limpa, depois executa. |
| `just emulator` | Android SDK | Sobe um emulador (idempotente). |

O teste de conformidade invoca o `cargo` para conduzir a CLI `wallet-conformance` em Rust; se o
`cargo` não estiver no `PATH`, ele é **pulado, não falhado**, de modo que o `:ssi` ainda compila
em uma máquina sem o workspace Rust. O `just test-wallet` também está dobrado dentro do
`just test` de nível superior.

### Veja um fluxo completo de ponta a ponta

Suba o backend e gere uma oferta, depois conduza o celular:

```sh
cd ..
just deploy        # Postgres + verificador WASM + emissor + relay
just offer-qr      # um QR de oferta de credencial para um aluno semeado
just wallet        # compila + executa a carteira em um emulador
```

Escaneie o QR da oferta (Receber) para obter o diploma, depois `just verifier` e escaneie seu QR
de requisição (Apresentar) para compartilhá-lo. A build de debug permite texto não cifrado para
qualquer host, então o emulador conversa com o backend no IP da LAN sem configuração extra.

## Paridade do motor, e o caminho até o Rust

O `KotlinSsiEngine` é a implementação da **Fase 1** — uma porta manual fiel do
`ssi_core::wallet_sim`. A interface `SsiEngine` existe para que a implementação possa ser trocada
sem tocar no app: um `RustSsiEngine` da **Fase 2** chamaria o `ssi-core` diretamente via UniFFI
para uma paridade exata, sem segunda porta. O mesmo oráculo de conformidade guarda ambos, então a
troca é demonstrável em vez de esperançosa.

## Nota de segurança

Isto é um **protótipo** para um TCC. A chave do titular é devidamente respaldada em hardware e não
exportável, mas a âncora de confiança é uma **raiz simulada da ICP-Brasil**, o SSO do emissor é um
IdP simulado e o estado pendente de código de autorização é mantido em memória (não persistido
através da morte do processo). Uma carteira em produção se ancoraria na PKI nacional real e
integraria o SSO efetivo da instituição. Veja o [README do sistema](../README.pt-BR.md#nota-de-segurança)
para as ressalvas equivalentes do backend.
