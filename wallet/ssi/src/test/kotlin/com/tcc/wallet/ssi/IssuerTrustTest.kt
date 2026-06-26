package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.interfaces.ECPrivateKey
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64

/**
 * HAIP §6.1.1 issuer-credential validation ([IssuerTrust]) at OID4VCI receipt time —
 * the wallet counterpart of `ssi_core::x509`'s reference suite. Signs a credential with
 * the committed mock UFSC leaf key (chain UFSC → MEC → mock ICP-Brasil) and asserts that
 * a valid credential passes while a tampered signature, a wrong `iss`, an untrusted root,
 * a CA-as-leaf, and a missing `x5c` are each rejected. JDK-only (no Rust, no network).
 */
class IssuerTrustTest {

    private val rootPem = resource("/pki/icp_brasil_root.pem")
    private val rogueRootPem = resource("/pki/rogue_root.pem")
    private val leafCert = parseCert(resource("/pki/ufsc_leaf.pem"))
    private val mecCert = parseCert(resource("/pki/mec_intermediate.pem"))
    private val leafKey = parseEcKey(resource("/pki/ufsc_leaf.key"))

    private val leafB64 = b64Std(leafCert.encoded)
    private val mecB64 = b64Std(mecCert.encoded)

    /** A valid issuer-signed credential: x5c = [leaf, mec], iss bound to the leaf SAN. */
    private fun credential(
        iss: String = "https://diploma.ufsc.br",
        x5c: List<String> = listOf(leafB64, mecB64),
    ): String {
        val header = JSONObject()
            .put("alg", "ES256")
            .put("typ", "dc+sd-jwt")
            .put("x5c", JSONArray(x5c))
        val payload = JSONObject()
            .put("iss", iss)
            .put("vct", "urn:tcc:mec:UniversityDiploma:1")
            .put("cnf", JSONObject().put("jwk", SoftwareHolderKey.generate().publicJwk()))
        return signIssuerJwt(header, payload, leafKey)
    }

    @Test
    fun `a well-formed credential validates against its anchor`() {
        IssuerTrust.fromPems(listOf(rootPem)).verifyCredential(credential())
    }

    @Test
    fun `the bundled default anchor validates the real mock chain`() {
        // Proves the bundled /trust/icp_brasil_root.pem resource is found and is the right root.
        IssuerTrust.default().verifyCredential(credential())
    }

    @Test
    fun `a tampered issuer signature is rejected`() {
        val tampered = tamperSignature(credential())
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifyCredential(tampered)
        }
    }

    @Test
    fun `an iss not bound to the leaf certificate is rejected`() {
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifyCredential(credential(iss = "https://evil.example"))
        }
    }

    @Test
    fun `a chain that does not anchor at a trusted root is rejected`() {
        // Same valid chain, but the verifier trusts only an unrelated (rogue) root.
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rogueRootPem)).verifyCredential(credential())
        }
    }

    @Test
    fun `a CA certificate presented as the leaf signer is rejected`() {
        // x5c[0] = the MEC intermediate (a CA) — HAIP forbids a CA as the end-entity signer.
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifyCredential(credential(x5c = listOf(mecB64)))
        }
    }

    @Test
    fun `a credential without an x5c header is rejected`() {
        val header = JSONObject().put("alg", "ES256").put("typ", "dc+sd-jwt")
        val payload = JSONObject().put("iss", "https://diploma.ufsc.br")
        val noX5c = signIssuerJwt(header, payload, leafKey)
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifyCredential(noX5c)
        }
    }

    // --- helpers --------------------------------------------------------------

    /** Sign a compact ES256 JWS the way the issuer does: JOSE raw R‖S over `header.payload`. */
    private fun signIssuerJwt(header: JSONObject, payload: JSONObject, priv: ECPrivateKey): String {
        val h = Bytes.b64url(header.toString().toByteArray(Charsets.UTF_8))
        val p = Bytes.b64url(payload.toString().toByteArray(Charsets.UTF_8))
        val signingInput = "$h.$p"
        val der = Signature.getInstance("SHA256withECDSA").apply {
            initSign(priv)
            update(signingInput.toByteArray(Charsets.UTF_8))
        }.sign()
        return "$signingInput.${Bytes.b64url(Ec.derToJoseRaw(der, Ec.FIELD_BYTES))}"
    }

    /**
     * Corrupt the ES256 signature so its decoded bytes ALWAYS change. Flipping the *last*
     * base64url char is unreliable: a 64-byte signature encodes to 86 chars whose final char
     * carries only 2 significant bits (the rest is zero padding), so `A`↔`B` decodes to the same
     * byte ~25% of the time. The *first* signature char encodes 6 fully-significant bits of `R`,
     * so flipping it deterministically alters the signature.
     */
    private fun tamperSignature(jwt: String): String {
        val dot = jwt.lastIndexOf('.')
        val sig = jwt.substring(dot + 1)
        val replacement = if (sig.first() == 'A') 'B' else 'A'
        return jwt.substring(0, dot + 1) + replacement + sig.drop(1)
    }

    private fun resource(path: String): String =
        IssuerTrustTest::class.java.getResourceAsStream(path)!!.bufferedReader().use { it.readText() }

    private fun parseCert(pem: String): X509Certificate =
        CertificateFactory.getInstance("X.509")
            .generateCertificate(pem.byteInputStream()) as X509Certificate

    private fun parseEcKey(pem: String): ECPrivateKey {
        val body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replace(Regex("\\s"), "")
        val der = Base64.getDecoder().decode(body)
        return KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(der)) as ECPrivateKey
    }

    private fun b64Std(der: ByteArray): String = Base64.getEncoder().encodeToString(der)
}
