package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
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
 * HAIP §4.1 / OID4VCI §11.2.3 **signed Credential Issuer Metadata** verification
 * ([IssuerTrust.verifySignedMetadata]) — the wallet's side of the VCI-8 requirement. Signs a
 * metadata document with the committed mock UFSC leaf key (chain UFSC → MEC → mock ICP-Brasil,
 * x5c = [leaf, mec]) and asserts that a valid `signed_metadata` JWT verifies and binds to the
 * expected issuer, while a tampered signature, a wrong `iss`, an issuer-mismatch (`sub`), an
 * untrusted root, and a missing `x5c` are each rejected. JDK-only (no Rust, no network).
 */
class SignedMetadataTest {

    private val rootPem = resource("/pki/icp_brasil_root.pem")
    private val rogueRootPem = resource("/pki/rogue_root.pem")
    private val leafCert = parseCert(resource("/pki/ufsc_leaf.pem"))
    private val mecCert = parseCert(resource("/pki/mec_intermediate.pem"))
    private val leafKey = parseEcKey(resource("/pki/ufsc_leaf.key"))

    private val leafB64 = b64Std(leafCert.encoded)
    private val mecB64 = b64Std(mecCert.encoded)

    private val issuerId = "https://diploma.ufsc.br"

    /** A valid `signed_metadata` JWT: x5c = [leaf, mec], iss bound to the leaf SAN, sub = issuer. */
    private fun signedMetadata(
        iss: String = issuerId,
        sub: String = issuerId,
        x5c: List<String> = listOf(leafB64, mecB64),
    ): String {
        val header = JSONObject()
            .put("alg", "ES256")
            .put("typ", "JWT")
            .put("x5c", JSONArray(x5c))
        val payload = JSONObject()
            .put("iss", iss)
            .put("sub", sub)
            .put("credential_issuer", sub)
            .put("credential_endpoint", "$sub/credential")
            .put("nonce_endpoint", "$sub/nonce")
        return signJwt(header, payload, leafKey)
    }

    @Test
    fun `a well-formed signed metadata verifies and returns its claims`() {
        val claims = IssuerTrust.fromPems(listOf(rootPem)).verifySignedMetadata(signedMetadata(), issuerId)
        assertEquals(issuerId, claims.getString("credential_issuer"))
        assertEquals("$issuerId/credential", claims.getString("credential_endpoint"))
    }

    @Test
    fun `the bundled default anchor verifies the real mock chain`() {
        IssuerTrust.default().verifySignedMetadata(signedMetadata(), issuerId)
    }

    @Test
    fun `a tampered signature is rejected`() {
        val tampered = tamperSignature(signedMetadata())
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifySignedMetadata(tampered, issuerId)
        }
    }

    @Test
    fun `an iss not bound to the leaf certificate is rejected`() {
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem))
                .verifySignedMetadata(signedMetadata(iss = "https://evil.example"), issuerId)
        }
    }

    @Test
    fun `signed metadata for a different issuer than the one being talked to is rejected`() {
        // Validly signed and chain-trusted, but sub/credential_issuer name another issuer.
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem))
                .verifySignedMetadata(signedMetadata(), expectedIssuer = "https://other.ufsc.br")
        }
    }

    @Test
    fun `a chain that does not anchor at a trusted root is rejected`() {
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rogueRootPem)).verifySignedMetadata(signedMetadata(), issuerId)
        }
    }

    @Test
    fun `signed metadata without an x5c header is rejected`() {
        val header = JSONObject().put("alg", "ES256").put("typ", "JWT")
        val payload = JSONObject().put("iss", issuerId).put("sub", issuerId)
        val noX5c = signJwt(header, payload, leafKey)
        assertThrows(RuntimeException::class.java) {
            IssuerTrust.fromPems(listOf(rootPem)).verifySignedMetadata(noX5c, issuerId)
        }
    }

    // --- helpers --------------------------------------------------------------

    /** Sign a compact ES256 JWS the way the issuer does: JOSE raw R‖S over `header.payload`. */
    private fun signJwt(header: JSONObject, payload: JSONObject, priv: ECPrivateKey): String {
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
     * Corrupt the ES256 signature so its decoded bytes ALWAYS change: flip the FIRST signature
     * char (6 fully-significant bits of `R`), never the last (only 2 significant bits, so the
     * change is lost ~25% of the time).
     */
    private fun tamperSignature(jwt: String): String {
        val dot = jwt.lastIndexOf('.')
        val sig = jwt.substring(dot + 1)
        val replacement = if (sig.first() == 'A') 'B' else 'A'
        return jwt.substring(0, dot + 1) + replacement + sig.drop(1)
    }

    private fun resource(path: String): String =
        SignedMetadataTest::class.java.getResourceAsStream(path)!!.bufferedReader().use { it.readText() }

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
