package com.tcc.wallet.ssi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayInputStream
import java.net.URI
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Base64
import java.util.Date
import javax.naming.ldap.LdapName

/**
 * **Issuer-credential validation at OID4VCI receipt time** — the wallet's side of the
 * HAIP §6.1.1 `x5c` issuer-trust model. Mirrors the verifier's reference implementation
 * `ssi_core::x509` (chain validation, leaf-not-CA, `iss`↔SAN binding) so the wallet and
 * verifier agree on what a trustworthy issuer credential is.
 *
 * Before a freshly-received credential is stored, [verifyCredential]:
 *  1. parses the `x5c` JOSE header of the issuer-signed SD-JWT (the part before the first `~`);
 *  2. resolves the issuer signing key from the **leaf** certificate (`x5c[0]`) and verifies the
 *     issuer JWS **ES256** signature over the credential — rejecting a forged/tampered credential;
 *  3. validates the certificate **chain** (leaf → intermediate …) up to a trusted **root anchor**
 *     held locally (HAIP: the leaf MUST NOT be self-signed/CA, and the root MUST NOT be in `x5c`);
 *  4. binds identity: the SD-JWT `iss` claim MUST match the leaf certificate (SAN / CN), exactly
 *     as the verifier does.
 *
 * Any failure throws, so an invalid credential is never returned to be stored. The wallet still
 * stores and later forwards the issuer JWT **unchanged** — this only gates *acceptance*.
 *
 * Trust anchor: the bundled mock **ICP-Brasil** root (`/trust/icp_brasil_root.pem`, a copy of the
 * verifier's default anchor `ssi_core::trust::ICP_BRASIL_MOCK_ROOT_PEM`).
 *
 * Chain + certificate handling uses the JVM standard library
 * (`CertificateFactory`/`CertPathValidator`/`PKIXParameters`); ES256 JWS verification reuses the
 * Nimbus pattern already used for JAR requests ([Jar]).
 */
class IssuerTrust(
    private val anchors: List<X509Certificate>,
    private val enabled: Boolean = true,
    private val clock: () -> Instant = Instant::now,
) {

    /** Validate a received compact SD-JWT VC; throws if the issuer credential is not trustworthy. */
    fun verifyCredential(sdJwt: String) {
        if (!enabled) return

        // The issuer-signed JWT is everything before the first '~' (the SD-JWT VC issuer part).
        val issuerJwt = sdJwt.substringBefore('~')
        verifyX5cJwt(issuerJwt)
    }

    /**
     * Verify **signed Credential Issuer Metadata** (OID4VCI §11.2.3, HAIP §4.1 / VCI-8): the
     * `signed_metadata` JWT served in `/.well-known/openid-credential-issuer`. Validates the JWS
     * with exactly the same HAIP §6.1.1 machinery as a credential — `x5c` chain → trusted anchor,
     * ES256 signature under the leaf, leaf-not-CA / no self-signed cert in `x5c`, and `iss`↔leaf
     * binding — and additionally binds the document to [expectedIssuer], the Credential Issuer
     * Identifier the wallet is talking to (the metadata's `sub` / `credential_issuer` claim per
     * §11.2.3). Returns the verified metadata claims; throws if anything fails.
     */
    fun verifySignedMetadata(signedMetadata: String, expectedIssuer: String): JSONObject {
        if (!enabled) return Jws.decodeUnverified(signedMetadata).second

        val payload = verifyX5cJwt(signedMetadata)

        // Bind the signed metadata to the issuer being talked to. §11.2.3 sets `sub` to the
        // Credential Issuer Identifier; we also accept the mirrored `credential_issuer` claim.
        val sub = payload.optString("sub")
        val credentialIssuer = payload.optString("credential_issuer")
        require(sub == expectedIssuer || credentialIssuer == expectedIssuer) {
            "signed metadata does not authenticate the expected issuer '$expectedIssuer' " +
                "(sub='$sub', credential_issuer='$credentialIssuer')"
        }
        return payload
    }

    /**
     * Verify a compact `x5c`-signed JWS under the HAIP §6.1.1 issuer-trust model and return its
     * payload. Shared by [verifyCredential] (the issuer-signed SD-JWT) and [verifySignedMetadata]
     * (the OID4VCI §11.2.3 `signed_metadata` JWT): both resolve the signing key from the leaf of
     * the `x5c` chain, enforce the HAIP structural constraints, validate the chain to a trusted
     * anchor, check the ES256 signature, and bind the JWT's `iss` to the leaf certificate.
     */
    private fun verifyX5cJwt(jwt: String): JSONObject {
        require(jwt.count { it == '.' } == 2) { "value is not a compact JWS" }
        val (header, payload) = Jws.decodeUnverified(jwt)

        // 1. x5c header → certificate chain (leaf first).
        val x5c = header.optJSONArray("x5c")
            ?: throw IllegalStateException("JWS header carries no x5c (HAIP §6.1.1)")
        val chain = parseX5c(x5c)
        val leaf = chain.first()

        // 2. HAIP structural constraints on the presented chain.
        //    The signing certificate is an end-entity cert: it MUST NOT assert cA.
        require(leaf.basicConstraints < 0) {
            "leaf certificate is a CA, not an end-entity signer (HAIP §6.1.1)"
        }
        //    The trust-anchor root is held locally and MUST NOT be present in x5c, so the chain
        //    MUST NOT contain a self-signed certificate (a root is self-signed).
        require(chain.none { it.subjectX500Principal == it.issuerX500Principal }) {
            "x5c must not contain a self-signed (root) certificate; the anchor is held locally (HAIP §6.1.1)"
        }

        // 3. Chain validation up to a trusted anchor (validity, cA on issuers, links, anchor).
        validateChain(chain)

        // 4. JWS signature under the leaf certificate's key (ES256).
        verifyIssuerSignature(jwt, leaf)

        // 5. Bind the JWT's iss to the leaf certificate (string compare; never dereferenced).
        val iss = payload.optString("iss")
        require(iss.isNotBlank()) { "JWS has no iss claim to bind to the leaf certificate" }
        requireIssMatchesLeaf(iss, leaf)
        return payload
    }

    /** Parse `x5c` (a JSON array of **standard** base64 DER strings, leaf first — RFC 7515 §4.1.6). */
    private fun parseX5c(x5c: JSONArray): List<X509Certificate> {
        require(x5c.length() > 0) { "x5c header is empty" }
        val cf = CertificateFactory.getInstance("X.509")
        return (0 until x5c.length()).map { i ->
            val der = Base64.getMimeDecoder().decode(x5c.getString(i))
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        }
    }

    /** PKIX validation of `[leaf, intermediate, …]` (root excluded) up to a trusted anchor. */
    private fun validateChain(chain: List<X509Certificate>) {
        require(anchors.isNotEmpty()) { "no trusted anchors configured" }
        val certPath = CertificateFactory.getInstance("X.509").generateCertPath(chain)
        val anchorSet = anchors.map { TrustAnchor(it, null) }.toSet()
        val params = PKIXParameters(anchorSet).apply {
            isRevocationEnabled = false // no CRL/OCSP for the mock prototype PKI
            date = Date.from(clock())
        }
        try {
            CertPathValidator.getInstance("PKIX").validate(certPath, params)
        } catch (e: Exception) {
            throw IllegalStateException(
                "issuer certificate chain does not validate to a trusted anchor: ${e.message}",
                e,
            )
        }
    }

    /** Verify the issuer JWS over [issuerJwt] under the [leaf]'s public key (must be ES256). */
    private fun verifyIssuerSignature(issuerJwt: String, leaf: X509Certificate) {
        // Build the ECKey from the leaf's public key directly (avoids ECKey.parse(cert), which
        // pulls in bcpkix; only bcprov is on the classpath). The mock PKI is P-256 throughout.
        val ecPub = leaf.publicKey as? ECPublicKey
            ?: throw IllegalStateException("leaf certificate key is not EC (P-256/ES256 expected)")
        val verifier = ECDSAVerifier(ECKey.Builder(Curve.P_256, ecPub).build())
        val jwt = SignedJWT.parse(issuerJwt)
        require(jwt.header.algorithm == JWSAlgorithm.ES256) { "issuer JWS must be signed with ES256" }
        require(jwt.verify(verifier)) {
            "issuer JWS signature does not verify under the leaf certificate key"
        }
    }

    /** Bind `iss` to the leaf certificate via SAN (dNSName/URI) or CN — never dereferenced. */
    private fun requireIssMatchesLeaf(iss: String, leaf: X509Certificate) {
        val sans = leafSans(leaf)
        if (iss in sans) return
        val cn = subjectCn(leaf)
        val host = runCatching { URI(iss).host }.getOrNull()
        if (host != null && (host in sans || host == cn)) return
        if (cn == iss) return
        throw IllegalStateException(
            "credential iss '$iss' is not bound to the leaf certificate (SAN=$sans, CN=$cn)",
        )
    }

    /** dNSName (type 2) + uniformResourceIdentifier (type 6) SAN entries. */
    private fun leafSans(leaf: X509Certificate): List<String> =
        leaf.subjectAlternativeNames?.mapNotNull { entry ->
            when (entry[0] as Int) {
                2, 6 -> entry[1] as? String
                else -> null
            }
        } ?: emptyList()

    private fun subjectCn(cert: X509Certificate): String? = runCatching {
        LdapName(cert.subjectX500Principal.name).rdns
            .firstOrNull { it.type.equals("CN", ignoreCase = true) }
            ?.value?.toString()
    }.getOrNull()

    companion object {
        private const val ANCHOR_RESOURCE = "/trust/icp_brasil_root.pem"

        /** The default validator, anchored at the bundled mock ICP-Brasil root. */
        fun default(clock: () -> Instant = Instant::now): IssuerTrust =
            IssuerTrust(bundledAnchors(), clock = clock)

        /** A validator anchored at a caller-supplied set of PEM roots (tests / future config). */
        fun fromPems(pems: List<String>, clock: () -> Instant = Instant::now): IssuerTrust =
            IssuerTrust(pems.map { parsePem(it) }, clock = clock)

        /** A no-op validator — for tests/flows that use stub (unsigned) credentials. */
        fun disabled(): IssuerTrust = IssuerTrust(emptyList(), enabled = false)

        /** The bundled trust anchor(s) from the classpath resource. */
        fun bundledAnchors(): List<X509Certificate> {
            val stream = IssuerTrust::class.java.getResourceAsStream(ANCHOR_RESOURCE)
                ?: error("bundled trust anchor $ANCHOR_RESOURCE missing from the classpath")
            val cf = CertificateFactory.getInstance("X.509")
            return stream.use { cf.generateCertificates(it).map { c -> c as X509Certificate } }
        }

        private fun parsePem(pem: String): X509Certificate =
            CertificateFactory.getInstance("X.509")
                .generateCertificate(ByteArrayInputStream(pem.toByteArray(Charsets.UTF_8))) as X509Certificate
    }
}
