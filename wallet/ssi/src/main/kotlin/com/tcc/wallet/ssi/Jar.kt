package com.tcc.wallet.ssi

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jwt.SignedJWT
import org.json.JSONObject

/**
 * `did:jwk` resolution + JWT-Secured Authorization Request (JAR, RFC 9101)
 * verification — the wallet side of the zero-knowledge-relay model
 * (`ssi_core::oid4vp::{resolve_did_jwk, verify_request}`).
 *
 * The verifier has no CA certificate; instead it anchors its key in the QR. The QR
 * carries `client_id = decentralized_identifier:did:jwk:<b64url(JWK)>` and the
 * signed request `by value`. The wallet resolves the key from the client_id
 * (deterministically, no network) and verifies the request's ES256 signature
 * against it, so a tampered or relay-injected request is rejected.
 */
object Jar {

    /** Resolve a `did:jwk` (or a `decentralized_identifier:did:jwk:…#frag` client_id)
     *  to its embedded public JWK by base64url-decoding the method-specific id. */
    fun resolveDidJwk(id: String): JSONObject {
        val did = id.removePrefix("decentralized_identifier:")
        require(did.startsWith("did:jwk:")) { "not a did:jwk identifier" }
        val suffix = did.removePrefix("did:jwk:").substringBefore('#')
        return JSONObject(String(Bytes.b64urlDecode(suffix), Charsets.UTF_8))
    }

    /**
     * Verify a signed Authorization Request (JAR JWT) against the `expectedClientId`
     * the wallet read **from the QR** (its out-of-band trust anchor), and return the
     * request claims. Throws if the signature is invalid or the client_id mismatches.
     */
    fun verifyRequest(requestJwt: String, expectedClientId: String): JSONObject {
        val signingKey = ECKey.parse(resolveDidJwk(expectedClientId).toString())
        val jwt = SignedJWT.parse(requestJwt)
        require(jwt.header.algorithm == JWSAlgorithm.ES256) { "JAR must be signed with ES256" }
        require(jwt.verify(ECDSAVerifier(signingKey))) { "JAR signature is invalid" }

        val payload = JSONObject(jwt.payload.toString())
        require(payload.optString("client_id") == expectedClientId) {
            "request client_id does not match the QR client_id"
        }
        return payload
    }
}
