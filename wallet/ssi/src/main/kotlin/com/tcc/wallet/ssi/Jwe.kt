package com.tcc.wallet.ssi

import com.nimbusds.jose.EncryptionMethod
import com.nimbusds.jose.JWEAlgorithm
import com.nimbusds.jose.JWEHeader
import com.nimbusds.jose.JWEObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDHDecrypter
import com.nimbusds.jose.crypto.ECDHEncrypter
import com.nimbusds.jose.jwk.ECKey
import org.json.JSONObject

/**
 * JWE for the OID4VP encrypted response — **ECDH-ES (Direct Key Agreement)** over
 * P-256 with **A128GCM/A256GCM**, in compact serialization, using **Nimbus
 * JOSE+JWT** (`com.nimbusds:nimbus-jose-jwt`).
 *
 * Nimbus implements RFC 7516/7518 exactly — the ephemeral `epk`, the NIST
 * SP 800-56A **Concat KDF** (AlgorithmID = the `enc` value, empty apu/apv,
 * SuppPubInfo = key length) and AES-GCM with the protected header as AAD — so the
 * output is **byte-compatible with the Rust verifier** (`ssi_core::jwe`), which is
 * hand-rolled on the same RFCs. That cross-language interop is the whole reason the
 * conformance oracle exists, and it is what guarantees this drop-in is correct.
 *
 * The wallet is always the JWE *sender* (it seals the response to
 * the verifier's ephemeral key); [decrypt] exists only for round-trip tests. We use
 * a real JOSE library here (Nimbus, JVM/Android) rather than hand-rolling — the
 * verifier side cannot (its `ssi-core` must compile to `wasm32`, where the mature
 * JWE crate `josekit` does not build), so only this side is library-backed.
 */
object Jwe {

    /** Seal [plaintext] to [recipientPubJwk] (an EC P-256 JWK) with ECDH-ES + [encAlg]
     *  (`A128GCM` or `A256GCM`). [kid] is echoed into the JWE header. Returns compact JWE. */
    fun encrypt(recipientPubJwk: JSONObject, kid: String, encAlg: String, plaintext: ByteArray): String {
        val recipient = ECKey.parse(recipientPubJwk.toString())
        val header = JWEHeader.Builder(JWEAlgorithm.ECDH_ES, encryptionMethod(encAlg))
            .keyID(kid)
            .build()
        val jwe = JWEObject(header, Payload(plaintext))
        jwe.encrypt(ECDHEncrypter(recipient))
        return jwe.serialize()
    }

    /** Open a compact JWE produced by [encrypt] using a P-256 private JWK (`d`).
     *  Provided for round-trip tests; the device wallet only ever encrypts. */
    fun decrypt(jwe: String, recipientPrivJwk: JSONObject): ByteArray {
        val key = ECKey.parse(recipientPrivJwk.toString())
        val obj = JWEObject.parse(jwe)
        obj.decrypt(ECDHDecrypter(key))
        return obj.payload.toBytes()
    }

    private fun encryptionMethod(encAlg: String): EncryptionMethod = when (encAlg) {
        "A128GCM" -> EncryptionMethod.A128GCM
        "A256GCM" -> EncryptionMethod.A256GCM
        else -> throw IllegalArgumentException("unsupported JWE enc: $encAlg")
    }
}
