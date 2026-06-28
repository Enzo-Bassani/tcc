package com.tcc.wallet.ssi

import com.nimbusds.jose.crypto.impl.ECDSA
import org.json.JSONObject
import java.math.BigInteger
import java.security.interfaces.ECPublicKey

/**
 * Shared P-256 / ES256 encoding helpers — the single source of truth for the JOSE wire
 * format, reused by every [HolderKey] backing. [SoftwareHolderKey] (`:ssi`, BouncyCastle)
 * and `KeystoreHolderKey` (`:app`, AndroidKeyStore) produce the same JWK shape and the same
 * raw R‖S signatures by going through here, so a Keystore-signed VP Token verifies exactly
 * like a software-signed one.
 *
 * The DER↔JOSE signature transcoding is delegated to **Nimbus JOSE+JWT**
 * (`com.nimbusds.jose.crypto.impl.ECDSA`), so this module does not hand-roll ASN.1. This is
 * the only JOSE work left in Kotlin — JWS/JWE/JAR/SD-JWT all run in Rust `ssi-core` over the
 * UniFFI [RustSsiEngine]; the wallet just frames the signing input and signs the digest here.
 */
object Ec {

    /** P-256 field size in bytes (the width of `x`, `y`, and each of `r`/`s`). */
    const val FIELD_BYTES = 32

    /** `{"kty":"EC","crv":"P-256","x":"<b64url-32B>","y":"<b64url-32B>"}`. */
    fun ecPublicJwk(pub: ECPublicKey): JSONObject {
        val w = pub.w
        return JSONObject()
            .put("kty", "EC")
            .put("crv", "P-256")
            .put("x", Bytes.b64url(toFixed(w.affineX, FIELD_BYTES)))
            .put("y", Bytes.b64url(toFixed(w.affineY, FIELD_BYTES)))
    }

    /** Left-pad a non-negative [BigInteger] to exactly [n] big-endian bytes,
     *  dropping the sign byte `toByteArray()` may prepend. */
    fun toFixed(value: BigInteger, n: Int): ByteArray {
        val src = value.toByteArray()
        val out = ByteArray(n)
        if (src.size >= n) {
            System.arraycopy(src, src.size - n, out, 0, n)
        } else {
            System.arraycopy(src, 0, out, n - src.size, src.size)
        }
        return out
    }

    /** Convert a DER `ECDSA-Sig-Value` (`SEQUENCE { r INTEGER, s INTEGER }`)
     *  into JOSE's fixed-width `R‖S` concatenation (each [n] bytes). The JCE
     *  `SHA256withECDSA` signers (BouncyCastle and AndroidKeyStore) both emit DER. */
    fun derToJoseRaw(der: ByteArray, n: Int): ByteArray =
        ECDSA.transcodeSignatureToConcat(der, 2 * n)
}
