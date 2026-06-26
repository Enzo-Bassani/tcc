package com.tcc.wallet.ssi

import java.security.MessageDigest
import java.util.Base64

/**
 * base64url (unpadded) and SHA-256 — the only encoding primitives the SSI wire
 * formats need. base64url is unpadded *everywhere*, so we never use the padding encoder.
 *
 * `java.util.Base64` is available on Android API 26+ (our `minSdk`).
 */
object Bytes {
    private val ENC: Base64.Encoder = Base64.getUrlEncoder().withoutPadding()
    private val DEC: Base64.Decoder = Base64.getUrlDecoder()

    fun b64url(data: ByteArray): String = ENC.encodeToString(data)

    fun b64urlDecode(s: String): ByteArray = DEC.decode(s)

    fun sha256(data: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(data)

    /** SHA-256 digest of an ASCII/UTF-8 string, base64url-encoded (the disclosure/`sd_hash` digest form). */
    fun sha256B64Url(text: String): String =
        b64url(sha256(text.toByteArray(Charsets.UTF_8)))
}
