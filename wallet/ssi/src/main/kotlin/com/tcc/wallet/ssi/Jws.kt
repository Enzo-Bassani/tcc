package com.tcc.wallet.ssi

import org.json.JSONObject

/**
 * Compact JWS over ES256 — the only signing the holder does (the VCI proof JWT
 * and the key-binding JWT). Byte-for-byte the same construction as
 * `ssi_core::crypto::sign_jws_es256`: `b64url(header).b64url(payload).b64url(sig)`,
 * signed over the ASCII `header.payload` string. The signature bytes come from
 * [HolderKey.sign] (JOSE raw R‖S), so this stays algorithm-agnostic.
 *
 * Key ordering inside the JSON objects is irrelevant for interop: a verifier
 * checks the signature over the exact bytes we emit (it never re-serializes), so
 * org.json's ordering is fine.
 */
object Jws {

    fun signEs256(header: JSONObject, payload: JSONObject, key: HolderKey): String {
        val h = Bytes.b64url(header.toString().toByteArray(Charsets.UTF_8))
        val p = Bytes.b64url(payload.toString().toByteArray(Charsets.UTF_8))
        val signingInput = "$h.$p"
        val sig = key.sign(signingInput.toByteArray(Charsets.UTF_8))
        return "$signingInput.${Bytes.b64url(sig)}"
    }

    /** Decode a compact JWS into `(header, payload)` WITHOUT verifying — for reading
     * an issuer JWT's `vct`/`cnf` etc. (the verifier does the real verification). */
    fun decodeUnverified(jws: String): Pair<JSONObject, JSONObject> {
        val parts = jws.split('.')
        require(parts.size == 3) { "compact JWS must have 3 parts" }
        val header = JSONObject(String(Bytes.b64urlDecode(parts[0]), Charsets.UTF_8))
        val payload = JSONObject(String(Bytes.b64urlDecode(parts[1]), Charsets.UTF_8))
        return header to payload
    }
}
