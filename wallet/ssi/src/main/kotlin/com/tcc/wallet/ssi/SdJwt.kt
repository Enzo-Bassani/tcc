package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject

/**
 * SD-JWT reading/assembly on the holder side. Mirrors `ssi_core::sd_jwt`:
 *
 * - compact form is `<issuer-jwt>~<disclosure-1>~…~<disclosure-n>~[<kb-jwt>]`;
 * - a disclosure is `base64url(JSON([salt, name, value]))`; its digest (listed in
 *   the parent object's `_sd`) is `base64url(SHA-256(ASCII(disclosure)))`.
 *
 * The wallet never *creates* disclosures (the issuer does); it splits a stored
 * credential, selects which disclosure strings to forward verbatim, and
 * reconstructs the full claim set for display.
 */
object SdJwt {

    /** `(issuer_jwt, disclosures)`; drops the trailing empty segment and any KB-JWT,
     *  exactly like `ssi_core::sd_jwt::split`. A stored credential carries no KB-JWT. */
    fun split(sdJwt: String): Pair<String, List<String>> {
        val parts = sdJwt.split('~')
        val issuerJwt = parts.firstOrNull().orEmpty()
        val disclosures = parts.drop(1).filter { it.isNotEmpty() }
        return issuerJwt to disclosures
    }

    /** The claim name a disclosure carries (`JSON([salt, name, value])[1]`). */
    fun disclosureName(encoded: String): String =
        decode(encoded).getString(1)

    /** The base64url SHA-256 digest of a disclosure string (its `_sd` entry). */
    fun digest(encoded: String): String = Bytes.sha256B64Url(encoded)

    private fun decode(encoded: String): JSONArray =
        JSONArray(String(Bytes.b64urlDecode(encoded), Charsets.UTF_8))

    /**
     * Reconstruct the full claim set: the issuer payload with every supplied
     * disclosure merged back in (and the `_sd` / `_sd_alg` machinery removed).
     * Used both to display a stored credential and to evaluate a DCQL query
     * against the wallet's full claims.
     */
    fun reconstruct(payload: JSONObject, disclosures: List<String>): JSONObject {
        val byDigest = HashMap<String, Pair<String, Any?>>()
        for (enc in disclosures) {
            val arr = decode(enc)
            byDigest[digest(enc)] = arr.getString(1) to arr.get(2)
        }
        return walk(payload, byDigest) as JSONObject
    }

    private fun walk(node: Any?, byDigest: Map<String, Pair<String, Any?>>): Any? = when (node) {
        is JSONObject -> {
            val out = JSONObject()
            for (key in node.keys()) {
                if (key == "_sd" || key == "_sd_alg") continue
                out.put(key, walk(node.get(key), byDigest))
            }
            node.optJSONArray("_sd")?.let { sd ->
                for (i in 0 until sd.length()) {
                    byDigest[sd.getString(i)]?.let { (name, value) ->
                        out.put(name, walk(value, byDigest))
                    }
                }
            }
            out
        }
        is JSONArray -> JSONArray().also { out ->
            for (i in 0 until node.length()) out.put(walk(node.get(i), byDigest))
        }
        else -> node
    }
}
