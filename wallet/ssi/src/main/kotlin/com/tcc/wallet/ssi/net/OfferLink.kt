package com.tcc.wallet.ssi.net

import org.json.JSONObject
import java.net.URLDecoder

/**
 * Resolve a Credential Offer from what a QR/deep link carries. Per OID4VCI an
 * `openid-credential-offer://` link holds either an inline `credential_offer`
 * (URL-encoded JSON) or a `credential_offer_uri` to fetch. The issuer in this repo
 * emits the `_uri` form (see `openid_link` in its `/credential-offer` response).
 */
object OfferLink {

    /** Accepts a full deep link, a bare `credential_offer_uri`, or inline offer JSON. */
    fun resolve(input: String, http: Http = Http()): JSONObject {
        val trimmed = input.trim()
        // Inline JSON pasted directly.
        if (trimmed.startsWith("{")) return JSONObject(trimmed)

        val query = trimmed.substringAfter('?', "")
        val params = parseQuery(query)

        params["credential_offer"]?.let { return JSONObject(it) }
        params["credential_offer_uri"]?.let { return http.getJson(it) }

        // Otherwise treat the whole string as a URI returning the offer JSON.
        return http.getJson(trimmed)
    }

    /** Split a `k=v&k=v` query string into a URL-decoded map (shared with callers that
     *  need to read query params, e.g. the OID4VCI `/authorize` URL). */
    fun parseQuery(query: String): Map<String, String> =
        query.split('&').filter { it.contains('=') }.associate { pair ->
            val (k, v) = pair.split('=', limit = 2)
            URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
        }
}
