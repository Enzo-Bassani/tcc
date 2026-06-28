package com.tcc.wallet.ssi.net

import com.tcc.wallet.ssi.SsiEngine
import com.tcc.wallet.ssi.StoredCredential
import org.json.JSONObject
import java.net.URLDecoder

/**
 * OID4VP 1.0 **presentation** over this repo's relay. The signed Authorization
 * Request travels **by value in the
 * QR** — `openid4vp://?client_id=<did:jwk>&request=<JAR JWT>` — so the wallet never
 * fetches it from the relay. The wallet verifies the request against the QR's
 * `client_id` (its did:jwk trust anchor), builds the VP Token, JWE-encrypts the
 * response to the verifier's ephemeral key, and POSTs the ciphertext to the
 * request's `response_uri`. The relay only ever carries that opaque blob.
 *
 * A real UI shows the requested claims (from [describeRequest]) and gets consent
 * before calling [present].
 */
class Oid4vpPresenter(
    private val http: Http = Http(),
    private val engine: SsiEngine,
) {

    /** A scanned request: the QR's `client_id` (the verifier's did:jwk trust anchor)
     *  plus the signed request delivered either **by value** (`requestJwt`) or **by
     *  reference** (`requestUri`, fetched from the relay). Exactly one is non-null. */
    data class ScannedRequest(
        val clientId: String,
        val requestJwt: String?,
        val requestUri: String?,
    )

    /**
     * Parse an `openid4vp://?client_id=…&(request=<JWT>|request_uri=<URL>)` QR URL.
     *
     * TODO(qr-url-contract): this URL format is hand-parsed here and hand-built in the
     * verifier (web/main.js); the engine should own the producer side.
     */
    fun parseQr(qr: String): ScannedRequest {
        val query = qr.substringAfter('?', "")
        val params = HashMap<String, String>()
        for (pair in query.split('&')) {
            val eq = pair.indexOf('=')
            if (eq <= 0) continue
            val k = URLDecoder.decode(pair.substring(0, eq), "UTF-8")
            val v = URLDecoder.decode(pair.substring(eq + 1), "UTF-8")
            params[k] = v
        }
        val clientId = params["client_id"] ?: error("QR has no client_id")
        return ScannedRequest(clientId, params["request"], params["request_uri"])
    }

    /** Resolve the signed request (fetching from the relay if delivered by reference),
     *  verify the did:jwk JAR against the QR's `client_id`, and return the authenticated
     *  request claims. Throws if the signature/client_id is wrong. */
    fun verifyRequest(scanned: ScannedRequest): JSONObject {
        val requestJwt = scanned.requestJwt
            ?: scanned.requestUri?.let { http.getJson(it).getString("request") }
            ?: error("QR has neither request nor request_uri")
        return engine.verifyRequest(requestJwt, scanned.clientId)
    }

    /**
     * Build the VP Token for the (already verified) [request], JWE-encrypt it as the
     * Authorization Response, and POST it to the relay. Returns the response that was
     * sent. Throws if no held credential satisfies the query.
     */
    fun present(
        request: JSONObject,
        credentials: List<StoredCredential>,
        selection: Map<String, Int> = emptyMap(),
    ): JSONObject {
        val responseUri = request.getString("response_uri")
        val response = engine.createResponse(request, credentials, selection)
        val resp = http.postJson(responseUri, response, null)
        if (!resp.ok) throw IllegalStateException("relay rejected the response: HTTP ${resp.status} ${resp.body}")
        return response
    }

    /** A human-readable summary of what the verifier is asking for, for the consent UI. */
    fun describeRequest(request: JSONObject): List<String> {
        val out = ArrayList<String>()
        val creds = request.getJSONObject("dcql_query").getJSONArray("credentials")
        for (i in 0 until creds.length()) {
            val q = creds.getJSONObject(i)
            val vct = q.optJSONObject("meta")?.optJSONArray("vct_values")?.optString(0) ?: "(any type)"
            val claims = q.optJSONArray("claims")
            val names = if (claims == null) "all claims" else (0 until claims.length()).joinToString(", ") { j ->
                val path = claims.getJSONObject(j).getJSONArray("path")
                (0 until path.length()).joinToString(".") { path.get(it).toString() }
            }
            out.add("$vct → $names")
        }
        return out
    }
}
