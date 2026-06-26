package com.tcc.wallet.ssi.net

import org.json.JSONObject

/**
 * Classifies what a scanned QR / pasted link is, so a single wallet entry point
 * can route to issuance (OID4VCI) or presentation (OID4VP). Scheme first
 * (`openid-credential-offer://` vs `openid4vp://`), then a content fallback for
 * bare JSON or `_uri` query forms. Grant selection *within* issuance stays in
 * [Oid4vciClient.detectGrant].
 */
object ScanDispatch {

    enum class Kind { Issuance, Presentation, Unknown }

    fun classify(input: String): Kind {
        val t = input.trim()
        if (t.isEmpty()) return Kind.Unknown
        return when {
            t.startsWith("openid-credential-offer", ignoreCase = true) -> Kind.Issuance
            t.startsWith("openid4vp", ignoreCase = true) -> Kind.Presentation
            t.startsWith("{") -> classifyJson(t)
            "credential_offer" in t -> Kind.Issuance // covers credential_offer + credential_offer_uri
            "request_uri" in t || "response_type" in t || "dcql_query" in t -> Kind.Presentation
            else -> Kind.Unknown
        }
    }

    private fun classifyJson(text: String): Kind =
        runCatching {
            val obj = JSONObject(text)
            when {
                obj.has("credential_issuer") || obj.has("credential_configuration_ids") -> Kind.Issuance
                obj.has("dcql_query") || obj.has("response_uri") || obj.has("client_id") -> Kind.Presentation
                else -> Kind.Unknown
            }
        }.getOrDefault(Kind.Unknown)
}
