package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject

/** camelCase boundary, for spacing out a VCT token ("UniversityDiploma" → "University Diploma"). */
private val CAMEL_BOUNDARY = Regex("(?<=[a-z])(?=[A-Z])")

/** Day-precision date label for `iat`/`exp`/`nbf` epoch claims. */
private val DAY_DATE_FMT = java.time.format.DateTimeFormatter.ofPattern("dd MMM yyyy")

/**
 * Pure-Kotlin holder engine. A faithful port of the reference holder
 * `ssi_core::wallet_sim`: it produces byte-for-byte the wire formats that the
 * conformance oracle (`crates/wallet-core`) verifies against the real
 * `ssi_core::oid4vp::validate_vp_token`.
 *
 * Thrown on failure: [IllegalStateException] when a required DCQL credential
 * query can't be satisfied (the all-or-nothing rule; a production UI surfaces
 * this as `access_denied`).
 */
class KotlinSsiEngine : SsiEngine {

    override fun buildVciProof(credentialIssuer: String, cNonce: String, holder: HolderKey): String {
        val header = JSONObject()
            .put("alg", "ES256")
            .put("typ", "openid4vci-proof+jwt")
            .put("jwk", holder.publicJwk())
        val payload = JSONObject()
            .put("aud", credentialIssuer)
            .put("iat", nowSeconds())
            .put("nonce", cNonce)
        return Jws.signEs256(header, payload, holder)
    }

    override fun createVpToken(request: JSONObject, credentials: List<StoredCredential>): JSONObject =
        createVpToken(request, credentials, emptyMap())

    private fun createVpToken(
        request: JSONObject,
        credentials: List<StoredCredential>,
        selection: Map<String, Int>,
    ): JSONObject {
        val dcql = request.getJSONObject("dcql_query")
        val queries = dcql.getJSONArray("credentials")
        val nonce = request.getString("nonce")
        val clientId = request.getString("client_id")

        val vpToken = JSONObject()
        for (q in 0 until queries.length()) {
            val query = queries.getJSONObject(q)
            val id = query.getString("id")

            val presentation = presentMatch(query, credentials, selection[id], nonce, clientId)
                ?: throw IllegalStateException("no held credential satisfies query '$id'")
            vpToken.put(id, JSONArray().put(presentation))
        }
        return vpToken
    }

    override fun createResponse(
        request: JSONObject,
        credentials: List<StoredCredential>,
        selection: Map<String, Int>,
    ): JSONObject {
        val vpToken = createVpToken(request, credentials, selection)
        val state = request.optString("state")

        // Plain response unless the verifier asked for encryption (direct_post.jwt).
        if (request.optString("response_mode") != "direct_post.jwt") {
            return JSONObject().put("vp_token", vpToken).put("state", state)
        }

        val (encJwk, kid) = verifierEncKey(request)
        val encAlg = pickEncAlg(request)
        val params = JSONObject().put("vp_token", vpToken).put("state", state)
        val jwe = Jwe.encrypt(encJwk, kid, encAlg, params.toString().toByteArray(Charsets.UTF_8))
        return JSONObject().put("response", jwe)
    }

    override fun readCredential(sdJwt: String): JSONObject {
        val (issuerJwt, disclosures) = SdJwt.split(sdJwt)
        val (_, payload) = Jws.decodeUnverified(issuerJwt)
        return SdJwt.reconstruct(payload, disclosures)
    }

    override fun verifyRequest(requestJwt: String, clientId: String): JSONObject =
        Jar.verifyRequest(requestJwt, clientId)

    override fun verifyIssuerCredential(sdJwt: String) = issuerTrust.verifyCredential(sdJwt)

    override fun verifySignedMetadata(signedMetadata: String, expectedIssuer: String): JSONObject =
        issuerTrust.verifySignedMetadata(signedMetadata, expectedIssuer)

    /** HAIP §6.1.1 issuer-trust validator, anchored at the bundled mock ICP-Brasil root. */
    private val issuerTrust: IssuerTrust = IssuerTrust.default()

    /** The verifier's response-encryption key (`use:enc`) from `client_metadata.jwks`,
     *  with its `kid`. */
    private fun verifierEncKey(request: JSONObject): Pair<JSONObject, String> {
        val keys = request
            .getJSONObject("client_metadata")
            .getJSONObject("jwks")
            .getJSONArray("keys")
        for (i in 0 until keys.length()) {
            val key = keys.getJSONObject(i)
            if (key.optString("use") == "enc") {
                return key to key.optString("kid")
            }
        }
        throw IllegalStateException("request has no use:enc key in client_metadata.jwks")
    }

    /** Prefer A256GCM (HAIP); otherwise A128GCM — the default when unadvertised. */
    private fun pickEncAlg(request: JSONObject): String {
        val supported = request
            .optJSONObject("client_metadata")
            ?.optJSONArray("encrypted_response_enc_values_supported")
        if (supported != null) {
            for (i in 0 until supported.length()) {
                if (supported.optString(i) == "A256GCM") return "A256GCM"
            }
        }
        return "A128GCM"
    }

    override fun findMatches(
        request: JSONObject,
        credentials: List<StoredCredential>,
    ): List<QueryMatch> {
        val queries = request.getJSONObject("dcql_query").getJSONArray("credentials")
        val out = ArrayList<QueryMatch>()
        for (q in 0 until queries.length()) {
            val query = queries.getJSONObject(q)
            val vct = query.optJSONObject("meta")?.optJSONArray("vct_values")?.optString(0)
            val matches = ArrayList<MatchedCredential>()
            for ((index, cred) in credentials.withIndex()) {
                val (issuerJwt, allDisclosures) = SdJwt.split(cred.sdJwt)
                val (_, payload) = Jws.decodeUnverified(issuerJwt)
                val fullClaims = SdJwt.reconstruct(payload, allDisclosures)

                val wanted = Dcql.resolveWantedLeafNames(query, fullClaims) ?: continue
                val disclosed = disclosedClaims(query, fullClaims, wanted)
                matches.add(
                    MatchedCredential(
                        index = index,
                        sdJwt = cred.sdJwt,
                        vct = fullClaims.optString("vct"),
                        disclosed = disclosed,
                        alwaysShared = alwaysSharedClaims(payload, disclosed.map { it.path }.toSet()),
                    ),
                )
            }
            out.add(QueryMatch(query.getString("id"), vct, matches))
        }
        return out
    }

    /** The label/value pairs the verifier would receive for [query] from a credential
     *  with [fullClaims], restricted to the [wanted] leaf names. Used by the consent UI. */
    private fun disclosedClaims(
        query: JSONObject,
        fullClaims: JSONObject,
        wanted: List<String>,
    ): List<DisclosedClaim> {
        val claims = query.optJSONArray("claims") ?: return emptyList()
        val out = ArrayList<DisclosedClaim>()
        for (i in 0 until claims.length()) {
            val path = claims.getJSONObject(i).getJSONArray("path")
            val segments = (0 until path.length()).map { path.get(it).toString() }
            val leaf = segments.lastOrNull() ?: continue
            if (leaf !in wanted) continue
            out.add(DisclosedClaim(segments, humanize(leaf), valueAtPath(fullClaims, segments)))
        }
        return out
    }

    /** The claims that travel with **every** presentation of a credential: the
     *  issuer-JWT payload claims that are *not* selectively disclosable (everything left
     *  after dropping the `_sd`/`_sd_alg` machinery, without merging any disclosure).
     *  These are signed into the credential, so the holder cannot withhold them — the
     *  consent UI shows them separately from what the verifier explicitly asked for.
     *  [askedPaths] are excluded to avoid double-listing a requested claim. */
    private fun alwaysSharedClaims(payload: JSONObject, askedPaths: Set<List<String>>): List<DisclosedClaim> {
        val out = ArrayList<DisclosedClaim>()
        payload.optString("vct").takeIf { it.isNotBlank() }
            ?.let { out.add(DisclosedClaim(listOf("vct"), "Credential type", humanizeVct(it))) }

        for (key in payload.keys()) {
            when (key) {
                "_sd", "_sd_alg", "vct" -> {}
                "iat" -> epochDate(payload, key)?.let { out.add(DisclosedClaim(listOf(key), "Issued", it)) }
                "exp" -> epochDate(payload, key)?.let { out.add(DisclosedClaim(listOf(key), "Expires", it)) }
                "nbf" -> epochDate(payload, key)?.let { out.add(DisclosedClaim(listOf(key), "Not valid before", it)) }
                "iss" -> payload.optString(key).takeIf { it.isNotBlank() }
                    ?.let { out.add(DisclosedClaim(listOf(key), "Issuer URI", it)) }
                "jti" -> payload.optString(key).takeIf { it.isNotBlank() }
                    ?.let { out.add(DisclosedClaim(listOf(key), "Credential ID", it)) }
                "cnf" -> {
                    val jwk = payload.optJSONObject("cnf")?.optJSONObject("jwk")
                    val desc = jwk?.let {
                        listOf(it.optString("kty"), it.optString("crv")).filter(String::isNotBlank).joinToString(" · ")
                    }
                    out.add(DisclosedClaim(listOf("cnf"), "Holder key binding", desc?.ifBlank { "device key" } ?: "device key"))
                }
                "status" -> {
                    val sl = payload.optJSONObject("status")?.optJSONObject("status_list")
                    val desc = if (sl != null && sl.has("idx")) "Token Status List #${sl.optInt("idx")}" else "Token Status List"
                    out.add(DisclosedClaim(listOf("status"), "Revocation reference", desc))
                }
                else -> flattenAlwaysShared(listOf(key), key, payload.get(key), out)
            }
        }
        return out.filter { it.path !in askedPaths }
    }

    private fun flattenAlwaysShared(path: List<String>, rawLabel: String, node: Any?, out: MutableList<DisclosedClaim>) {
        when (node) {
            is JSONObject -> for (k in node.keys()) {
                if (k == "_sd" || k == "_sd_alg") continue
                flattenAlwaysShared(path + k, "$rawLabel $k", node.get(k), out)
            }
            is JSONArray -> {} // arrays are rare in the issuer payload metadata; skip in the summary
            else -> node?.let { out.add(DisclosedClaim(path, humanize(rawLabel), it.toString())) }
        }
    }

    /** `urn:tcc:mec:UniversityDiploma:1` → "University Diploma". */
    private fun humanizeVct(vct: String): String {
        val token = vct.split(':').lastOrNull { it.isNotBlank() && !it.all(Char::isDigit) } ?: vct
        return token.replace(CAMEL_BOUNDARY, " ").ifBlank { vct }
    }

    private fun epochDate(payload: JSONObject, key: String): String? {
        val seconds = payload.optLong(key, 0L)
        if (seconds <= 0L) return null
        return java.time.Instant.ofEpochSecond(seconds)
            .atZone(java.time.ZoneId.systemDefault())
            .format(DAY_DATE_FMT)
    }

    /** Follow an object path (string keys only — the demo claims are object pointers)
     *  and stringify the leaf; "" if absent. */
    private fun valueAtPath(claims: JSONObject, path: List<String>): String {
        var node: Any? = claims
        for (key in path) {
            node = (node as? JSONObject)?.opt(key) ?: return ""
        }
        return node?.toString() ?: ""
    }

    /** `full_name` → `Full name`, `student_id` → `Student id`. */
    private fun humanize(leaf: String): String =
        leaf.replace('_', ' ').replaceFirstChar { it.uppercase() }

    /** Build the presentation for [query]: the holder's [chosenIndex] credential when
     *  it satisfies the query, otherwise the first held credential that does — or
     *  `null` if none matches. */
    private fun presentMatch(
        query: JSONObject,
        credentials: List<StoredCredential>,
        chosenIndex: Int?,
        nonce: String,
        clientId: String,
    ): String? {
        val order = if (chosenIndex != null && chosenIndex in credentials.indices) {
            listOf(chosenIndex) + credentials.indices.filter { it != chosenIndex }
        } else {
            credentials.indices.toList()
        }
        for (i in order) {
            val cred = credentials[i]
            val (issuerJwt, allDisclosures) = SdJwt.split(cred.sdJwt)
            val (_, payload) = Jws.decodeUnverified(issuerJwt)
            val fullClaims = SdJwt.reconstruct(payload, allDisclosures)

            val wanted = Dcql.resolveWantedLeafNames(query, fullClaims) ?: continue
            return present(issuerJwt, allDisclosures, wanted, cred.holder, nonce, clientId)
        }
        return null
    }

    /** Assemble one SD-JWT presentation: select the wanted disclosures, then append
     *  a key-binding JWT bound to nonce + audience + sd_hash.
     *  Identical byte layout to `wallet_sim::present`. */
    private fun present(
        issuerJwt: String,
        allDisclosures: List<String>,
        wantedLeafNames: List<String>,
        holder: HolderKey,
        nonce: String,
        clientId: String,
    ): String {
        val selected = allDisclosures.filter { wantedLeafNames.contains(SdJwt.disclosureName(it)) }

        // issuer JWT + each selected disclosure preceded by '~', then a trailing '~'.
        val prefix = buildString {
            append(issuerJwt)
            for (enc in selected) {
                append('~')
                append(enc)
            }
            append('~')
        }

        // sd_hash is over exactly those bytes (everything before the KB-JWT). The
        // trailing '~' MUST be included or holder binding fails.
        val sdHash = Bytes.sha256B64Url(prefix)
        return prefix + buildKbJwt(holder, nonce, clientId, sdHash)
    }

    private fun buildKbJwt(holder: HolderKey, nonce: String, audience: String, sdHash: String): String {
        val header = JSONObject()
            .put("alg", "ES256")
            .put("typ", "kb+jwt")
        val payload = JSONObject()
            .put("iat", nowSeconds())
            .put("aud", audience)
            .put("nonce", nonce)
            .put("sd_hash", sdHash)
        return Jws.signEs256(header, payload, holder)
    }

    private fun nowSeconds(): Long = System.currentTimeMillis() / 1000
}
