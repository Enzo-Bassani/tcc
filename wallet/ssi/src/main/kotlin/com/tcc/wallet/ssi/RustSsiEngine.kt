package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject
import uniffi.wallet_ffi.buildVciProof as ffiBuildVciProof
import uniffi.wallet_ffi.createResponse as ffiCreateResponse
import uniffi.wallet_ffi.createVpToken as ffiCreateVpToken
import uniffi.wallet_ffi.findMatches as ffiFindMatches
import uniffi.wallet_ffi.readCredential as ffiReadCredential
import uniffi.wallet_ffi.verifyIssuerCredential as ffiVerifyIssuerCredential
import uniffi.wallet_ffi.verifyRequest as ffiVerifyRequest
import uniffi.wallet_ffi.verifySignedMetadata as ffiVerifySignedMetadata

/** camelCase boundary, for spacing out a VCT token ("UniversityDiploma" → "University Diploma"). */
private val CAMEL_BOUNDARY = Regex("(?<=[a-z])(?=[A-Z])")

/** Day-precision date label for `iat`/`exp`/`nbf` epoch claims. */
private val DAY_DATE_FMT = java.time.format.DateTimeFormatter.ofPattern("dd MMM yyyy")

/** The bundled mock ICP-Brasil root anchor (a copy of `ssi_core::trust::ICP_BRASIL_MOCK_ROOT_PEM`). */
private const val ANCHOR_RESOURCE = "/trust/icp_brasil_root.pem"

/**
 * The holder engine backed by the **shared Rust `ssi-core`** over UniFFI — the
 * Phase-2 implementation of [SsiEngine]. All SD-JWT / JWS / JWE / DCQL / x5c logic
 * runs in `ssi-core` (the same engine the issuer and verifier use); this class only
 * marshals JSON across the FFI and turns the engine's structured match data into the
 * humanized labels the consent UI shows.
 *
 * Signing is delegated back to Kotlin via [KotlinHolderSigner] so the holder's
 * (non-exportable) key never crosses the boundary. The Rust calls throw
 * `uniffi.wallet_ffi.WalletException` on failure.
 */
class RustSsiEngine : SsiEngine {

    override fun buildVciProof(credentialIssuer: String, cNonce: String, holder: HolderKey): String =
        ffiBuildVciProof(KotlinHolderSigner(holder), credentialIssuer, cNonce)

    override fun createVpToken(request: JSONObject, credentials: List<StoredCredential>): JSONObject =
        JSONObject(ffiCreateVpToken(request.toString(), credentials.map { it.sdJwt }, emptyMap(), signerOf(credentials)))

    override fun createResponse(
        request: JSONObject,
        credentials: List<StoredCredential>,
        selection: Map<String, Int>,
    ): JSONObject {
        val ffiSelection = selection.mapValues { it.value.toUInt() }
        val response = ffiCreateResponse(request.toString(), credentials.map { it.sdJwt }, ffiSelection, signerOf(credentials))
        return JSONObject(response)
    }

    override fun findMatches(request: JSONObject, credentials: List<StoredCredential>): List<QueryMatch> {
        val out = JSONArray(ffiFindMatches(request.toString(), credentials.map { it.sdJwt }))
        return (0 until out.length()).map { mapQueryMatch(out.getJSONObject(it), credentials) }
    }

    override fun readCredential(sdJwt: String): JSONObject = JSONObject(ffiReadCredential(sdJwt))

    override fun verifyRequest(requestJwt: String, clientId: String): JSONObject =
        JSONObject(ffiVerifyRequest(requestJwt, clientId))

    override fun verifyIssuerCredential(sdJwt: String) =
        ffiVerifyIssuerCredential(sdJwt, trustAnchors, nowUnix())

    override fun verifySignedMetadata(signedMetadata: String, expectedIssuer: String): JSONObject =
        JSONObject(ffiVerifySignedMetadata(signedMetadata, expectedIssuer, trustAnchors, nowUnix()))

    // --- FFI marshaling --------------------------------------------------------

    /** The bundled trust anchors (mock ICP-Brasil root) the engine validates `x5c`
     *  chains against — the same PEM resource the verifier ships, loaded once. */
    private val trustAnchors: List<String> by lazy {
        val pem = javaClass.getResourceAsStream(ANCHOR_RESOURCE)
            ?.bufferedReader()?.use { it.readText() }
            ?: error("bundled trust anchor $ANCHOR_RESOURCE missing from the classpath")
        listOf(pem)
    }

    private fun nowUnix(): Long = System.currentTimeMillis() / 1000

    /** All held credentials share the single device holder key, so the engine takes
     *  one signer for the batch. */
    private fun signerOf(credentials: List<StoredCredential>): KotlinHolderSigner {
        val holder = credentials.firstOrNull()?.holder
            ?: throw IllegalStateException("no credentials to present")
        return KotlinHolderSigner(holder)
    }

    private fun mapQueryMatch(obj: JSONObject, credentials: List<StoredCredential>): QueryMatch {
        val matches = obj.getJSONArray("matches")
        return QueryMatch(
            queryId = obj.getString("query_id"),
            vct = if (obj.isNull("vct")) null else obj.optString("vct").ifBlank { null },
            matches = (0 until matches.length()).map { mapMatch(matches.getJSONObject(it), credentials) },
        )
    }

    private fun mapMatch(obj: JSONObject, credentials: List<StoredCredential>): MatchedCredential {
        val index = obj.getInt("index")
        val disclosed = obj.getJSONArray("disclosed").let { arr ->
            (0 until arr.length()).map { mapDisclosed(arr.getJSONObject(it)) }
        }
        val alwaysShared = obj.getJSONArray("always_shared").let { arr ->
            (0 until arr.length()).flatMap { mapAlwaysShared(arr.getJSONObject(it)) }
        }
        return MatchedCredential(
            index = index,
            sdJwt = credentials[index].sdJwt,
            vct = obj.optString("vct"),
            disclosed = disclosed,
            alwaysShared = alwaysShared,
        )
    }

    // --- UI humanization (the wallet UI's job; values come structured from Rust) --

    /** A requested, selectively-disclosed claim: humanize its leaf name and stringify its value. */
    private fun mapDisclosed(claim: JSONObject): DisclosedClaim {
        val path = pathOf(claim)
        val leaf = path.lastOrNull() ?: ""
        return DisclosedClaim(path, humanize(leaf), stringifyValue(claim.opt("value")))
    }

    /** One always-shared issuer-JWT claim → its consent-screen label(s). Mirrors the
     *  per-key labeling the wallet has always shown; unknown nested objects flatten. */
    private fun mapAlwaysShared(claim: JSONObject): List<DisclosedClaim> {
        val key = pathOf(claim).firstOrNull() ?: return emptyList()
        val value = claim.opt("value")
        return when (key) {
            "vct" -> listOf(DisclosedClaim(listOf("vct"), "Credential type", humanizeVct(value?.toString().orEmpty())))
            "iat" -> epochDate(value)?.let { listOf(DisclosedClaim(listOf("iat"), "Issued", it)) } ?: emptyList()
            "exp" -> epochDate(value)?.let { listOf(DisclosedClaim(listOf("exp"), "Expires", it)) } ?: emptyList()
            "nbf" -> epochDate(value)?.let { listOf(DisclosedClaim(listOf("nbf"), "Not valid before", it)) } ?: emptyList()
            "iss" -> listOf(DisclosedClaim(listOf("iss"), "Issuer URI", value?.toString().orEmpty()))
            "jti" -> listOf(DisclosedClaim(listOf("jti"), "Credential ID", value?.toString().orEmpty()))
            "cnf" -> {
                val jwk = (value as? JSONObject)?.optJSONObject("jwk")
                val desc = jwk?.let {
                    listOf(it.optString("kty"), it.optString("crv")).filter(String::isNotBlank).joinToString(" · ")
                }
                listOf(DisclosedClaim(listOf("cnf"), "Holder key binding", desc?.ifBlank { "device key" } ?: "device key"))
            }
            "status" -> {
                val sl = (value as? JSONObject)?.optJSONObject("status_list")
                val desc = if (sl != null && sl.has("idx")) "Token Status List #${sl.optInt("idx")}" else "Token Status List"
                listOf(DisclosedClaim(listOf("status"), "Revocation reference", desc))
            }
            else -> flattenAlwaysShared(listOf(key), key, value)
        }
    }

    private fun flattenAlwaysShared(path: List<String>, rawLabel: String, node: Any?): List<DisclosedClaim> = when (node) {
        is JSONObject -> node.keys().asSequence()
            .filter { it != "_sd" && it != "_sd_alg" }
            .flatMap { flattenAlwaysShared(path + it, "$rawLabel $it", node.get(it)).asSequence() }
            .toList()
        is JSONArray -> emptyList() // arrays are rare in the issuer payload metadata; skip in the summary
        null, JSONObject.NULL -> emptyList()
        else -> listOf(DisclosedClaim(path, humanize(rawLabel), node.toString()))
    }

    private fun pathOf(claim: JSONObject): List<String> {
        val arr = claim.getJSONArray("path")
        return (0 until arr.length()).map { arr.getString(it) }
    }

    /** Stringify a leaf claim value; objects/arrays render as their JSON. */
    private fun stringifyValue(value: Any?): String = when (value) {
        null, JSONObject.NULL -> ""
        else -> value.toString()
    }

    /** `urn:tcc:mec:UniversityDiploma:1` → "University Diploma". */
    private fun humanizeVct(vct: String): String {
        val token = vct.split(':').lastOrNull { it.isNotBlank() && !it.all(Char::isDigit) } ?: vct
        return token.replace(CAMEL_BOUNDARY, " ").ifBlank { vct }
    }

    private fun epochDate(value: Any?): String? {
        val seconds = (value as? Number)?.toLong() ?: return null
        if (seconds <= 0L) return null
        return java.time.Instant.ofEpochSecond(seconds)
            .atZone(java.time.ZoneId.systemDefault())
            .format(DAY_DATE_FMT)
    }

    /** `full_name` → `Full name`, `student_id` → `Student id`. */
    private fun humanize(leaf: String): String =
        leaf.replace('_', ' ').replaceFirstChar { it.uppercase() }
}
