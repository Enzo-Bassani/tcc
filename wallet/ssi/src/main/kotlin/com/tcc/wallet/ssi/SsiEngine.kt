package com.tcc.wallet.ssi

import org.json.JSONObject

/** One credential the wallet holds: the issued compact SD-JWT and the holder key
 *  whose public JWK is its `cnf`. */
data class StoredCredential(val sdJwt: String, val holder: HolderKey)

/** One claim a credential would disclose to answer a DCQL query, with its leaf
 *  [path], a human [label] (humanized leaf name), and the actual [value] — for the
 *  presentation consent screen. */
data class DisclosedClaim(val path: List<String>, val label: String, val value: String)

/** A held credential that satisfies a DCQL credential query: its [index] in the
 *  wallet list, the compact [sdJwt], its [vct], the [disclosed] claims/values it would
 *  reveal if chosen, and the [alwaysShared] claims that travel with **every**
 *  presentation of it (the non-selectively-disclosable issuer-JWT payload — credential
 *  type, issuer, validity, revocation pointer, holder key binding, institution …),
 *  which the holder cannot withhold. */
data class MatchedCredential(
    val index: Int,
    val sdJwt: String,
    val vct: String,
    val disclosed: List<DisclosedClaim>,
    val alwaysShared: List<DisclosedClaim>,
)

/** All held credentials that satisfy one DCQL credential query (`queryId`/`vct`).
 *  More than one [matches] entry is what drives the wallet's "choose which
 *  credential to present" step. */
data class QueryMatch(val queryId: String, val vct: String?, val matches: List<MatchedCredential>)

/**
 * The holder's SSI operations, behind an interface so the implementation can be
 * swapped without touching the app (the "Hybrid" strategy):
 *
 * - [KotlinSsiEngine] — the Phase-1 pure-Kotlin implementation (here).
 * - a future `RustSsiEngine` — Phase 2, calling `ssi-core` over UniFFI for exact
 *   parity. The same conformance oracle (`crates/wallet-core`) guards both.
 *
 * Everything here is framework-agnostic: no Android, no HTTP, no storage — those
 * live in the `:app` module and the `net` package.
 */
interface SsiEngine {

    /** The OID4VCI holder-binding proof JWT (`typ: openid4vci-proof+jwt`) for the
     *  Nonce-Endpoint `c_nonce`. Its `jwk` header becomes the credential's `cnf`. */
    fun buildVciProof(credentialIssuer: String, cNonce: String, holder: HolderKey): String

    /** Build the OID4VP VP Token answering [request] with [credentials]:
     *  `{ "<dcql-id>": ["<issuer-jwt>~<disclosures>~<kb-jwt>"] }`. */
    fun createVpToken(request: JSONObject, credentials: List<StoredCredential>): JSONObject

    /** Build the full Authorization Response for a (verified) [request]: the VP Token
     *  JWE-encrypted to the verifier's ephemeral key for `direct_post.jwt`
     *  (`{"response":"<JWE>"}`), or the plain `{vp_token, state}` otherwise.
     *
     *  [selection] maps a DCQL `queryId` to the **index** (into [credentials]) of the
     *  credential the holder chose for that query. Queries absent from the map fall
     *  back to the first held credential that satisfies them. */
    fun createResponse(
        request: JSONObject,
        credentials: List<StoredCredential>,
        selection: Map<String, Int> = emptyMap(),
    ): JSONObject

    /** For each DCQL credential query in [request], every held credential that can
     *  satisfy it together with the claims/values it would disclose. The UI shows the
     *  matches so the holder can choose when more than one credential qualifies. */
    fun findMatches(request: JSONObject, credentials: List<StoredCredential>): List<QueryMatch>

    /** The full (all-disclosures-applied) claim set of a stored SD-JWT, for display. */
    fun readCredential(sdJwt: String): JSONObject
}
