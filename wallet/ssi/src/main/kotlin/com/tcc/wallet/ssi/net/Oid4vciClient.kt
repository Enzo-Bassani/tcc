package com.tcc.wallet.ssi.net

import com.tcc.wallet.ssi.Bytes
import com.tcc.wallet.ssi.HolderKey
import com.tcc.wallet.ssi.IssuerTrust
import com.tcc.wallet.ssi.SsiEngine
import org.json.JSONArray
import org.json.JSONObject
import java.net.URLEncoder
import java.security.SecureRandom

/**
 * OID4VCI 1.0 **client** (the issuance half). Drives
 * discovery → token → nonce → credential, returning the compact SD-JWT VC to
 * store. The holder-binding proof is built by the [SsiEngine].
 *
 * Two grants are supported:
 *  - **Pre-authorized** ([receive]) — needs no browser; the offer carries the code.
 *  - **Authorization code** ([prepareAuthorization] + [completeAuthorization]) —
 *    needs a browser round-trip to the issuer's `/authorize` → mock-SSO, with
 *    PKCE S256. Split in two so the Android `:app` can open a browser between the
 *    two halves and resume on the redirect.
 *
 * No `tx_code`, and `invalid_nonce` triggers one fresh-nonce retry — shared by
 * both flows via [fetchCredential].
 *
 * On receipt the issuer credential is **validated** ([IssuerTrust]) before it is
 * returned to be stored: HAIP §6.1.1 `x5c` resolution + chain validation to a
 * trusted root + `iss`↔leaf binding. An invalid credential is rejected, never stored.
 */
class Oid4vciClient(
    private val http: Http = Http(),
    private val issuerTrust: IssuerTrust = IssuerTrust.default(),
) {

    /** Which OID4VCI grant a resolved offer asks the wallet to run. */
    enum class Grant { PreAuthorized, AuthorizationCode }

    /**
     * Opaque continuation for the authorization-code flow: everything
     * [completeAuthorization] needs after the browser redirect. Held in memory
     * across the browser trip (process-death persistence is deferred); the
     * PKCE [codeVerifier] never leaves the device.
     */
    data class AuthPending(
        val credentialIssuer: String,
        val configId: String,
        val authorizationUrl: String,
        val tokenEndpoint: String,
        val credentialEndpoint: String,
        val nonceEndpoint: String,
        val codeVerifier: String,
        val state: String,
        val redirectUri: String,
    )

    /** Run the pre-authorized flow for a resolved Credential Offer and return the SD-JWT VC. */
    fun receive(offer: JSONObject, holder: HolderKey, engine: SsiEngine): String {
        val issuer = offer.getString("credential_issuer")
        val configId = offer.getJSONArray("credential_configuration_ids").getString(0)
        val preAuthCode = offer.getJSONObject("grants")
            .getJSONObject(PRE_AUTH_GRANT)
            .getString("pre-authorized_code")

        val meta = discover(issuer)

        // Token (pre-authorized code; no c_nonce here in OID4VCI 1.0).
        val token = http.postForm(
            meta.tokenEndpoint,
            mapOf("grant_type" to PRE_AUTH_GRANT, "pre-authorized_code" to preAuthCode),
        ).json().getString("access_token")

        return fetchCredential(issuer, configId, meta.credentialEndpoint, meta.nonceEndpoint, token, holder, engine)
    }

    /**
     * Phase 1 of the authorization-code flow: discover endpoints, generate a PKCE
     * `code_verifier`/S256 `code_challenge` and a random `state`, and build the
     * `/authorize` URL the caller opens in a browser. Returns the [AuthPending]
     * continuation; does no user-blocking I/O beyond the two metadata GETs.
     */
    fun prepareAuthorization(offer: JSONObject, redirectUri: String): AuthPending {
        val issuer = offer.getString("credential_issuer")
        val configId = offer.getJSONArray("credential_configuration_ids").getString(0)

        val meta = discover(issuer)
        val authorizationEndpoint = meta.authorizationEndpoint
            ?: error("issuer advertises no authorization_endpoint")

        val codeVerifier = randomToken()
        val codeChallenge = Bytes.sha256B64Url(codeVerifier)
        val state = randomToken()

        val authorizationDetails = JSONArray().put(
            JSONObject()
                .put("type", "openid_credential")
                .put("credential_configuration_id", configId),
        )

        val url = buildUrl(
            authorizationEndpoint,
            linkedMapOf(
                "response_type" to "code",
                "client_id" to CLIENT_ID,
                "redirect_uri" to redirectUri,
                "code_challenge" to codeChallenge,
                "code_challenge_method" to "S256",
                "state" to state,
                // HAIP §4.2/§4.3 (VCI-11/VCI-13): the credential type MUST be
                // communicated via the OAuth `scope`; the scope value equals the
                // credential_configuration_id advertised in issuer metadata.
                "scope" to configId,
                "authorization_details" to authorizationDetails.toString(),
            ),
        )

        return AuthPending(
            credentialIssuer = issuer,
            configId = configId,
            authorizationUrl = url,
            tokenEndpoint = meta.tokenEndpoint,
            credentialEndpoint = meta.credentialEndpoint,
            nonceEndpoint = meta.nonceEndpoint,
            codeVerifier = codeVerifier,
            state = state,
            redirectUri = redirectUri,
        )
    }

    /**
     * Phase 2 of the authorization-code flow: exchange the redirect's `code`
     * (with the stored PKCE verifier) for an access token, then run the shared
     * nonce → credential tail. Returns the compact SD-JWT VC.
     */
    fun completeAuthorization(
        pending: AuthPending,
        code: String,
        iss: String?,
        holder: HolderKey,
        engine: SsiEngine,
    ): String {
        // RFC 9207 (HAIP §4): the authorization server MUST return its issuer
        // identifier as `iss` in the authorization response. Verify it matches the
        // expected issuer (mix-up defence); reject when absent or mismatched.
        require(iss == pending.credentialIssuer) {
            "authorization response iss mismatch: expected ${pending.credentialIssuer}, got $iss"
        }
        val token = http.postForm(
            pending.tokenEndpoint,
            mapOf(
                "grant_type" to AUTH_CODE_GRANT,
                "code" to code,
                "code_verifier" to pending.codeVerifier,
                "redirect_uri" to pending.redirectUri,
            ),
        ).json().getString("access_token")

        return fetchCredential(
            pending.credentialIssuer, pending.configId,
            pending.credentialEndpoint, pending.nonceEndpoint, token, holder, engine,
        )
    }

    // --- internals ------------------------------------------------------------

    private data class Discovery(
        val authorizationEndpoint: String?,
        val tokenEndpoint: String,
        val credentialEndpoint: String,
        val nonceEndpoint: String,
    )

    /** Read issuer + AS metadata (OID4VCI 1.0 puts the nonce endpoint in issuer metadata). */
    private fun discover(issuer: String): Discovery {
        val issuerMeta = http.getJson("$issuer/.well-known/openid-credential-issuer")
        // HAIP §4.1 / OID4VCI §11.2.3: if the issuer serves `signed_metadata`, authenticate the
        // issuer beyond TLS by verifying the JWT (x5c chain → trusted anchor, ES256 leaf signature,
        // iss↔leaf binding) and binding it to the credential_issuer we are talking to. Reject a
        // forged/wrong-issuer document — never proceed with unauthenticated issuer metadata.
        issuerMeta.optString("signed_metadata").takeIf { it.isNotBlank() }?.let { signed ->
            issuerTrust.verifySignedMetadata(signed, issuer)
        }
        val asMeta = http.getJson("$issuer/.well-known/oauth-authorization-server")
        return Discovery(
            authorizationEndpoint = asMeta.optString("authorization_endpoint").takeIf { it.isNotBlank() },
            tokenEndpoint = asMeta.getString("token_endpoint"),
            credentialEndpoint = issuerMeta.getString("credential_endpoint"),
            nonceEndpoint = issuerMeta.optString("nonce_endpoint", "$issuer/nonce"),
        )
    }

    /** Nonce → proof → credential, with a single invalid_nonce retry. */
    private fun fetchCredential(
        issuer: String,
        configId: String,
        credentialEndpoint: String,
        nonceEndpoint: String,
        token: String,
        holder: HolderKey,
        engine: SsiEngine,
    ): String {
        var lastError = ""
        repeat(2) {
            val cNonce = http.postJson(nonceEndpoint, JSONObject(), null).json().getString("c_nonce")
            val proof = engine.buildVciProof(issuer, cNonce, holder)
            val body = JSONObject()
                .put("credential_configuration_id", configId)
                .put("proofs", JSONObject().put("jwt", JSONArray().put(proof)))

            val resp = http.postJson(credentialEndpoint, body, token)
            if (resp.ok) {
                val credential = resp.json().getJSONArray("credentials").getJSONObject(0).getString("credential")
                // HAIP x5c validation at receipt: reject (never store) an untrustworthy credential.
                issuerTrust.verifyCredential(credential)
                return credential
            }
            lastError = resp.body
            val error = runCatching { resp.json().optString("error") }.getOrDefault("")
            if (error != "invalid_nonce") throw IllegalStateException("credential request failed: ${resp.body}")
            // else: loop once more with a fresh c_nonce.
        }
        throw IllegalStateException("credential request failed after nonce retry: $lastError")
    }

    private fun randomToken(): String {
        val bytes = ByteArray(32)
        RNG.nextBytes(bytes)
        return Bytes.b64url(bytes)
    }

    private fun buildUrl(endpoint: String, params: Map<String, String>): String {
        val query = params.entries.joinToString("&") { (k, v) ->
            "${URLEncoder.encode(k, "UTF-8")}=${URLEncoder.encode(v, "UTF-8")}"
        }
        return if ('?' in endpoint) "$endpoint&$query" else "$endpoint?$query"
    }

    companion object {
        private const val PRE_AUTH_GRANT = "urn:ietf:params:oauth:grant-type:pre-authorized_code"
        private const val AUTH_CODE_GRANT = "authorization_code"
        private const val CLIENT_ID = "tcc-wallet"
        private val RNG = SecureRandom()

        /** Inspect a resolved offer's `grants` and pick the flow; defaults to pre-authorized. */
        fun detectGrant(offer: JSONObject): Grant {
            val grants = offer.optJSONObject("grants")
            return when {
                grants?.has(PRE_AUTH_GRANT) == true -> Grant.PreAuthorized
                grants?.has(AUTH_CODE_GRANT) == true -> Grant.AuthorizationCode
                else -> Grant.PreAuthorized
            }
        }
    }
}
