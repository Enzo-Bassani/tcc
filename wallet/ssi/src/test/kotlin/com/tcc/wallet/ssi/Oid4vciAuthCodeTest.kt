package com.tcc.wallet.ssi

import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import com.tcc.wallet.ssi.net.Oid4vciClient
import com.tcc.wallet.ssi.net.OfferLink
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Exercises the OID4VCI **authorization-code** flow of [Oid4vciClient] headlessly
 * (JDK only) against an in-process issuer stub:
 *  - [prepareAuthorization] emits the exact PKCE pair + `/authorize` query the Rust
 *    issuer's `verify_pkce` validates (`base64url(sha256(code_verifier)) == code_challenge`);
 *  - [completeAuthorization] sends the `authorization_code` grant with the matching
 *    `code_verifier` and returns the served SD-JWT.
 * Plus table tests for grant + scan classification.
 */
class Oid4vciAuthCodeTest {

    /** A no-op engine: the credential tail only needs a proof string back. */
    private val stubEngine = object : SsiEngine {
        override fun buildVciProof(credentialIssuer: String, cNonce: String, holder: HolderKey): String =
            "proof.$cNonce"
        override fun createVpToken(request: JSONObject, credentials: List<StoredCredential>) = JSONObject()
        override fun createResponse(request: JSONObject, credentials: List<StoredCredential>, selection: Map<String, Int>) = JSONObject()
        override fun findMatches(request: JSONObject, credentials: List<StoredCredential>) = emptyList<QueryMatch>()
        override fun readCredential(sdJwt: String) = JSONObject()
    }

    private val holder: HolderKey = SoftwareHolderKey.generate()

    private fun offer(issuer: String): JSONObject = JSONObject(
        """
        {"credential_issuer":"$issuer",
         "credential_configuration_ids":["UniversityDiplomaSdJwt"],
         "grants":{"authorization_code":{}}}
        """.trimIndent(),
    )

    /** Issuer stub: the two `.well-known` docs plus /token, /nonce, /credential.
     *  Records the last /token form body for assertions. */
    private class IssuerStub {
        val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val base: String get() = "http://127.0.0.1:${server.address.port}"
        var tokenForm: Map<String, String> = emptyMap()
        val sdJwt = "issuer~jwt~disclosures"

        init {
            json("/.well-known/openid-credential-issuer") {
                JSONObject()
                    .put("credential_issuer", base)
                    .put("credential_endpoint", "$base/credential")
                    .put("nonce_endpoint", "$base/nonce")
                    .toString()
            }
            json("/.well-known/oauth-authorization-server") {
                JSONObject()
                    .put("issuer", base)
                    .put("authorization_endpoint", "$base/authorize")
                    .put("token_endpoint", "$base/token")
                    .toString()
            }
            server.createContext("/token") { ex ->
                tokenForm = parseForm(readBody(ex))
                reply(ex, JSONObject().put("access_token", "tok-123").put("token_type", "Bearer").toString())
            }
            json("/nonce") { JSONObject().put("c_nonce", "nonce-xyz").toString() }
            server.createContext("/credential") { ex ->
                val resp = JSONObject().put(
                    "credentials",
                    org.json.JSONArray().put(JSONObject().put("credential", sdJwt)),
                )
                reply(ex, resp.toString())
            }
            server.start()
        }

        private fun json(path: String, body: () -> String) =
            server.createContext(path) { ex -> reply(ex, body()) }

        private fun reply(ex: HttpExchange, body: String) {
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }

        private fun readBody(ex: HttpExchange): String =
            ex.requestBody.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }

        private fun parseForm(body: String): Map<String, String> =
            body.split('&').filter { it.contains('=') }.associate {
                val (k, v) = it.split('=', limit = 2)
                URLDecoder.decode(k, "UTF-8") to URLDecoder.decode(v, "UTF-8")
            }

        fun stop() = server.stop(0)
    }

    private fun queryOf(url: String): Map<String, String> =
        OfferLink.parseQuery(url.substringAfter('?'))

    @Test
    fun `prepareAuthorization emits a valid PKCE S256 authorize URL`() {
        val stub = IssuerStub()
        try {
            val pending = Oid4vciClient().prepareAuthorization(offer(stub.base), "com.tcc.wallet://oid4vci")
            val q = queryOf(pending.authorizationUrl)

            assertTrue(pending.authorizationUrl.startsWith("${stub.base}/authorize?"))
            assertEquals("code", q["response_type"])
            assertEquals("S256", q["code_challenge_method"])
            assertEquals("com.tcc.wallet://oid4vci", q["redirect_uri"])
            assertEquals(pending.state, q["state"])
            // The exact relation the issuer's verify_pkce checks.
            assertEquals(Bytes.sha256B64Url(pending.codeVerifier), q["code_challenge"])

            val details = org.json.JSONArray(q["authorization_details"])
            assertEquals("UniversityDiplomaSdJwt", details.getJSONObject(0).getString("credential_configuration_id"))
            assertEquals("openid_credential", details.getJSONObject(0).getString("type"))

            // HAIP §4.2/§4.3 (VCI-11/VCI-13): credential type communicated via `scope`.
            assertEquals("UniversityDiplomaSdJwt", q["scope"])
        } finally {
            stub.stop()
        }
    }

    @Test
    fun `each prepareAuthorization uses a fresh verifier and state`() {
        val stub = IssuerStub()
        try {
            val a = Oid4vciClient().prepareAuthorization(offer(stub.base), "com.tcc.wallet://oid4vci")
            val b = Oid4vciClient().prepareAuthorization(offer(stub.base), "com.tcc.wallet://oid4vci")
            assertNotEquals(a.codeVerifier, b.codeVerifier)
            assertNotEquals(a.state, b.state)
        } finally {
            stub.stop()
        }
    }

    @Test
    fun `completeAuthorization exchanges the code and returns the SD-JWT`() {
        val stub = IssuerStub()
        try {
            // Disable issuer-credential validation: the stub serves a placeholder SD-JWT, not a
            // real x5c-signed credential (that path is covered by IssuerTrustTest).
            val client = Oid4vciClient(issuerTrust = IssuerTrust.disabled())
            val pending = client.prepareAuthorization(offer(stub.base), "com.tcc.wallet://oid4vci")
            // RFC 9207: the returned `iss` matches the expected issuer.
            val sdJwt = client.completeAuthorization(pending, "auth-code-abc", stub.base, holder, stubEngine)

            assertEquals(stub.sdJwt, sdJwt)
            assertEquals("authorization_code", stub.tokenForm["grant_type"])
            assertEquals("auth-code-abc", stub.tokenForm["code"])
            assertEquals(pending.codeVerifier, stub.tokenForm["code_verifier"])
        } finally {
            stub.stop()
        }
    }

    @Test
    fun `completeAuthorization rejects a mismatched or missing iss (RFC 9207)`() {
        val stub = IssuerStub()
        try {
            val client = Oid4vciClient(issuerTrust = IssuerTrust.disabled())
            val pending = client.prepareAuthorization(offer(stub.base), "com.tcc.wallet://oid4vci")

            // Wrong issuer identifier → rejected before any token exchange.
            assertThrows(IllegalArgumentException::class.java) {
                client.completeAuthorization(pending, "auth-code-abc", "https://evil.example", holder, stubEngine)
            }
            // Missing `iss` is likewise rejected (the AS MUST send it).
            assertThrows(IllegalArgumentException::class.java) {
                client.completeAuthorization(pending, "auth-code-abc", null, holder, stubEngine)
            }
        } finally {
            stub.stop()
        }
    }

    @Test
    fun `detectGrant reads the offer's grants`() {
        val auth = JSONObject("""{"grants":{"authorization_code":{}}}""")
        val pre = JSONObject("""{"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"x"}}}""")
        val none = JSONObject("{}")
        assertEquals(Oid4vciClient.Grant.AuthorizationCode, Oid4vciClient.detectGrant(auth))
        assertEquals(Oid4vciClient.Grant.PreAuthorized, Oid4vciClient.detectGrant(pre))
        assertEquals(Oid4vciClient.Grant.PreAuthorized, Oid4vciClient.detectGrant(none))
    }
}
