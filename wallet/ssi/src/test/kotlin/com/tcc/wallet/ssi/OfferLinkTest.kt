package com.tcc.wallet.ssi

import com.sun.net.httpserver.HttpServer
import com.tcc.wallet.ssi.net.OfferLink
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.net.InetSocketAddress
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Covers OID4VCI Credential Offer resolution — both the pure parsing branches
 * (inline JSON, `credential_offer` deep links) and the fetch branches
 * (`credential_offer_uri`, bare URI), the latter against an in-process HTTP
 * server so the real [com.tcc.wallet.ssi.net.Http] client is exercised too.
 */
class OfferLinkTest {

    private val sampleOffer = """
        {"credential_issuer":"https://issuer.example",
         "credential_configuration_ids":["UniversityDiplomaSdJwt"],
         "grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc 123/x"}}}
    """.trimIndent()

    private fun enc(s: String) = URLEncoder.encode(s, "UTF-8")

    /** Run `block` with a one-shot HTTP server serving `body` (JSON) at `path`,
     *  passing it the base URL; the server is always stopped afterwards. */
    private fun <T> withServer(path: String, body: String, block: (base: String) -> T): T {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext(path) { ex ->
            val bytes = body.toByteArray(StandardCharsets.UTF_8)
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, bytes.size.toLong())
            ex.responseBody.use { it.write(bytes) }
        }
        server.start()
        try {
            return block("http://127.0.0.1:${server.address.port}")
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `inline JSON is parsed directly`() {
        val offer = OfferLink.resolve(sampleOffer)
        assertEquals("https://issuer.example", offer.getString("credential_issuer"))
    }

    @Test
    fun `deep link with inline credential_offer is url-decoded and parsed`() {
        val link = "openid-credential-offer://?credential_offer=${enc(sampleOffer)}"
        val offer = OfferLink.resolve(link)
        // The pre-authorized code contains a space and a slash — proves URL decoding.
        val code = offer.getJSONObject("grants")
            .getJSONObject("urn:ietf:params:oauth:grant-type:pre-authorized_code")
            .getString("pre-authorized_code")
        assertEquals("abc 123/x", code)
    }

    @Test
    fun `inline credential_offer takes precedence over a uri`() {
        // Both params present: the inline offer must win (no fetch attempted, so the
        // unreachable URI is never dialed).
        val link = "openid-credential-offer://?credential_offer=${enc(sampleOffer)}" +
            "&credential_offer_uri=${enc("http://127.0.0.1:1/never")}"
        val offer = OfferLink.resolve(link)
        assertEquals("https://issuer.example", offer.getString("credential_issuer"))
    }

    @Test
    fun `deep link with credential_offer_uri is fetched over HTTP`() = withServer("/offer", sampleOffer) { base ->
        val link = "openid-credential-offer://?credential_offer_uri=${enc("$base/offer")}"
        val offer = OfferLink.resolve(link)
        assertEquals(
            "UniversityDiplomaSdJwt",
            offer.getJSONArray("credential_configuration_ids").getString(0),
        )
    }

    @Test
    fun `a bare URI is fetched as the offer JSON`() = withServer("/o", sampleOffer) { base ->
        val offer: JSONObject = OfferLink.resolve("$base/o")
        assertEquals("https://issuer.example", offer.getString("credential_issuer"))
    }
}
