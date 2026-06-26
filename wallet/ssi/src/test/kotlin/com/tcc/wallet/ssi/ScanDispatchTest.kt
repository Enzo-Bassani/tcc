package com.tcc.wallet.ssi

import com.tcc.wallet.ssi.net.ScanDispatch
import com.tcc.wallet.ssi.net.ScanDispatch.Kind
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

/** A scanned QR / pasted link must route to the right flow: issuance vs presentation. */
class ScanDispatchTest {

    @Test
    fun `classifies by scheme`() {
        assertEquals(Kind.Issuance, ScanDispatch.classify("openid-credential-offer://?credential_offer_uri=https://i/o"))
        assertEquals(Kind.Presentation, ScanDispatch.classify("openid4vp://?client_id=did:jwk:..&request_uri=https://r/x"))
    }

    @Test
    fun `classifies bare offer JSON as issuance`() {
        val offer = """{"credential_issuer":"https://i","credential_configuration_ids":["X"],"grants":{}}"""
        assertEquals(Kind.Issuance, ScanDispatch.classify(offer))
    }

    @Test
    fun `classifies a request object JSON as presentation`() {
        val req = """{"client_id":"did:jwk:..","response_uri":"https://r/x","dcql_query":{}}"""
        assertEquals(Kind.Presentation, ScanDispatch.classify(req))
    }

    @Test
    fun `unknown input is Unknown`() {
        assertEquals(Kind.Unknown, ScanDispatch.classify(""))
        assertEquals(Kind.Unknown, ScanDispatch.classify("https://example.com/whatever"))
    }
}
