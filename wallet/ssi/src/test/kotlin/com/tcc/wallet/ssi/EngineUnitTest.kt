package com.tcc.wallet.ssi

import org.json.JSONArray
import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

/**
 * Fast, self-contained checks of the wire-format building blocks — no Rust, no
 * network. These run on any machine with a JDK; the cross-language guarantee is
 * in [ConformanceTest].
 */
class EngineUnitTest {

    @Test
    fun `base64url is unpadded and round-trips`() {
        val data = byteArrayOf(1, 2, 3, 4, 5)
        val enc = Bytes.b64url(data)
        assertFalse(enc.contains('='), "base64url must be unpadded")
        assertTrue(Bytes.b64urlDecode(enc).contentEquals(data))
    }

    @Test
    fun `holder key round-trips through its scalar`() {
        val key = SoftwareHolderKey.generate()
        val same = SoftwareHolderKey.fromScalar(key.scalar)
        assertTrue(key.scalar.contentEquals(same.scalar))
        // Same private scalar → same EC public point (x and y).
        assertEquals(key.publicJwk().getString("x"), same.publicJwk().getString("x"))
        assertEquals(key.publicJwk().getString("y"), same.publicJwk().getString("y"))
        assertEquals("EC", key.publicJwk().getString("kty"))
        assertEquals("P-256", key.publicJwk().getString("crv"))
    }

    @Test
    fun `ES256 signature is 64 bytes over the signing input`() {
        val key = SoftwareHolderKey.generate()
        val jws = Jws.signEs256(JSONObject().put("alg", "ES256"), JSONObject().put("hello", "world"), key)
        val parts = jws.split('.')
        assertEquals(3, parts.size)
        assertEquals(64, Bytes.b64urlDecode(parts[2]).size, "JOSE ES256 signature is raw R‖S (32+32)")
        val (h, p) = Jws.decodeUnverified(jws)
        assertEquals("ES256", h.getString("alg"))
        assertEquals("world", p.getString("hello"))
    }

    @Test
    fun `reconstruct merges disclosures and drops the _sd machinery`() {
        // Build a payload with one disclosable claim, mimicking the issuer.
        val name = "given_name"
        val value = "Ada"
        val salt = Bytes.b64url(ByteArray(16) { 7 })
        val disclosure = Bytes.b64url(JSONArray().put(salt).put(name).put(value).toString().toByteArray())
        val digest = SdJwt.digest(disclosure)
        val payload = JSONObject()
            .put("vct", "demo")
            .put("_sd", JSONArray().put(digest))
            .put("_sd_alg", "sha-256")

        val full = SdJwt.reconstruct(payload, listOf(disclosure))
        assertEquals("Ada", full.getString("given_name"))
        assertEquals("demo", full.getString("vct"))
        assertFalse(full.has("_sd"))
        assertFalse(full.has("_sd_alg"))
        assertEquals(name, SdJwt.disclosureName(disclosure))
    }

    @Test
    fun `JWE round-trips for both content-encryption algorithms`() {
        // The recipient (verifier) key pair, as a private JWK with d (+ public x/y).
        val key = SoftwareHolderKey.generate()
        val pubJwk = key.publicJwk()
        val privJwk = JSONObject(pubJwk.toString()).put("d", Bytes.b64url(key.scalar))

        for (enc in listOf("A128GCM", "A256GCM")) {
            val msg = """{"vp_token":{"diploma":["a~b~kb"]},"state":"s1"}""".toByteArray()
            val jwe = Jwe.encrypt(pubJwk, "verifier-enc-1", enc, msg)
            assertEquals(5, jwe.split('.').size, "compact JWE has 5 parts")
            assertEquals("", jwe.split('.')[1], "ECDH-ES has an empty Encrypted Key")
            assertFalse(jwe.contains("vp_token"), "ciphertext must not leak plaintext")
            assertTrue(Jwe.decrypt(jwe, privJwk).contentEquals(msg))
        }
    }

    @Test
    fun `did jwk JAR verification accepts a good request and rejects a bad client_id`() {
        // Resolving a did:jwk just base64url-decodes the embedded JWK.
        val key = SoftwareHolderKey.generate()
        val pubJwk = key.publicJwk()
        val did = "did:jwk:" + Bytes.b64url(pubJwk.toString().toByteArray())
        val clientId = "decentralized_identifier:$did"
        val resolved = Jar.resolveDidJwk(clientId)
        assertEquals(pubJwk.getString("x"), resolved.getString("x"))

        // Sign a request object with that key (as the verifier's JAR would be).
        val header = JSONObject().put("alg", "ES256").put("kid", "$did#0").put("typ", "oauth-authz-req+jwt")
        val payload = JSONObject().put("client_id", clientId).put("nonce", "n1").put("response_uri", "https://v/r")
        val jwt = Jws.signEs256(header, payload, key)

        val verified = Jar.verifyRequest(jwt, clientId)
        assertEquals("n1", verified.getString("nonce"))

        // A different (attacker) did:jwk client_id must not verify the same JWT.
        val attacker = "decentralized_identifier:did:jwk:" +
            Bytes.b64url(SoftwareHolderKey.generate().publicJwk().toString().toByteArray())
        assertThrows(IllegalArgumentException::class.java) { Jar.verifyRequest(jwt, attacker) }
    }

    @Test
    fun `findMatches lists every matching credential and selection picks the chosen one`() {
        val holder = SoftwareHolderKey.generate()
        val credA = buildCredential(holder, "demo", linkedMapOf("full_name" to "Ada", "degree" to "BSc"))
        val credB = buildCredential(holder, "demo", linkedMapOf("full_name" to "Bob", "degree" to "MSc"))
        val wallet = listOf(StoredCredential(credA, holder), StoredCredential(credB, holder))

        val request = JSONObject(
            """
            { "client_id":"c", "nonce":"n",
              "dcql_query": { "credentials": [
                { "id":"d", "format":"dc+sd-jwt", "meta": {"vct_values":["demo"]},
                  "claims": [ {"path":["full_name"]}, {"path":["degree"]} ] } ] } }
            """.trimIndent(),
        )
        val engine = KotlinSsiEngine()

        val matches = engine.findMatches(request, wallet)
        assertEquals(1, matches.size)
        assertEquals(2, matches[0].matches.size, "both credentials satisfy the query")
        assertEquals("Ada", matches[0].matches[0].disclosed.first { it.label == "Full name" }.value)
        assertEquals("Bob", matches[0].matches[1].disclosed.first { it.label == "Full name" }.value)

        // The non-selective payload claims that travel regardless of the holder's choice.
        val alwaysShared = matches[0].matches[0].alwaysShared
        assertTrue(alwaysShared.any { it.label == "Credential type" }, "vct is always shared")
        assertTrue(alwaysShared.any { it.label == "Holder key binding" }, "cnf is always shared")

        // Selecting index 1 (credB) must put credB's issuer JWT in the VP token.
        val chosen = engine.createResponse(request, wallet, mapOf("d" to 1))
        val chosenPres = chosen.getJSONObject("vp_token").getJSONArray("d").getString(0)
        assertTrue(chosenPres.startsWith(credB.substringBefore('~')), "selection must present credB")

        // No selection falls back to the first match (credA).
        val fallback = engine.createResponse(request, wallet)
        val fallbackPres = fallback.getJSONObject("vp_token").getJSONArray("d").getString(0)
        assertTrue(fallbackPres.startsWith(credA.substringBefore('~')), "default presents the first match")
    }

    /** Assemble a minimal compact SD-JWT: each claim is a leaf disclosure whose digest
     *  is listed in the payload `_sd`, bound to [holder]'s key as `cnf`. */
    private fun buildCredential(holder: HolderKey, vct: String, claims: Map<String, String>): String {
        val disclosures = ArrayList<String>()
        val sd = JSONArray()
        for ((name, value) in claims) {
            val salt = Bytes.b64url(ByteArray(16) { (name.hashCode() + it).toByte() })
            val d = Bytes.b64url(JSONArray().put(salt).put(name).put(value).toString().toByteArray())
            disclosures.add(d)
            sd.put(SdJwt.digest(d))
        }
        val payload = JSONObject()
            .put("vct", vct)
            .put("_sd", sd)
            .put("_sd_alg", "sha-256")
            .put("cnf", JSONObject().put("jwk", holder.publicJwk()))
        val header = JSONObject().put("alg", "ES256").put("typ", "dc+sd-jwt")
        val issuerJwt = Jws.signEs256(header, payload, holder)
        return buildString {
            append(issuerJwt)
            for (d in disclosures) { append('~'); append(d) }
        }
    }

    @Test
    fun `DCQL selects requested leaf names and respects vct`() {
        val claims = JSONObject().put("vct", "demo").put("given_name", "Ada").put("degree", "BSc")
        val query = JSONObject(
            """
            { "id":"d", "format":"dc+sd-jwt",
              "meta": { "vct_values": ["demo"] },
              "claims": [ {"path":["given_name"]}, {"path":["degree"]} ] }
            """.trimIndent(),
        )
        assertEquals(listOf("given_name", "degree"), Dcql.resolveWantedLeafNames(query, claims))

        val wrongVct = JSONObject(query.toString()).put("meta", JSONObject().put("vct_values", JSONArray().put("other")))
        assertEquals(null, Dcql.resolveWantedLeafNames(wrongVct, claims))
    }
}
