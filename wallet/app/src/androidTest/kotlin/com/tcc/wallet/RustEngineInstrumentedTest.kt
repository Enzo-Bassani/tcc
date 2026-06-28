package com.tcc.wallet

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.tcc.wallet.ssi.RustSsiEngine
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.util.Base64

/**
 * Tier-3 on-device check (the one thing the host-JVM parity tests cannot cover):
 * the UniFFI native engine (`libwallet_ffi`) loads under Android via JNA, and a
 * **non-exportable AndroidKeyStore** holder key signs through the `ForeignSigner`
 * callback to produce a *cryptographically valid* ES256 proof. This proves the
 * full FFI + Keystore signing path works on a real device/emulator.
 */
@RunWith(AndroidJUnit4::class)
class RustEngineInstrumentedTest {

    @Test
    fun keystoreSignerProducesAValidProofThroughTheRustEngine() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        // A non-exportable Keystore key (TEE/StrongBox), under a test alias.
        val holder = KeystoreHolderKey.getOrCreate(context, alias = "test_holder_es256")
        val engine = RustSsiEngine()

        // The engine frames the JWS in Rust and calls back to the Keystore only to sign.
        val proof = engine.buildVciProof("https://issuer.example", "nonce-123", holder)

        val parts = proof.split(".")
        assertEquals("a compact JWS has three parts", 3, parts.size)

        val header = JSONObject(String(b64urlDecode(parts[0])))
        assertEquals("ES256", header.getString("alg"))
        assertEquals("openid4vci-proof+jwt", header.getString("typ"))
        // The proof self-attests its key: the embedded jwk equals the holder's. Compared
        // field-by-field (it round-trips through the FFI's sorted JSON, so key order differs,
        // and Android's platform org.json has no structural `similar`).
        val jwk = header.getJSONObject("jwk")
        val expected = holder.publicJwk()
        for (field in listOf("kty", "crv", "x", "y")) {
            assertEquals("jwk.$field", expected.getString(field), jwk.getString(field))
        }

        // The Keystore signature actually verifies under the holder's public key —
        // i.e. the bytes the engine signed match what it framed.
        val signingInput = "${parts[0]}.${parts[1]}".toByteArray(Charsets.US_ASCII)
        val signature = b64urlDecode(parts[2])
        assertTrue(
            "the Keystore-signed proof must verify under the holder's public key",
            verifyEs256(signingInput, signature, header.getJSONObject("jwk")),
        )
    }

    private fun b64urlDecode(s: String): ByteArray = Base64.getUrlDecoder().decode(s)

    /** Verify an ES256 (P-256) signature in JOSE raw R‖S form against an EC public JWK. */
    private fun verifyEs256(message: ByteArray, joseSig: ByteArray, jwk: JSONObject): Boolean {
        val x = BigInteger(1, b64urlDecode(jwk.getString("x")))
        val y = BigInteger(1, b64urlDecode(jwk.getString("y")))
        // P-256 parameters via a generated keypair's spec (avoids hard-coding the curve).
        val params = java.security.AlgorithmParameters.getInstance("EC").apply {
            init(java.security.spec.ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(java.security.spec.ECParameterSpec::class.java)
        val pub = KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
        return Signature.getInstance("SHA256withECDSA").run {
            initVerify(pub)
            update(message)
            verify(joseToDer(joseSig))
        }
    }

    /** JOSE raw R‖S (64 bytes) → DER ECDSA-Sig-Value, the form java.security expects. */
    private fun joseToDer(jose: ByteArray): ByteArray {
        val n = jose.size / 2
        val r = trimInt(jose.copyOfRange(0, n))
        val s = trimInt(jose.copyOfRange(n, jose.size))
        val body = ByteArrayOutputStream().apply {
            write(0x02); write(r.size); write(r)
            write(0x02); write(s.size); write(s)
        }.toByteArray()
        return ByteArrayOutputStream().apply {
            write(0x30); write(body.size); write(body)
        }.toByteArray()
    }

    /** Strip leading zero bytes and re-pad so the integer stays positive (DER INTEGER). */
    private fun trimInt(b: ByteArray): ByteArray {
        var i = 0
        while (i < b.size - 1 && b[i] == 0.toByte()) i++
        val trimmed = b.copyOfRange(i, b.size)
        return if (trimmed[0].toInt() and 0x80 != 0) byteArrayOf(0) + trimmed else trimmed
    }
}
