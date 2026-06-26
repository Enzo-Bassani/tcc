package com.tcc.wallet.ssi

import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.json.JSONObject
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The wallet's holder key: an **ES256** (ECDSA P-256) signer. The public JWK becomes
 * the credential's `cnf.jwk` at issuance; every presentation's
 * key-binding JWT (and the OID4VCI key proof) is signed with the private half.
 *
 * This is the **seam** between key material and the protocol: callers ([KotlinSsiEngine],
 * [Jws.signEs256], the OID4VCI/OID4VP clients) only ever need [sign] and [publicJwk], so
 * the backing is swappable. Two implementations exist:
 *
 *  - [SoftwareHolderKey] — BouncyCastle, scalar in memory. Used by the conformance test
 *    and anywhere that must run on a plain JDK (the `:ssi` module has no Android SDK).
 *  - `KeystoreHolderKey` (Android `:app`) — a non-exportable AndroidKeyStore/StrongBox
 *    key. The HAIP/ARF/EUDI device-binding model; this is what ships in the wallet.
 *
 * ES256/P-256 is the HAIP §7 baseline every conformant wallet must support, and — unlike
 * Ed25519 — it is the algorithm Android Keystore/StrongBox can hardware-back.
 * Signatures are JOSE raw R‖S (64 bytes), matching `ssi_core::crypto::sign_jws_es256` /
 * the `p256` verifier; see [Ec] for the shared encoding both implementations use.
 */
interface HolderKey {

    /** `{"kty":"EC","crv":"P-256","x":"<b64url-32B>","y":"<b64url-32B>"}`. */
    fun publicJwk(): JSONObject

    /** ES256 signature over [message]: ECDSA-P-256/SHA-256, JOSE raw R‖S (64 bytes). */
    fun sign(message: ByteArray): ByteArray
}

/**
 * Software [HolderKey] built on BouncyCastle's JCE provider, so behaviour is identical on a
 * plain JDK (the conformance test) and on Android. The 32-byte private [scalar] is held in
 * memory; on Android the non-exportable `KeystoreHolderKey` is used instead.
 */
class SoftwareHolderKey private constructor(
    private val priv: ECPrivateKey,
    private val pub: ECPublicKey,
) : HolderKey {

    /** The 32-byte big-endian private scalar `d`. Only meaningful for a software key. */
    val scalar: ByteArray
        get() = Ec.toFixed(priv.s, Ec.FIELD_BYTES)

    override fun publicJwk(): JSONObject = Ec.ecPublicJwk(pub)

    override fun sign(message: ByteArray): ByteArray {
        val ecdsa = Signature.getInstance("SHA256withECDSA", BC)
        ecdsa.initSign(priv)
        ecdsa.update(message)
        return Ec.derToJoseRaw(ecdsa.sign(), Ec.FIELD_BYTES)
    }

    companion object {
        private val BC = BouncyCastleProvider()
        private val CURVE = ECNamedCurveTable.getParameterSpec("secp256r1")

        fun generate(): SoftwareHolderKey {
            val gen = KeyPairGenerator.getInstance("EC", BC)
            gen.initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
            val kp = gen.generateKeyPair()
            return SoftwareHolderKey(kp.private as ECPrivateKey, kp.public as ECPublicKey)
        }

        /** Reconstruct from the 32-byte private scalar. */
        fun fromScalar(scalar: ByteArray): SoftwareHolderKey {
            require(scalar.size == Ec.FIELD_BYTES) { "P-256 scalar must be ${Ec.FIELD_BYTES} bytes, got ${scalar.size}" }
            val d = BigInteger(1, scalar)
            val q = CURVE.g.multiply(d).normalize() // Q = d·G
            val kf = KeyFactory.getInstance("EC", BC)
            val priv = kf.generatePrivate(ECPrivateKeySpec(d, CURVE)) as ECPrivateKey
            val pub = kf.generatePublic(ECPublicKeySpec(q, CURVE)) as ECPublicKey
            return SoftwareHolderKey(priv, pub)
        }
    }
}
