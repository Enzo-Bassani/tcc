package com.tcc.wallet

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import com.tcc.wallet.ssi.Ec
import com.tcc.wallet.ssi.HolderKey
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * The production [HolderKey]: an ES256 (P-256) key generated and held **non-exportable**
 * inside the Android Keystore — StrongBox when the device has it, the TEE otherwise. The
 * private scalar never leaves secure hardware, giving the HAIP/ARF/EUDI device-binding
 * guarantee the EU profiles require. Signatures go out as JOSE raw R‖S via [Ec], so a
 * Keystore-signed VP Token / VCI proof verifies exactly like the software
 * [com.tcc.wallet.ssi.SoftwareHolderKey].
 *
 * No user-authentication gate (the prototype flow stays unprompted) and no attestation
 * certificate — non-exportability is the property we need here.
 */
class KeystoreHolderKey private constructor(
    private val privateKey: PrivateKey,
    private val pub: ECPublicKey,
) : HolderKey {

    override fun publicJwk(): JSONObject = Ec.ecPublicJwk(pub)

    override fun sign(message: ByteArray): ByteArray {
        val ecdsa = Signature.getInstance("SHA256withECDSA")
        ecdsa.initSign(privateKey)
        ecdsa.update(message)
        return Ec.derToJoseRaw(ecdsa.sign(), Ec.FIELD_BYTES)
    }

    companion object {
        private const val KEYSTORE = "AndroidKeyStore"
        private const val DEFAULT_ALIAS = "holder_es256"

        /**
         * Load the holder key under [alias], generating a fresh non-exportable P-256 key on
         * first use. StrongBox is requested when the device advertises it; if generation
         * fails with [StrongBoxUnavailableException] we retry once on the TEE.
         */
        fun getOrCreate(context: Context, alias: String = DEFAULT_ALIAS): KeystoreHolderKey {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            if (!ks.containsAlias(alias)) generate(context, alias)
            val privateKey = ks.getKey(alias, null) as PrivateKey
            val pub = ks.getCertificate(alias).publicKey as ECPublicKey
            return KeystoreHolderKey(privateKey, pub)
        }

        private fun generate(context: Context, alias: String) {
            // StrongBox is API 28+; on older devices, or if the device claims StrongBox but
            // can't satisfy this spec, fall through to a (still non-exportable) TEE key.
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
            ) {
                try {
                    generateKeyPair(alias, strongBox = true)
                    return
                } catch (_: StrongBoxUnavailableException) {
                    // fall through to the TEE
                }
            }
            generateKeyPair(alias, strongBox = false)
        }

        private fun generateKeyPair(alias: String, strongBox: Boolean) {
            val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setDigests(KeyProperties.DIGEST_SHA256)
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                builder.setIsStrongBoxBacked(true)
            }
            val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            gen.initialize(builder.build())
            gen.generateKeyPair()
        }
    }
}
