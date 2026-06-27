package com.tcc.wallet.ssi

import uniffi.wallet_ffi.ForeignSigner

/**
 * Bridges a [HolderKey] (the software key, or the Android Keystore key in `:app`)
 * to the Rust engine's [ForeignSigner] callback. The engine frames every holder
 * JWS itself and calls back here only to sign raw bytes, so the **private key
 * never crosses the FFI** — exactly what the non-exportable Keystore key requires.
 *
 * The wallet's holder keys are ES256 throughout (the HAIP baseline and the only
 * algorithm Android StrongBox can hardware-back), so [algorithm] is fixed.
 */
class KotlinHolderSigner(private val holder: HolderKey) : ForeignSigner {
    override fun publicJwk(): String = holder.publicJwk().toString()

    override fun algorithm(): String = "ES256"

    override fun sign(message: ByteArray): ByteArray = holder.sign(message)
}
