package com.tcc.wallet

import com.tcc.wallet.ssi.HolderKey
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Dead-simple persistence for the prototype: the list of issued SD-JWT credential strings,
 * as a JSON file under the app's private storage. The holder key is not persisted here — it
 * lives non-exportable in the Android Keystore (StrongBox-preferred), passed in as [holder].
 */
class WalletStore(private val file: File, val holder: HolderKey) {

    private val credentials = mutableListOf<String>()

    init {
        if (file.exists()) load()
    }

    fun credentials(): List<String> = credentials.toList()

    fun addCredential(sdJwt: String) {
        credentials.add(sdJwt)
        save()
    }

    private fun load() {
        val root = JSONObject(file.readText())
        val arr = root.optJSONArray("credentials") ?: JSONArray()
        credentials.clear()
        for (i in 0 until arr.length()) credentials.add(arr.getString(i))
    }

    private fun save() {
        val root = JSONObject()
            .put("credentials", JSONArray(credentials))
        file.writeText(root.toString())
    }
}
