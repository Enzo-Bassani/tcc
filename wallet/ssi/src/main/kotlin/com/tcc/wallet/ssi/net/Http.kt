package com.tcc.wallet.ssi.net

import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * A tiny synchronous HTTP helper over `java.net.HttpURLConnection` — works
 * unchanged on the JVM (tests) and on Android. No third-party HTTP dependency.
 *
 * Synchronous on purpose; the Android `:app` calls it off the main thread
 * (Dispatchers.IO), otherwise Android throws `NetworkOnMainThreadException`.
 */
class Http(private val timeoutMs: Int = 15_000) {

    data class Resp(val status: Int, val body: String) {
        val ok: Boolean get() = status in 200..299
        fun json(): JSONObject = JSONObject(body)
        fun bodyOrThrow(): String =
            if (ok) body else throw IOException("HTTP $status: $body")
    }

    fun get(url: String): Resp = request("GET", url, null, null, null)

    fun getJson(url: String): JSONObject = JSONObject(get(url).bodyOrThrow())

    fun postForm(url: String, form: Map<String, String>): Resp {
        val body = form.entries.joinToString("&") { (k, v) -> "${enc(k)}=${enc(v)}" }
        return request("POST", url, "application/x-www-form-urlencoded", body, null)
    }

    fun postJson(url: String, body: JSONObject, bearer: String?): Resp =
        request("POST", url, "application/json", body.toString(), bearer)

    fun put(url: String, body: JSONObject): Resp =
        request("PUT", url, "application/json", body.toString(), null)

    private fun request(method: String, url: String, contentType: String?, body: String?, bearer: String?): Resp {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = method
            connectTimeout = timeoutMs
            readTimeout = timeoutMs
            setRequestProperty("Accept", "application/json")
            bearer?.let { setRequestProperty("Authorization", "Bearer $it") }
            if (body != null) {
                doOutput = true
                contentType?.let { setRequestProperty("Content-Type", it) }
            }
        }
        try {
            if (body != null) conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val status = conn.responseCode
            val stream = if (status in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader(Charsets.UTF_8)?.use { it.readText() }.orEmpty()
            return Resp(status, text)
        } finally {
            conn.disconnect()
        }
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8")
}
