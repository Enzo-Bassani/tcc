package com.tcc.wallet.ssi

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * Differential guard for the engine cutover: the legacy [KotlinSsiEngine] and the
 * new [RustSsiEngine] (UniFFI over `ssi-core`) must agree on identical inputs.
 *
 * Asserts three things over a minted credential + signed request:
 *  1. the SD-JWT **presentation prefix** (issuer JWT + selected disclosures + trailing
 *     `~`, i.e. everything the `sd_hash` is taken over) is byte-identical;
 *  2. the Authorization Response from *each* engine is accepted by the real verifier
 *     (`wallet-conformance verify`) — the key-binding JWTs differ per signature/`iat`,
 *     so the oracle is the parity backstop here;
 *  3. `findMatches` (the disclosed path/value sets) and `readCredential` agree.
 *
 * Needs `cargo` (the oracle) and the host-built `libwallet_ffi` (the bindings).
 * Skips cleanly when either is absent, so `:ssi:test` still runs without them.
 */
class EngineParityTest {

    @Test
    fun `kotlin and rust engines build the same presentation and both verify`() {
        assumeTrue(cargoAvailable(), "cargo not on PATH — skipping engine parity")
        assumeTrue(ffiLibAvailable(), "libwallet_ffi not built — run `just wallet-ffi-host`")

        val work = freshTempDir()
        val holder = SoftwareHolderKey.generate()
        val bundle = mint(holder, work)
        val request = Jar.verifyRequest(bundle.getString("request_jwt"), bundle.getString("client_id"))
        val creds = listOf(StoredCredential(bundle.getString("sd_jwt"), holder))

        val kotlin = KotlinSsiEngine()
        val rust = RustSsiEngine()

        // (1) identical presentation prefix (same sd_hash basis).
        assertEquals(
            prefix(kotlin.createVpToken(request, creds)),
            prefix(rust.createVpToken(request, creds)),
            "the SD-JWT presentation prefix must be byte-identical across engines",
        )

        // (2) each engine's response is accepted by the real verifier.
        for ((name, engine) in listOf<Pair<String, SsiEngine>>("kotlin" to kotlin, "rust" to rust)) {
            val response = engine.createResponse(request, creds, emptyMap())
            val responseFile = File(work, "$name-response.json").apply { writeText(response.toString()) }
            val code = conformance(work, "verify", "--bundle", File(work, "bundle.json").path, "--response", responseFile.path)
            assertEquals(0, code, "the $name engine's response must verify (see printed report)")
        }

        // (3) findMatches disclosed (path,value) sets + readCredential agree.
        assertEquals(
            disclosedSet(kotlin.findMatches(request, creds)),
            disclosedSet(rust.findMatches(request, creds)),
            "both engines must disclose the same claims for the same query",
        )
        assertTrue(
            kotlin.readCredential(creds[0].sdJwt).similar(rust.readCredential(creds[0].sdJwt)),
            "both engines must reconstruct the same claim set",
        )

        // (4) request authentication + issuer-credential trust agree across engines.
        val reqJwt = bundle.getString("request_jwt")
        val clientId = bundle.getString("client_id")
        assertTrue(
            kotlin.verifyRequest(reqJwt, clientId).similar(rust.verifyRequest(reqJwt, clientId)),
            "both engines must authenticate the signed request to the same claims",
        )
        // Neither engine throws → both accept the minted issuer credential as trustworthy.
        kotlin.verifyIssuerCredential(creds[0].sdJwt)
        rust.verifyIssuerCredential(creds[0].sdJwt)
    }

    // --- helpers ---------------------------------------------------------------

    /** The presentation prefix (everything up to and including the final `~` before
     *  the key-binding JWT) of the first credential in a VP Token. */
    private fun prefix(vpToken: JSONObject): String {
        val firstQuery = vpToken.keys().next()
        val presentation = vpToken.getJSONArray(firstQuery).getString(0)
        return presentation.substringBeforeLast('~') + "~"
    }

    private fun disclosedSet(matches: List<QueryMatch>): Set<Pair<List<String>, String>> =
        matches.flatMap { it.matches }.flatMap { it.disclosed }.map { it.path to it.value }.toSet()

    private fun mint(holder: HolderKey, work: File): JSONObject {
        val holderFile = File(work, "holder.json").apply { writeText(holder.publicJwk().toString()) }
        val bundleFile = File(work, "bundle.json")
        val code = conformance(work, "mint", "--holder-jwk", holderFile.path, "--out", bundleFile.path)
        assertEquals(0, code, "mint should succeed")
        return JSONObject(bundleFile.readText())
    }

    private fun conformance(work: File, vararg args: String): Int {
        val cmd = mutableListOf("cargo", "run", "-q", "-p", "wallet-core", "--bin", "wallet-conformance", "--")
        cmd.addAll(args)
        val proc = ProcessBuilder(cmd).directory(repoRoot()).redirectErrorStream(true).start()
        val output = proc.inputStream.bufferedReader().readText()
        val code = proc.waitFor()
        if (output.isNotBlank()) println(output)
        return code
    }

    private fun repoRoot(): File {
        var dir: File? = File(System.getProperty("user.dir"))
        while (dir != null) {
            if (File(dir, "Cargo.toml").exists() && File(dir, "crates/wallet-core").isDirectory) return dir
            dir = dir.parentFile
        }
        error("could not locate the repo root (a dir with Cargo.toml + crates/wallet-core)")
    }

    private fun cargoAvailable(): Boolean = try {
        ProcessBuilder("cargo", "--version").redirectErrorStream(true).start().waitFor() == 0
    } catch (e: Exception) {
        false
    }

    /** The host-built native lib must be on `jna.library.path` (set by the :ssi test task). */
    private fun ffiLibAvailable(): Boolean {
        val dir = System.getProperty("wallet.ffi.libdir") ?: return false
        return File(dir, System.mapLibraryName("wallet_ffi")).exists()
    }

    private fun freshTempDir(): File =
        File.createTempFile("engine-parity", "").let { it.delete(); it.mkdirs(); it.deleteOnExit(); it }
}
