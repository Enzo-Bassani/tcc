package com.tcc.wallet.ssi

import org.json.JSONObject
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Test
import java.io.File

/**
 * The compatibility guard: the Authorization Response built by
 * [RustSsiEngine] (UniFFI over ssi-core) — verifying the verifier's signed request (did:jwk JAR), then
 * JWE-encrypting the VP Token (`direct_post.jwt`) — must make the REAL verifier
 * (`ssi_core::oid4vp`) report `valid == true`. This exercises BOTH cross-language
 * surfaces at once: Kotlin verifies a Rust-signed JAR, and Rust decrypts a
 * Kotlin-sealed JWE. We drive the Rust `wallet-conformance` CLI:
 *
 *   mint  → a credential bound to our holder key + a signed request to answer
 *   (Kotlin verifies the request, builds the VP Token, encrypts the response)
 *   verify → exits 0 iff the verifier accepts it
 *
 * Requires `cargo` on PATH (the repo's Rust workspace). If absent, the test is
 * skipped rather than failed, so `:ssi` still builds on a machine without Rust.
 */
class ConformanceTest {

    @Test
    fun `verifier accepts the Kotlin-built encrypted response`() {
        assumeTrue(cargoAvailable(), "cargo not on PATH — skipping cross-language conformance")
        assumeTrue(ffiLibAvailable(), "libwallet_ffi not built — run `just wallet-ffi-host`")
        val work = freshTempDir()
        val holder = SoftwareHolderKey.generate()

        val bundle = mint(holder, revoked = false, work = work)
        val response = respond(bundle, holder)
        // The cross-language proof: the response carries an opaque JWE, not cleartext.
        assertNotEquals("", response.optString("response"), "response must be an encrypted JWE")
        val respFile = File(work, "response.json").apply { writeText(response.toString()) }

        val code = conformance(work, "verify", "--bundle", File(work, "bundle.json").path, "--response", respFile.path)
        assertEquals(0, code, "verifier must accept the Kotlin response (see printed report)")
    }

    @Test
    fun `verifier rejects a revoked credential`() {
        assumeTrue(cargoAvailable(), "cargo not on PATH — skipping cross-language conformance")
        assumeTrue(ffiLibAvailable(), "libwallet_ffi not built — run `just wallet-ffi-host`")
        val work = freshTempDir()
        val holder = SoftwareHolderKey.generate()

        val bundle = mint(holder, revoked = true, work = work)
        val response = respond(bundle, holder)
        val respFile = File(work, "response.json").apply { writeText(response.toString()) }

        val code = conformance(work, "verify", "--bundle", File(work, "bundle.json").path, "--response", respFile.path)
        assertNotEquals(0, code, "a revoked credential must NOT verify")
    }

    // --- helpers ---------------------------------------------------------------

    /** The wallet half of the flow: verify the bundle's signed request (did:jwk JAR),
     *  build the VP Token, and seal it as the encrypted Authorization Response. */
    private val engine = RustSsiEngine()

    private fun respond(bundle: JSONObject, holder: HolderKey): JSONObject {
        val request = engine.verifyRequest(bundle.getString("request_jwt"), bundle.getString("client_id"))
        return engine.createResponse(
            request,
            listOf(StoredCredential(bundle.getString("sd_jwt"), holder)),
        )
    }

    /** The host-built native lib must be on `jna.library.path` (set by the :ssi test task). */
    private fun ffiLibAvailable(): Boolean {
        val dir = System.getProperty("wallet.ffi.libdir") ?: return false
        return File(dir, System.mapLibraryName("wallet_ffi")).exists()
    }

    private fun mint(holder: HolderKey, revoked: Boolean, work: File): JSONObject {
        val holderFile = File(work, "holder.json").apply { writeText(holder.publicJwk().toString()) }
        val bundleFile = File(work, "bundle.json")
        val args = buildList {
            addAll(listOf("mint", "--holder-jwk", holderFile.path, "--out", bundleFile.path))
            if (revoked) add("--revoked")
        }
        val code = conformance(work, *args.toTypedArray())
        assertEquals(0, code, "mint should succeed")
        return JSONObject(bundleFile.readText())
    }

    /** Run `cargo run -p wallet-core --bin wallet-conformance -- <args>` from the repo root. */
    private fun conformance(work: File, vararg args: String): Int {
        val cmd = mutableListOf("cargo", "run", "-q", "-p", "wallet-core", "--bin", "wallet-conformance", "--")
        cmd.addAll(args)
        val proc = ProcessBuilder(cmd)
            .directory(repoRoot())
            .redirectErrorStream(true)
            .start()
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

    private fun freshTempDir(): File =
        File.createTempFile("wallet-conf", "").let {
            it.delete(); it.mkdirs(); it.deleteOnExit(); it
        }
}
