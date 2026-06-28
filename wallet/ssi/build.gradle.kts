// The framework-agnostic SSI engine + protocol clients, as a plain Kotlin/JVM
// library. Deliberately NOT an Android module: it has no Android dependencies, so
// its tests (including the Rust conformance oracle) run with only a JDK + Gradle —
// no Android SDK, no emulator. The Android `:app` module depends on this.
plugins {
    alias(libs.plugins.kotlin.jvm)
}

dependencies {
    implementation(libs.bouncycastle)    // SoftwareHolderKey curve ops only (gen + fromScalar's d·G); JVM/conformance — Android uses KeystoreHolderKey
    implementation(libs.nimbus.jose.jwt) // JOSE: response JWE (Jwe.kt), DER↔R‖S transcode (Ec), JAR verify (Jar)
    implementation(libs.json)            // org.json — also provided by the Android platform at runtime
    // JNA for the UniFFI bindings. compileOnly so the plain jar is NOT exposed
    // transitively to :app (which supplies the @aar variant — same classes + the
    // Android jnidispatch — and would otherwise clash). The host JVM tests need it
    // on the runtime classpath, hence testImplementation.
    compileOnly(libs.jna)
    testImplementation(libs.junit.jupiter)
    testImplementation(libs.jna)
}

kotlin {
    jvmToolchain(17)
}

// The host-built Rust native lib (libwallet_ffi) the UniFFI bindings load. Built by
// `just wallet-ffi-host` into the workspace target/ dir (../../target relative to :ssi).
val rustHostLibDir: File = projectDir.resolve("../../target/debug")

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
    // The conformance test shells out to `cargo`; surface its output.
    testLogging.showStandardStreams = true
    // Where JNA looks for libwallet_ffi.so for the RustSsiEngine / parity tests.
    // Tests that need it skip cleanly when the lib hasn't been built.
    systemProperty("jna.library.path", rustHostLibDir.absolutePath)
    systemProperty("wallet.ffi.libdir", rustHostLibDir.absolutePath)
}
