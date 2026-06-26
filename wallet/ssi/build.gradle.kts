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
    testImplementation(libs.junit.jupiter)
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
    // The conformance test shells out to `cargo`; surface its output.
    testLogging.showStandardStreams = true
}
