pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "wallet"

// :ssi  — Kotlin/JVM app-facing SSI layer: the engine interface + protocol clients,
//         over the Rust ssi-core engine via UniFFI (testable with just a JDK + cargo).
// :app  — the Android shell (UI, storage, key handling) that depends on :ssi.
include(":ssi", ":app")
