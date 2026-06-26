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

// :ssi  — pure Kotlin/JVM SSI engine + protocol clients (testable with just a JDK).
// :app  — the Android shell (UI, storage, key handling) that depends on :ssi.
include(":ssi", ":app")
