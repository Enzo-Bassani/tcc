// Root build script — declares the plugins used by the sub-modules without
// applying them here (each module applies what it needs).
plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.compose.compiler) apply false
}
