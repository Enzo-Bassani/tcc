plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.compose.compiler)
}

android {
    namespace = "com.tcc.wallet"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.tcc.wallet"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        compose = true
    }
    // org.json is provided by the Android platform at runtime; the copy :ssi pulls
    // in for the JVM is harmlessly shadowed by it. Excluding stray META-INF files
    // just avoids license-file merge noise when packaging.
    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }
}

dependencies {
    implementation(project(":ssi"))
    // JNA's Android runtime: the @aar variant bundles libjnidispatch.so for the
    // Android ABIs (the plain jar :ssi uses only carries desktop builds), so the
    // UniFFI bindings can load libwallet_ffi on-device. Version pinned in the catalog.
    implementation("net.java.dev.jna:jna:${libs.versions.jna.get()}@aar")

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    // Chrome Custom Tabs — launch the issuer's /authorize (SSO) for the OID4VCI auth-code flow.
    implementation(libs.androidx.browser)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.foundation)
    implementation(libs.androidx.material3)
    implementation(libs.androidx.material.icons.extended)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    debugImplementation(libs.androidx.ui.tooling)

    // QR scanning: CameraX preview/analysis + ML Kit's bundled QR decoder (no Play Services).
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.mlkit.barcode.scanning)

    // Tier-3 on-device test: the UniFFI engine + AndroidKeyStore signer on an emulator.
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}
