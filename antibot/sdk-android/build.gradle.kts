plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "pro.curator.antibot.sdk.android"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        consumerProguardFiles("consumer-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // The SDK collects device/OS signals; keep the released code map for crash triage.
    buildFeatures {
        buildConfig = true
    }
}

dependencies {
    api(project(":sdk-core"))
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.androidx.security.crypto)
    implementation(libs.play.integrity)
}
