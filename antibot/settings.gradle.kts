rootProject.name = "curator-antibot"

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
    }
}

// JVM modules: always part of the build (compile + test without an Android SDK).
include(":protocol")
include(":sdk-core")
include(":server")

// The Android layer requires the Android SDK. It is only wired into the build
// when an Android SDK is available (ANDROID_HOME / ANDROID_SDK_ROOT / local.properties),
// so that CI and `gradle :server:build` work on a plain JVM machine.
val androidAvailable =
    System.getenv("ANDROID_HOME") != null ||
        System.getenv("ANDROID_SDK_ROOT") != null ||
        file("local.properties").exists()

if (androidAvailable) {
    include(":sdk-android")
    include(":demo-app")
} else {
    logger.lifecycle(
        "[curator-antibot] Android SDK not detected -> modules ':sdk-android' and ':demo-app' are EXCLUDED " +
            "from this build. Open the project in Android Studio (or set ANDROID_HOME) to build them.",
    )
}
