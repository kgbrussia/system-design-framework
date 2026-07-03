plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
}

dependencies {
    api(project(":protocol"))
    api(libs.okhttp)
    implementation(libs.kotlinx.coroutines.core)

    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

kotlin {
    jvmToolchain(21)
    explicitApi()
}

tasks.test {
    useJUnitPlatform()
}
