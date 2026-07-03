plugins {
    alias(libs.plugins.kotlin.jvm)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ktor)
    application
}

dependencies {
    implementation(project(":protocol"))

    implementation(libs.ktor.server.core)
    implementation(libs.ktor.server.netty)
    implementation(libs.ktor.server.content.negotiation)
    implementation(libs.ktor.serialization.json)
    implementation(libs.ktor.server.status.pages)
    implementation(libs.ktor.server.call.logging)
    implementation(libs.ktor.server.default.headers)
    implementation(libs.ktor.server.cors)
    implementation(libs.kotlinx.coroutines.core)
    implementation(libs.logback.classic)

    testImplementation(libs.ktor.server.test.host)
    testImplementation(libs.kotlinx.coroutines.test)
    testImplementation(libs.junit.jupiter)
    testRuntimeOnly(libs.junit.platform.launcher)
}

application {
    mainClass.set("pro.curator.antibot.server.ApplicationKt")
}

kotlin {
    jvmToolchain(21)
}

tasks.test {
    useJUnitPlatform()
}
