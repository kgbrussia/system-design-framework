// Root build script. Plugins are declared here (apply false) so subprojects can
// apply them from the version catalog without repeating versions.
plugins {
    alias(libs.plugins.kotlin.jvm) apply false
    alias(libs.plugins.kotlin.serialization) apply false
    alias(libs.plugins.ktor) apply false
}

group = "pro.curator.antibot"
version = "1.0.0"
