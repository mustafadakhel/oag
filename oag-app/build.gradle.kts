plugins {
    application
    alias(libs.plugins.shadow)
}

dependencies {
    implementation(project(":oag-core"))
    implementation(project(":oag-policy"))
    implementation(project(":oag-enforcement"))
    implementation(project(":oag-inspection"))
    implementation(project(":oag-audit"))
    implementation(project(":oag-secrets"))
    implementation(project(":oag-telemetry"))
    implementation(project(":oag-proxy"))
    implementation(libs.kotlinx.serialization.json)
}

application {
    mainClass.set("com.mustafadakhel.oag.app.MainKt")
}

tasks.shadowJar {
    archiveClassifier.set("all")
}
