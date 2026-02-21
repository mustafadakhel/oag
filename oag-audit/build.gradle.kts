dependencies {
    implementation(project(":oag-core"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.coroutines.core)

    testImplementation(project(":oag-telemetry"))
    testImplementation(libs.coroutines.test)
    testImplementation(platform(libs.opentelemetry.bom))
    testImplementation(libs.opentelemetry.sdk.testing)
}
