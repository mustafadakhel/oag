dependencies {
    implementation(project(":oag-core"))
    implementation(project(":oag-policy"))
    implementation(project(":oag-inspection"))
    implementation(project(":oag-enforcement"))
    implementation(project(":oag-audit"))
    implementation(project(":oag-secrets"))
    implementation(project(":oag-telemetry"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.coroutines.core)

    testImplementation(libs.coroutines.test)
}
