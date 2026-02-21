dependencies {
    implementation(project(":oag-core"))
    implementation(libs.kotlinx.serialization.json)

    testImplementation(libs.coroutines.test)
}
