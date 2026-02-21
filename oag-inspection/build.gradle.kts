dependencies {
    implementation(project(":oag-core"))
    implementation(project(":oag-policy"))
    implementation(libs.kotlinx.serialization.json)

    compileOnly(libs.onnxruntime)
    compileOnly(libs.djl.api)
    compileOnly(libs.djl.tokenizers)

    testImplementation(libs.onnxruntime)
    testImplementation(libs.djl.api)
    testImplementation(libs.djl.tokenizers)
}
