dependencies {
    implementation(project(":oag-core"))
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotaml)
    implementation(libs.coroutines.core)

    compileOnly(libs.onnxruntime)
    compileOnly(libs.djl.api)
    compileOnly(libs.djl.tokenizers)

    testImplementation(libs.coroutines.test)
    testImplementation(libs.onnxruntime)
    testImplementation(libs.djl.api)
    testImplementation(libs.djl.tokenizers)
}
