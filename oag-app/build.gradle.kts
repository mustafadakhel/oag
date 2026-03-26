plugins {
    application
    alias(libs.plugins.shadow)
    alias(libs.plugins.graalvm.native)
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

graalvmNative {
    metadataRepository {
        enabled.set(true)
    }
    binaries {
        named("main") {
            mainClass.set("com.mustafadakhel.oag.app.MainKt")
            imageName.set("oag")
            buildArgs.addAll(
                "--no-fallback",
                "--initialize-at-run-time=org.bouncycastle.jce.provider.BouncyCastleProvider",
                "--initialize-at-run-time=org.bouncycastle.jcajce.provider.drbg.DRBG",
                "--initialize-at-run-time=org.bouncycastle.crypto.prng.SP800SecureRandom",
                "-H:+ReportExceptionStackTraces"
            )
        }
    }
}
