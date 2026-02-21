plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.8.0"
}
rootProject.name = "oag"
include("oag-core", "oag-policy", "oag-inspection", "oag-enforcement", "oag-audit", "oag-secrets", "oag-telemetry", "oag-pipeline", "oag-proxy", "oag-app")
