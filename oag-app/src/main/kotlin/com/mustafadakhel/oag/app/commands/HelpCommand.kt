package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.COMMAND_NAMES
import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.JSON_MODE_COMMANDS
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

import java.io.PrintStream

internal val HelpCommand = CliCommand { args, out ->
    if (args.hasFlag(CliFlags.JSON)) {
        out.println(cliJson.encodeToString(HelpJsonOutput(
            commands = COMMAND_NAMES,
            jsonModes = JSON_MODE_COMMANDS
        )))
        return@CliCommand 0
    }
    printUsage(out)
    0
}

@Serializable
internal data class HelpJsonOutput(
    val commands: List<String>,
    @SerialName("json_modes") val jsonModes: List<String>
)

private fun printUsage(out: PrintStream) {
    out.println("oag run [--policy <file>] [--config-dir <dir>] [--port <n>] [--log <file>] [--agent <id>] [--session <id>]")
    out.println("       [--max-threads <n>] [--secret-prefix <prefix>] [--secret-provider <env|file|oauth2>] [--secret-dir <dir>]")
    out.println("       [--oauth2-token-url <url>] [--oauth2-client-id <id>] [--oauth2-client-secret <secret>] [--oauth2-scope <scope>]")
    out.println("       [--policy-public-key <file>] [--policy-require-signature]")
    out.println("       [--verbose] [--dry-run] [--watch] [--block-ip-literals] [--enforce-redirect-policy]")
    out.println("       [--block-private-resolved-ips] [--tls-inspect] [--tls-ca-cert-path <file>]")
    out.println("       [--mtls-ca-cert <file>] [--mtls-keystore <file>] [--mtls-keystore-password <pass>]")
    out.println("       [--agent-signing-secret <secret>] [--require-signed-headers]")
    out.println("       [--connect-timeout-ms <ms>] [--read-timeout-ms <ms>]")
    out.println("       [--otel-exporter <none|otlp_http|otlp_grpc|stdout>] [--otel-endpoint <url>]")
    out.println("       [--otel-headers <k=v,...>] [--otel-timeout-ms <ms>] [--otel-service-name <name>]")
    out.println("       [--admin-port <n>] [--circuit-breaker-threshold <n>] [--circuit-breaker-reset-ms <ms>] [--circuit-breaker-half-open-probes <n>]")
    out.println("       [--drain-timeout-ms <ms>] [--inject-request-id] [--request-id-header <name>]")
    out.println("       [--pool-max-idle <n>] [--pool-idle-timeout-ms <ms>]")
    out.println("       [--log-max-size-mb <n>] [--log-max-files <n>] [--log-compress] [--log-rotation-interval <hourly|daily>]")
    out.println("       [--admin-allowed-ips <ip,...>] [--admin-token <token>] [--admin-reload-cooldown-ms <ms>]")
    out.println("       [--webhook-url <url>] [--webhook-events <event,...>]")
    out.println("       [--webhook-timeout-ms <ms>] [--webhook-signing-secret <secret>]")
    out.println("       [--policy-url <url>] [--policy-fetch-interval-s <n>]")
    out.println("       [--integrity-check-interval-s <n>] [--velocity-spike-threshold <n>]")
    out.println("oag doctor [--policy <file>] [--config-dir <dir>] [--port <n>] [--max-threads <n>] [--secret-prefix <prefix>]")
    out.println("           [--secret-provider <env|file|oauth2>] [--secret-dir <dir>]")
    out.println("           [--policy-public-key <file>] [--policy-require-signature]")
    out.println("           [--block-ip-literals] [--enforce-redirect-policy] [--block-private-resolved-ips]")
    out.println("           [--connect-timeout-ms <ms>] [--read-timeout-ms <ms>]")
    out.println("           [--otel-exporter <none|otlp_http|otlp_grpc|stdout>] [--otel-endpoint <url>]")
    out.println("           [--otel-headers <k=v,...>] [--otel-timeout-ms <ms>] [--otel-service-name <name>]")
    out.println("           [--json] [--verbose]")
    out.println("oag explain [--policy <file>] [--config-dir <dir>] [--policy-public-key <file>] [--policy-require-signature]")
    out.println("          --request \"METHOD https://host/path\" [--json] [--verbose]")
    out.println("oag test [--policy <file>|<file>] [--config-dir <dir>] [--policy-public-key <file>] [--policy-require-signature]")
    out.println("       --cases <file> [--json] [--verbose]")
    out.println("oag hash [--policy <file>|<file>] [--config-dir <dir>] [--json]")
    out.println("oag bundle --policy <file> --out <file> [--sign-key <file>] [--key-id <id>] [--json]")
    out.println("oag verify --bundle <file> --public-key <file> [--json]")
    out.println("oag lint [--policy <file>] [--config-dir <dir>] [--policy-public-key <file>] [--policy-require-signature] [--json]")
    out.println("oag simulate [--policy <file>] [--config-dir <dir>] --method <METHOD> --host <host> [--path <path>]")
    out.println("             [--scheme <http|https>] [--port <n>] [--batch <file>]")
    out.println("             [--policy-public-key <file>] [--policy-require-signature] [--json]")
    out.println("oag diff <policy1> <policy2> [--json]")
    out.println("oag help [--json]")
}
