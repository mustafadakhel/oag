package com.mustafadakhel.oag.app

import kotlin.test.Test
import kotlin.test.assertTrue

import java.io.ByteArrayOutputStream
import java.io.PrintStream

class HelpCommandTest {

    private fun helpOutput(): String {
        val out = ByteArrayOutputStream()
        runCli(arrayOf("help"), PrintStream(out), PrintStream(ByteArrayOutputStream()))
        return out.toString(Charsets.UTF_8)
    }

    @Test
    fun `help text contains all commands`() {
        val output = helpOutput()
        for (command in COMMAND_NAMES) {
            assertTrue(output.contains("oag $command"), "help text missing command: $command")
        }
    }

    @Test
    fun `help text contains critical run flags`() {
        val output = helpOutput()
        val criticalFlags = listOf(
            CliFlags.POLICY,
            CliFlags.CONFIG_DIR,
            CliFlags.PORT,
            CliFlags.VERBOSE,
            CliFlags.DRY_RUN,
            CliFlags.WATCH,
            CliFlags.SECRET_PROVIDER,
            CliFlags.TLS_INSPECT,
            CliFlags.ADMIN_PORT,
            CliFlags.WEBHOOK_URL,
            CliFlags.OTEL_EXPORTER,
            CliFlags.BLOCK_IP_LITERALS,
            CliFlags.ENFORCE_REDIRECT_POLICY,
            CliFlags.BLOCK_PRIVATE_RESOLVED_IPS,
            CliFlags.POLICY_PUBLIC_KEY,
            CliFlags.POLICY_REQUIRE_SIGNATURE,
            CliFlags.INJECT_REQUEST_ID,
            CliFlags.POOL_MAX_IDLE,
            CliFlags.POLICY_URL,
        )
        for (flag in criticalFlags) {
            assertTrue(output.contains(flag), "help text missing flag: $flag")
        }
    }
}
