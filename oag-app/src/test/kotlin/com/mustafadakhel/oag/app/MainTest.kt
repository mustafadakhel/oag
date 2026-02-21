package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.app.commands.BatchSimulateJsonOutput
import com.mustafadakhel.oag.app.commands.DiffJsonOutput
import kotlinx.serialization.json.Json

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.util.Base64

class MainTest {
    private val tempFiles = mutableListOf<Path>()
    private val tempDirs = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
        tempDirs.forEach { dir ->
            runCatching {
                Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
        tempDirs.clear()
    }

    @Test
    fun `doctor returns ok for valid policy`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", policyPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok"))
    }

    @Test
    fun `doctor returns error for missing policy`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", "C:/missing/policy.yaml"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("policyPath does not exist"))
    }

    @Test
    fun `doctor fails fast when required flag value is missing`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Missing value for --policy"))
    }

    @Test
    fun `doctor fails fast when optional int flag value is missing`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", policyPath, "--port"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Missing value for --port"))
    }

    @Test
    fun `doctor fails fast for invalid secret provider`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", policyPath, "--secret-provider", "bogus"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Invalid --secret-provider value"))
    }

    @Test
    fun `doctor fails fast for invalid otel exporter`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", policyPath, "--otel-exporter", "bogus"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Invalid --otel-exporter value"))
    }

    @Test
    fun `doctor json mode prints machine readable success`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", policyPath, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":true"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"policy_hash\""))
    }

    @Test
    fun `doctor accepts config dir with default policy path`() {
        val configDir = writeConfigDirWithPolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--config-dir", configDir, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":true"))
    }

    @Test
    fun `doctor json verbose mode includes effective config`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "doctor",
                "--policy", policyPath,
                "--json",
                "--verbose",
                "--block-ip-literals",
                "--connect-timeout-ms", "1111"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"effective_config\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"block_ip_literals\":true"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"connect_timeout_ms\":1111"))
    }

    @Test
    fun `doctor json mode prints machine readable error`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", "C:/missing/policy.yaml", "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":false"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error_code\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error\""))
    }

    @Test
    fun `doctor json error escapes control characters in message`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("doctor", "--policy", "C:/missing/\npolicy.yaml", "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        val body = out.toString(Charsets.UTF_8)
        assertTrue(body.contains("\\npolicy.yaml"))
        assertTrue(body.lineSequence().count { it.isNotBlank() } == 1)
    }

    @Test
    fun `explain returns allow for matching request`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "POST https://api.openai.com/v1/chat/completions"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("action=allow"))
        assertTrue(out.toString(Charsets.UTF_8).contains("reason=allowed_by_rule"))
    }

    @Test
    fun `explain accepts tab separated method and target`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "POST\thttps://api.openai.com/v1/chat/completions"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("action=allow"))
        assertTrue(out.toString(Charsets.UTF_8).contains("reason=allowed_by_rule"))
    }

    @Test
    fun `explain returns error code for invalid request format`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "https://api.openai.com/v1/chat/completions"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Invalid --request format"))
    }

    @Test
    fun `explain json mode prints machine readable success`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "POST https://api.openai.com/v1/chat/completions",
                "--json"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":true"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"action\":\"allow\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"reason_code\":\"allowed_by_rule\""))
    }

    @Test
    fun `explain accepts config dir with default policy path`() {
        val configDir = writeConfigDirWithPolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--config-dir", configDir,
                "--request", "POST https://api.openai.com/v1/chat/completions",
                "--json"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"action\":\"allow\""))
    }

    @Test
    fun `explain json verbose mode includes normalized request tuple`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "post https://api.openai.com/v1/chat/completions",
                "--json",
                "--verbose"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        val body = out.toString(Charsets.UTF_8)
        assertTrue(body.contains("\"request\""))
        assertTrue(body.contains("\"scheme\":\"https\""))
        assertTrue(body.contains("\"host\":\"api.openai.com\""))
        assertTrue(body.contains("\"method\":\"POST\""))
        assertTrue(body.contains("\"path\":\"/v1/chat/completions\""))
    }

    @Test
    fun `explain json mode prints machine readable error`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf(
                "explain",
                "--policy", policyPath,
                "--request", "https://api.openai.com/v1/chat/completions",
                "--json"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":false"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error_code\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error\""))
    }

    @Test
    fun `unknown command returns error code`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("unknown"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("unknown_command"))
    }

    @Test
    fun `help command prints usage`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("help"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("oag run [--policy"))
        assertTrue(out.toString(Charsets.UTF_8).contains("oag doctor [--policy"))
        assertTrue(out.toString(Charsets.UTF_8).contains("oag explain [--policy"))
        assertTrue(out.toString(Charsets.UTF_8).contains("oag test"))
        assertTrue(out.toString(Charsets.UTF_8).contains("oag help"))
    }

    @Test
    fun `help json mode prints machine readable command metadata`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("help", "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"commands\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"json_modes\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"help\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"hash\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"bundle\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"verify\""))
    }

    @Test
    fun `test command returns ok when all cases pass`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: allow case
                request: "POST https://api.openai.com/v1/chat/completions"
                expectAction: "allow"
                expectReason: "allowed_by_rule"
              - name: deny case
                request: "GET https://api.openai.com/v1/models"
                expectAction: "deny"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok total=2 passed=2 failed=0"))
    }

    @Test
    fun `test command accepts tab separated case request values`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: allow-openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: allow case
                request: "POST\thttps://api.openai.com/v1/chat/completions"
                expectAction: "allow"
                expectReason: "allowed_by_rule"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok total=1 passed=1 failed=0"))
    }

    @Test
    fun `test command returns non zero when a case fails`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: expected allow but denied
                request: "GET https://api.openai.com/v1/models"
                expectAction: "allow"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("fail expected allow but denied"))
        assertTrue(out.toString(Charsets.UTF_8).contains("policy tests failed"))
    }

    @Test
    fun `test command supports positional policy path`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: deny case
                request: "GET https://api.openai.com/v1/models"
                expectAction: "deny"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", policyPath, "--cases", casesPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok total=1 passed=1 failed=0"))
    }

    @Test
    fun `test command json mode prints machine readable success`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: deny case
                request: "GET https://api.openai.com/v1/models"
                expectAction: "deny"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":true"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"failed\":0"))
    }

    @Test
    fun `test command json mode prints machine readable failure summary`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: expected allow but denied
                request: "GET https://api.openai.com/v1/models"
                expectAction: "allow"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"ok\":false"))
        assertTrue(output.contains("\"failures\""))
        assertFalse(output.contains("\"error_code\""), "should not emit a second JSON error object")
    }

    @Test
    fun `test json mode prints machine readable error for missing required args`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("\"ok\":false"))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error_code\""))
        assertTrue(out.toString(Charsets.UTF_8).contains("\"error\""))
    }

    @Test
    fun `test command json verbose mode includes per case details`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: deny case
                request: "GET https://api.openai.com/v1/models"
                expectAction: "deny"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--policy", policyPath, "--cases", casesPath, "--json", "--verbose"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        val body = out.toString(Charsets.UTF_8)
        assertTrue(body.contains("\"cases\""))
        assertTrue(body.contains("\"name\":\"deny case\""))
        assertTrue(body.contains("\"actual_action\":\"deny\""))
        assertTrue(body.contains("\"actual_reason\":\"no_match_default_deny\""))
    }

    @Test
    fun `hash command prints policy hash`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("hash", "--policy", policyPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).trim().isNotEmpty())
    }

    @Test
    fun `bundle and verify commands succeed`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val privateKeyPath = writePrivateKeyPem(keyPair)
        val publicKeyPath = writePublicKeyPem(keyPair)
        val bundlePath = Files.createTempFile("policy-bundle", ".json").also { tempFiles.add(it) }.toString()

        val bundleOut = ByteArrayOutputStream()
        val bundleErr = ByteArrayOutputStream()
        val bundleCode = runCli(
            arrayOf(
                "bundle",
                "--policy", policyPath,
                "--out", bundlePath,
                "--sign-key", privateKeyPath.toString(),
                "--key-id", "test-key",
                "--json"
            ),
            PrintStream(bundleOut),
            PrintStream(bundleErr)
        )
        assertEquals(0, bundleCode)
        assertTrue(bundleOut.toString(Charsets.UTF_8).contains("\"ok\":true"))

        val verifyOut = ByteArrayOutputStream()
        val verifyErr = ByteArrayOutputStream()
        val verifyCode = runCli(
            arrayOf("verify", "--bundle", bundlePath, "--public-key", publicKeyPath.toString(), "--json"),
            PrintStream(verifyOut),
            PrintStream(verifyErr)
        )
        assertEquals(0, verifyCode)
        assertTrue(verifyOut.toString(Charsets.UTF_8).contains("\"ok\":true"))
    }

    @Test
    fun `hash json includes bundle metadata`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val privateKeyPath = writePrivateKeyPem(keyPair)
        val publicKeyPath = writePublicKeyPem(keyPair)
        val bundlePath = Files.createTempFile("policy-bundle", ".json").also { tempFiles.add(it) }.toString()

        val bundleCode = runCli(
            arrayOf(
                "bundle",
                "--policy", policyPath,
                "--out", bundlePath,
                "--sign-key", privateKeyPath.toString(),
                "--key-id", "test-key"
            ),
            PrintStream(ByteArrayOutputStream()),
            PrintStream(ByteArrayOutputStream())
        )
        assertEquals(0, bundleCode)

        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val hashCode = runCli(
            arrayOf(
                "hash",
                "--policy", bundlePath,
                "--policy-public-key", publicKeyPath.toString(),
                "--policy-require-signature",
                "--json"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, hashCode)
        val body = out.toString(Charsets.UTF_8)
        assertTrue(body.contains("\"bundle\""))
        assertTrue(body.contains("\"signature_status\":\"verified\""))
    }

    @Test
    fun `doctor json verbose includes bundle metadata`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val keyPair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair()
        val privateKeyPath = writePrivateKeyPem(keyPair)
        val publicKeyPath = writePublicKeyPem(keyPair)
        val bundlePath = Files.createTempFile("policy-bundle", ".json").also { tempFiles.add(it) }.toString()

        val bundleCode = runCli(
            arrayOf(
                "bundle",
                "--policy", policyPath,
                "--out", bundlePath,
                "--sign-key", privateKeyPath.toString(),
                "--key-id", "test-key"
            ),
            PrintStream(ByteArrayOutputStream()),
            PrintStream(ByteArrayOutputStream())
        )
        assertEquals(0, bundleCode)

        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val doctorCode = runCli(
            arrayOf(
                "doctor",
                "--policy", bundlePath,
                "--policy-public-key", publicKeyPath.toString(),
                "--policy-require-signature",
                "--json",
                "--verbose"
            ),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, doctorCode)
        val body = out.toString(Charsets.UTF_8)
        assertTrue(body.contains("\"bundle\""))
        assertTrue(body.contains("\"signature_status\":\"verified\""))
    }

    @Test
    fun `test command accepts config dir with default policy path`() {
        val configDir = writeConfigDirWithPolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val casesPath = writeCases(
            """
            cases:
              - name: deny case
                request: "GET https://api.openai.com/v1/models"
                expectAction: "deny"
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--config-dir", configDir, "--cases", casesPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok total=1 passed=1 failed=0"))
    }

    @Test
    fun `test command does not treat cases file value as positional policy`() {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("test", "--cases", "cases.yaml"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("Missing required argument --policy (or --config-dir)"))
    }

    private fun writePolicy(content: String): String =
        Files.createTempFile("policy", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }.toString()

    private fun writeCases(content: String): String =
        Files.createTempFile("cases", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }.toString()

    private fun writeConfigDirWithPolicy(policyContent: String): String =
        Files.createTempDirectory("oag-config").also { dir ->
            tempDirs.add(dir)
            Files.writeString(dir.resolve("policy.yaml"), policyContent)
        }.toString()

    private fun writePublicKeyPem(keyPair: KeyPair): Path {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(keyPair.public.encoded)
        val pem = buildString {
            appendLine("-----BEGIN PUBLIC KEY-----")
            appendLine(encoded)
            appendLine("-----END PUBLIC KEY-----")
        }
        return Files.createTempFile("public", ".pem").also { tempFiles.add(it); Files.writeString(it, pem) }
    }

    @Test
    fun `lint returns 0 for clean policy`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: r1
                host: api.openai.com
              - id: r2
                host: api.github.com
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("lint", "--policy", policyPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("ok no warnings"))
    }

    @Test
    fun `lint returns 1 when warnings found`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: r1
                host: api.example.com
              - id: r2
                host: api.example.com
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("lint", "--policy", policyPath),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("SHADOWED_RULE"))
        assertTrue(output.contains("1 warning(s) found"))
    }

    @Test
    fun `lint json returns warnings array`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            allow:
              - id: r1
                host: api.example.com
              - id: r2
                host: api.example.com
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("lint", "--policy", policyPath, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(1, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"ok\":false"))
        assertTrue(output.contains("\"warning_count\":1"))
        assertTrue(output.contains("\"code\":\"SHADOWED_RULE\""))
    }

    @Test
    fun `lint json returns ok true for clean policy`() {
        val policyPath = writePolicy(
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("lint", "--policy", policyPath, "--json"),
            PrintStream(out),
            PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"ok\":true"))
        assertTrue(output.contains("\"warning_count\":0"))
    }

    @Test
    fun `simulate returns allow for matching request`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [POST]
                paths: [/v1/*]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "POST",
                "--host", "api.example.com", "--path", "/v1/chat"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("action=allow"))
        assertTrue(output.contains("rule=api"))
    }

    @Test
    fun `simulate returns deny for non-matching request`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [POST]
                paths: [/v1/*]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "GET",
                "--host", "evil.com", "--path", "/hack"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("action=deny"))
        assertTrue(output.contains("reason=no_match_default_deny"))
    }

    @Test
    fun `simulate json returns structured output`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: openai
                host: api.openai.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [API_KEY]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "POST",
                "--host", "api.openai.com", "--path", "/v1/chat", "--json"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"ok\":true"))
        assertTrue(output.contains("\"action\":\"allow\""))
        assertTrue(output.contains("\"rule_id\":\"openai\""))
        assertTrue(output.contains("\"eligible_secrets\":[\"API_KEY\"]"))
    }

    @Test
    fun `simulate json deny has no eligible secrets`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "GET",
                "--host", "x.com", "--path", "/", "--json"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"action\":\"deny\""))
        assertTrue(!output.contains("eligible_secrets"))
    }

    @Test
    fun `simulate defaults scheme to https and port to 443`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                conditions:
                  scheme: https
                  ports: [443]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "GET",
                "--host", "api.example.com", "--json"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"action\":\"allow\""))
        assertTrue(output.contains("\"scheme\":\"https\""))
        assertTrue(output.contains("\"port\":443"))
    }

    @Test
    fun `simulate with http scheme defaults port to 80`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                conditions:
                  scheme: http
                  ports: [80]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "GET",
                "--host", "api.example.com", "--scheme", "http", "--json"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("\"action\":\"allow\""))
        assertTrue(output.contains("\"port\":80"))
    }

    @Test
    fun `simulate missing method returns error`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--host", "x.com"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(1, code)
        assertTrue(err.toString(Charsets.UTF_8).contains("--method"))
    }

    @Test
    fun `simulate text output shows eligible secrets`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [POST]
                paths: [/v1/*]
                secrets: [KEY_A, KEY_B]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()

        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--method", "POST",
                "--host", "api.example.com", "--path", "/v1/chat"),
            PrintStream(out), PrintStream(err)
        )

        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("eligible_secrets: KEY_A, KEY_B"))
    }

    @Test
    fun `diff identical policies reports no changes`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                paths: [/*]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", policy, policy), PrintStream(out), PrintStream(err))
        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("no changes"))
    }

    @Test
    fun `diff detects added rule in text mode`() {
        val old = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val new = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                paths: [/*]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", old, new), PrintStream(out), PrintStream(err))
        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("allow added: api"))
    }

    @Test
    fun `diff detects removed rule`() {
        val old = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                paths: [/*]
        """.trimIndent())
        val new = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", old, new), PrintStream(out), PrintStream(err))
        assertEquals(0, code)
        assertTrue(out.toString(Charsets.UTF_8).contains("allow removed: api"))
    }

    @Test
    fun `diff json returns structured output`() {
        val old = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val new = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
                paths: [/*]
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", old, new, "--json"), PrintStream(out), PrintStream(err))
        assertEquals(0, code)
        val result = Json.decodeFromString<DiffJsonOutput>(out.toString(Charsets.UTF_8))
        assertTrue(result.ok)
        assertTrue(result.hasChanges)
        assertEquals(1, result.ruleDiffs.size)
        assertEquals("added", result.ruleDiffs[0].change)
        assertEquals("api", result.ruleDiffs[0].id)
    }

    @Test
    fun `diff detects defaults change`() {
        val old = writePolicy("""
            version: 1
            defaults:
              action: deny
              max_body_bytes: 1024
        """.trimIndent())
        val new = writePolicy("""
            version: 1
            defaults:
              action: deny
              max_body_bytes: 2048
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", old, new), PrintStream(out), PrintStream(err))
        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("defaults changed"))
        assertTrue(output.contains("max_body_bytes"))
    }

    @Test
    fun `diff missing second argument returns error`() {
        val policy = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(arrayOf("diff", policy), PrintStream(out), PrintStream(err))
        assertEquals(1, code)
    }

    @Test
    fun `simulate batch text output shows per-request results and summary`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [GET]
        """.trimIndent())
        val batchPath = writeBatch("""
            requests:
              - name: allowed
                method: GET
                host: api.example.com
                path: /data
              - name: denied
                method: GET
                host: evil.com
                path: /
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--batch", batchPath),
            PrintStream(out), PrintStream(err)
        )
        assertEquals(0, code)
        val output = out.toString(Charsets.UTF_8)
        assertTrue(output.contains("allowed: action=allow"))
        assertTrue(output.contains("denied: action=deny"))
        assertTrue(output.contains("total=2 allow=1 deny=1"))
    }

    @Test
    fun `simulate batch json output contains results and summary`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
            allow:
              - id: api
                host: api.example.com
                methods: [POST]
                secrets: [KEY]
        """.trimIndent())
        val batchPath = writeBatch("""
            requests:
              - name: hit
                method: POST
                host: api.example.com
                path: /v1
              - name: miss
                method: GET
                host: evil.com
                path: /
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--batch", batchPath, "--json"),
            PrintStream(out), PrintStream(err)
        )
        assertEquals(0, code)
        val result = Json.decodeFromString<BatchSimulateJsonOutput>(out.toString(Charsets.UTF_8))
        assertTrue(result.ok)
        assertEquals(2, result.total)
        assertEquals(1, result.allowCount)
        assertEquals(1, result.denyCount)
        assertEquals(2, result.results.size)
        assertEquals("allow", result.results[0].action)
        assertEquals("deny", result.results[1].action)
        assertNotNull(result.results[0].eligibleSecrets)
    }

    @Test
    fun `simulate batch errors on missing file`() {
        val policyPath = writePolicy("""
            version: 1
            defaults:
              action: deny
        """.trimIndent())
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val code = runCli(
            arrayOf("simulate", "--policy", policyPath, "--batch", "C:/missing/batch.yaml"),
            PrintStream(out), PrintStream(err)
        )
        assertEquals(1, code)
    }

    private fun writeBatch(content: String): String =
        Files.createTempFile("batch", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }.toString()

    private fun writePrivateKeyPem(keyPair: KeyPair): Path {
        val encoded = Base64.getMimeEncoder(64, "\n".toByteArray())
            .encodeToString(keyPair.private.encoded)
        val pem = buildString {
            appendLine("-----BEGIN PRIVATE KEY-----")
            appendLine(encoded)
            appendLine("-----END PRIVATE KEY-----")
        }
        return Files.createTempFile("private", ".pem").also { tempFiles.add(it); Files.writeString(it, pem) }
    }

}
