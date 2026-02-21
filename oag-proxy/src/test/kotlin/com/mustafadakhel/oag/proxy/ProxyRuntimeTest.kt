package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.audit.AuditEventType
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.proxy.lifecycle.reconfigureRateLimiters
import com.mustafadakhel.oag.proxy.pipeline.buildFullProxyHandler
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.NetworkConfig
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.secrets.SecretProvider
import com.mustafadakhel.oag.secrets.SecretProviderType
import com.mustafadakhel.oag.secrets.SecretValue
import com.mustafadakhel.oag.telemetry.OtelConfig
import com.mustafadakhel.oag.telemetry.OtelExporterType

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

import java.io.ByteArrayOutputStream
import java.net.Socket
import java.nio.file.Files
import java.nio.file.Path

class ProxyRuntimeTest {
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
    fun `validate config fails on invalid listen port`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    listenPort = 0
                )
            )
        }
    }

    @Test
    fun `validate config fails on invalid max threads`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    maxThreads = 0
                )
            )
        }
    }

    @Test
    fun `validate config fails on blank listen host`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    listenHost = " "
                )
            )
        }
    }

    @Test
    fun `validate config fails on blank log path`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    log = ProxyLogConfig(path = " ")
                )
            )
        }
    }

    @Test
    fun `validate config fails on blank policy path`() {
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = " ")
                )
            )
        }
    }

    @Test
    fun `validate config fails when policy signature required without public key`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath, requireSignature = true)
                )
            )
        }
    }

    @Test
    fun `validate config fails when log path is a directory`() {
        val policyPath = tempPolicyPath()
        val logDir = Files.createTempDirectory("oag-logdir").also { tempDirs.add(it) }
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    log = ProxyLogConfig(path = logDir.toString())
                )
            )
        }
    }

    @Test
    fun `validate config fails when log path parent is a file`() {
        val policyPath = tempPolicyPath()
        val parentFile = Files.createTempFile("oag-parent", ".tmp").also { tempFiles.add(it) }
        val logPath = parentFile.resolve("child").toString()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    log = ProxyLogConfig(path = logPath)
                )
            )
        }
    }

    @Test
    fun `validate config fails on missing policy path`() {
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = "C:/definitely-missing/policy.yaml")
                )
            )
        }
    }

    @Test
    fun `validate config fails on blank secret prefix`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    secret = ProxySecretConfig(envPrefix = " ")
                )
            )
        }
    }

    @Test
    fun `validate config fails when file secret provider has no directory`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    secret = ProxySecretConfig(provider = SecretProviderType.FILE)
                )
            )
        }
    }

    @Test
    fun `validate config fails when file secret provider directory is missing`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    secret = ProxySecretConfig(provider = SecretProviderType.FILE, fileDir = "C:/missing/dir")
                )
            )
        }
    }

    @Test
    fun `validate config accepts file secret provider when directory exists`() {
        val policyPath = tempPolicyPath()
        val secretDir = Files.createTempDirectory("oag-secrets").also { tempDirs.add(it) }
        validateProxyConfig(
            ProxyConfig(
                policy = ProxyPolicyConfig(path = policyPath),
                secret = ProxySecretConfig(provider = SecretProviderType.FILE, fileDir = secretDir.toString())
            )
        )
    }

    @Test
    fun `validate config fails on non positive connect timeout`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    network = ProxyNetworkConfig(connectTimeoutMs = 0)
                )
            )
        }
    }

    @Test
    fun `validate config fails on non positive read timeout`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    network = ProxyNetworkConfig(readTimeoutMs = 0)
                )
            )
        }
    }

    @Test
    fun `validate config fails when otel exporter lacks endpoint`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    otelConfig = OtelConfig(exporter = OtelExporterType.OTLP_HTTP)
                )
            )
        }
    }

    @Test
    fun `validate config accepts otel exporter with endpoint`() {
        val policyPath = tempPolicyPath()
        validateProxyConfig(
            ProxyConfig(
                policy = ProxyPolicyConfig(path = policyPath),
                otelConfig = OtelConfig(
                    exporter = OtelExporterType.OTLP_HTTP,
                    endpoint = "http://localhost:4318/v1/logs"
                )
            )
        )
    }

    @Test
    fun `build startup event maps config fields deterministically`() {
        val policyPath = tempPolicyPath()
        val event = buildStartupEvent(
            ProxyConfig(
                policy = ProxyPolicyConfig(
                    path = policyPath,
                    publicKeyPath = "C:/keys/policy.pub",
                    requireSignature = true
                ),
                network = ProxyNetworkConfig(
                    blockIpLiterals = true,
                    enforceRedirectPolicy = true,
                    blockPrivateResolvedIps = true,
                    connectTimeoutMs = 1111,
                    readTimeoutMs = 2222
                ),
                identity = ProxyIdentityConfig(
                    agentId = "agent-1",
                    sessionId = "session-1"
                ),
                secret = ProxySecretConfig(
                    envPrefix = "OAG_SECRET_",
                    provider = SecretProviderType.FILE,
                    fileDir = "C:/secrets"
                ),
                listenHost = "127.0.0.1",
                listenPort = 9090,
                oagVersion = "0.1.0",
                maxThreads = 16,
                log = ProxyLogConfig(path = "logs/audit.jsonl"),
                dryRun = true
            ),
            policyHash = "abc123"
        )

        assertEquals(AuditEventType.STARTUP, event.eventType)
        assertEquals("0.1.0", event.oagVersion)
        assertEquals("abc123", event.policyHash)
        assertEquals("agent-1", event.agentId)
        assertEquals(policyPath, event.config.policyPath)
        assertEquals("C:/keys/policy.pub", event.config.policyPublicKeyPath)
        assertEquals(true, event.config.policyRequireSignature)
        assertEquals("logs/audit.jsonl", event.config.logPath)
        assertEquals(9090, event.config.listenPort)
        assertEquals(true, event.config.dryRun)
        assertEquals(true, event.config.blockIpLiterals)
        assertEquals(true, event.config.enforceRedirectPolicy)
        assertEquals(true, event.config.blockPrivateResolvedIps)
        assertEquals(1111, event.config.connectTimeoutMs)
        assertEquals(2222, event.config.readTimeoutMs)
        assertEquals("OAG_SECRET_", event.config.secretEnvPrefix)
        assertEquals("file", event.config.secretProvider)
        assertEquals("C:/secrets", event.config.secretFileDir)
        assertEquals("none", event.config.otelExporter)
    }

    @Test
    fun `validate config rejects blank tls ca cert path`() {
        val policyPath = tempPolicyPath()
        assertFailsWith<IllegalArgumentException> {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    tls = ProxyTlsConfig(inspect = true, caCertPath = "  ")
                )
            )
        }
    }

    @Test
    fun `validate config accepts tls inspect without cert path`() {
        val policyPath = tempPolicyPath()
        validateProxyConfig(
            ProxyConfig(
                policy = ProxyPolicyConfig(path = policyPath),
                tls = ProxyTlsConfig(inspect = true)
            )
        )
    }

    @Test
    fun `mTLS keystore without caCertPath fails validation`() {
        val policyPath = tempPolicyPath()
        val keystorePath = Files.createTempFile("keystore", ".p12").also { tempFiles.add(it) }
        assertFailsWith<IllegalArgumentException>("mtlsCaCertPath must be set") {
            validateProxyConfig(
                ProxyConfig(
                    policy = ProxyPolicyConfig(path = policyPath),
                    tls = ProxyTlsConfig(
                        mtlsKeystorePath = keystorePath.toString()
                    )
                )
            )
        }
    }

    @Test
    fun `proxy server isDraining is false initially`() {
        val server = createProxyServer()
        assertFalse(server.isDraining)
    }

    @Test
    fun `proxy server drain sets isDraining to true`() {
        val server = createProxyServer()
        server.drain()
        assertTrue(server.isDraining)
    }

    @Test
    fun `proxy server activeConnectionCount is zero initially`() {
        val server = createProxyServer()
        assertEquals(0, server.activeConnectionCount)
    }

    @Test
    fun `proxy server awaitDrain returns true when no active connections`() = runTest {
        val server = createProxyServer()
        server.drain()
        assertTrue(server.awaitDrainBlocking(100))
    }

    @Test
    fun `proxy server drain stops accepting new connections`() = runTest {
        val server = createProxyServer(listenPort = 0)
        backgroundScope.launch(Dispatchers.IO) { server.start() }
        awaitServerReady(server)

        val port = server.localPort
        assertTrue(port > 0, "server should have bound a port")

        server.drain()
        assertTrue(server.isDraining)

        val connectFailed = runCatching {
            Socket("127.0.0.1", port).use { it.getInputStream().read() }
        }.isFailure
        assertTrue(connectFailed, "Connection should be refused after drain")
    }

    @Test
    fun `proxy server awaitDrain returns true immediately when no active connections`() = runTest {
        val server = createProxyServer(listenPort = 0)
        backgroundScope.launch(Dispatchers.IO) { server.start() }
        awaitServerReady(server)

        server.drain()
        val drained = server.awaitDrainBlocking(200)
        assertTrue(drained, "should drain immediately with no active connections")
    }

    @Test
    fun `proxy server localPort returns bound port`() = runTest {
        val server = createProxyServer(listenPort = 0)
        assertEquals(-1, server.localPort, "localPort should be -1 before start")

        backgroundScope.launch(Dispatchers.IO) { server.start() }
        awaitServerReady(server)

        val port = server.localPort
        assertTrue(port > 0, "localPort should be positive after start")

        server.drain()
    }

    @Test
    fun `proxy server rejects connections when at max threads during drain`() = runTest {
        val policyPath = Path.of(tempPolicyPath())
        val policyService = PolicyService(policyPath)
        val config = HandlerConfig(
            network = NetworkConfig(),
            params = HandlerParams(agentId = null, sessionId = null)
        )
        val server = ProxyServer(
            listenHost = "127.0.0.1",
            listenPort = 0,
            handler = buildFullProxyHandler(
                config = config,
                policyService = policyService,
                secretMaterializer = SecretMaterializer(object : SecretProvider {
                    override fun resolve(secretId: String): SecretValue? = null
                }),
                auditLogger = AuditLogger(ByteArrayOutputStream()),
                rateLimiterRegistry = RateLimiterRegistry(),
                dataBudgetTracker = DataBudgetTracker(),
                tokenBudgetTracker = TokenBudgetTracker()
            ),
            config = config,
            maxThreads = 1
        )
        backgroundScope.launch(Dispatchers.IO) { server.start() }
        awaitServerReady(server)

        assertEquals(0, server.activeConnectionCount)
        server.drain()
        assertTrue(server.isDraining)
        assertTrue(server.awaitDrainBlocking(500))
    }

    @Test
    fun `reconfigureRateLimiters replaces existing limiters`() {
        val expectedBurst = 2
        val policyFile = Files.createTempFile("policy", ".yaml").also { tempFiles.add(it) }
        Files.writeString(policyFile, """
            version: 1
            defaults:
              action: deny
            allow:
              - id: rule_a
                host: a.com
                rate_limit:
                  requests_per_second: 10.0
                  burst: $expectedBurst
        """.trimIndent())

        val policyService = PolicyService(policyPath = policyFile)
        val registry = RateLimiterRegistry()
        registry.configure("old_rule", 1.0, 1)

        reconfigureRateLimiters(policyService, registry)

        assertFalse(registry.tryAcquire("old_rule"))
        repeat(expectedBurst) { assertTrue(registry.tryAcquire("rule_a")) }
        assertFalse(registry.tryAcquire("rule_a"))
    }

    private fun createProxyServer(listenPort: Int = 0): ProxyServer {
        val policyPath = Path.of(tempPolicyPath())
        val policyService = PolicyService(policyPath)
        val config = HandlerConfig(
            network = NetworkConfig(),
            params = HandlerParams(agentId = null, sessionId = null)
        )
        return ProxyServer(
            listenHost = "127.0.0.1",
            listenPort = listenPort,
            handler = buildFullProxyHandler(
                config = config,
                policyService = policyService,
                secretMaterializer = SecretMaterializer(object : SecretProvider {
                    override fun resolve(secretId: String): SecretValue? = null
                }),
                auditLogger = AuditLogger(ByteArrayOutputStream()),
                rateLimiterRegistry = RateLimiterRegistry(),
                dataBudgetTracker = DataBudgetTracker(),
                tokenBudgetTracker = TokenBudgetTracker()
            ),
            config = config
        )
    }

    private fun tempPolicyPath(): String {
        val file = Files.createTempFile("policy", ".yaml")
        tempFiles.add(file)
        Files.writeString(
            file,
            """
            version: 1
            defaults:
              action: DENY
            """.trimIndent()
        )
        return file.toString()
    }
}
