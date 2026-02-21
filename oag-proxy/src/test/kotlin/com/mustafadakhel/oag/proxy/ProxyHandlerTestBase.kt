package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.pipeline.NetworkConfig
import com.mustafadakhel.oag.pipeline.RequestIdConfig
import com.mustafadakhel.oag.proxy.pipeline.buildFullProxyHandler
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.secrets.SecretProvider
import com.mustafadakhel.oag.secrets.SecretValue

import kotlinx.serialization.json.Json

import kotlin.test.AfterTest

import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.net.InetAddress
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.Path

internal data class HandlerWithAudit(val handler: ProxyHandler, val auditOut: ByteArrayOutputStream)

internal abstract class ProxyHandlerTestBase {
    protected val testJson = Json { ignoreUnknownKeys = true }
    protected val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    protected fun createHandler(
        policyPath: Path,
        secretProvider: SecretProvider,
        dryRun: Boolean = false,
        blockIpLiterals: Boolean = false,
        enforceRedirectPolicy: Boolean = false,
        blockPrivateResolvedIps: Boolean = false,
        readTimeoutMs: Int = 30_000,
        hostResolver: HostResolver = HostResolver { host -> InetAddress.getAllByName(host).toList() },
        injectRequestId: Boolean = false,
        requestIdHeader: String = "X-Request-Id"
    ): HandlerWithAudit {
        val auditOut = ByteArrayOutputStream()
        val policyService = PolicyService(policyPath)
        return HandlerWithAudit(buildFullProxyHandler(
            config = HandlerConfig(
                network = NetworkConfig(
                    blockIpLiterals = blockIpLiterals,
                    blockPrivateResolvedIps = blockPrivateResolvedIps,
                    enforceRedirectPolicy = enforceRedirectPolicy,
                    readTimeoutMs = readTimeoutMs
                ),
                requestId = RequestIdConfig(
                    injectRequestId = injectRequestId,
                    requestIdHeader = requestIdHeader
                ),
                params = HandlerParams(
                    agentId = "agent-1",
                    sessionId = "session-1",
                    dryRun = dryRun
                )
            ),
            policyService = policyService,
            secretMaterializer = SecretMaterializer(secretProvider),
            auditLogger = AuditLogger(auditOut),
            hostResolver = hostResolver,
            rateLimiterRegistry = RateLimiterRegistry(),
            dataBudgetTracker = DataBudgetTracker(),
            tokenBudgetTracker = TokenBudgetTracker()
        ), auditOut)
    }

    protected fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also { tempFiles.add(it); Files.writeString(it, content) }

    protected fun firstAuditEvent(out: ByteArrayOutputStream): AuditEvent {
        val line = out.toString(Charsets.UTF_8).lineSequence().first { it.isNotBlank() }
        return testJson.decodeFromString<AuditEvent>(line)
    }

    protected fun readHeaders(input: InputStream): String {
        val bytes = ByteArrayOutputStream()
        var state = 0
        while (true) {
            val read = input.read()
            if (read == -1) break
            bytes.write(read)
            state = when {
                state == 0 && read == '\r'.code -> 1
                state == 1 && read == '\n'.code -> 2
                state == 2 && read == '\r'.code -> 3
                state == 3 && read == '\n'.code -> break
                else -> 0
            }
        }
        return bytes.toString(Charsets.US_ASCII)
    }
}

internal object EmptySecretProvider : SecretProvider {
    override fun resolve(secretId: String): SecretValue? = null
}

internal class TimeoutAfterBufferInputStream(
    private val payload: ByteArray
) : InputStream() {
    private var index = 0

    override fun read(): Int {
        if (index >= payload.size) throw SocketTimeoutException("simulated read timeout")
        return payload[index++].toInt() and 0xFF
    }
}

internal class IoFailureAfterBufferInputStream(
    private val payload: ByteArray
) : InputStream() {
    private var index = 0

    override fun read(): Int {
        if (index >= payload.size) throw IOException("simulated client read failure")
        return payload[index++].toInt() and 0xFF
    }
}

