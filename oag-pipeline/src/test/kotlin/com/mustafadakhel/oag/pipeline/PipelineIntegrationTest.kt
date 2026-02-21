package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.enforcement.DataBudgetTracker
import com.mustafadakhel.oag.enforcement.RateLimiterRegistry
import com.mustafadakhel.oag.enforcement.TokenBudgetTracker
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.secrets.SecretProvider
import com.mustafadakhel.oag.secrets.SecretValue

import kotlinx.coroutines.test.runTest
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class PipelineIntegrationTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private val noopProvider = object : SecretProvider {
        override fun resolve(secretId: String): SecretValue? = null
    }

    private val loopbackResolver = HostResolver { listOf(InetAddress.getLoopbackAddress()) }

    private fun buildPipelineContext(
        host: String = "api.example.com",
        path: String = "/api/v1/chat",
        method: String = "POST",
        body: String? = null
    ): RequestPipelineContext {
        val headers = buildMap {
            put("host", host)
            put(HttpConstants.CONTENT_TYPE, "application/json")
            if (body != null) put(HttpConstants.CONTENT_LENGTH, body.length.toString())
        }
        val target = ParsedTarget(scheme = "https", host = host, port = 443, path = path)
        val request = HttpRequest(method = method, target = "https://$host$path", version = "HTTP/1.1", headers = headers)
        val config = HandlerConfig(
            params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
            security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false),
            requestId = RequestIdConfig(injectRequestId = true)
        )
        return RequestPipelineContext(
            requestContext = RequestContext(config = config, target = target, request = request, trace = null),
            output = CountingOutputStream(ByteArrayOutputStream()),
            clientInput = body?.let { ByteArrayInputStream(it.toByteArray()) }
        )
    }

    @Test
    fun `http pipeline populates PolicyEvalKey for allowed request`() = runTest {
        val policyService = PolicyService(writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent()))

        val pipeline = buildHttpPipeline(
            config = HandlerConfig(
                params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
                security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false),
                requestId = RequestIdConfig(injectRequestId = true)
            ),
            policyService = policyService,
            hostResolver = loopbackResolver,
            rateLimiterRegistry = RateLimiterRegistry(),
            sessionRequestTracker = null,
            dataBudgetTracker = DataBudgetTracker(),
            tokenBudgetTracker = TokenBudgetTracker(),
            secretMaterializer = SecretMaterializer(noopProvider),
            circuitBreakerRegistry = null
        )

        val context = buildPipelineContext()
        pipeline.run(context)

        val evalResult = context.outputs.getOrNull(PolicyEvalKey)
        assertNotNull(evalResult, "PolicyEvalKey should be populated after pipeline run")
        assertEquals(PolicyAction.ALLOW, evalResult.decision.action)
    }

    @Test
    fun `http pipeline populates HeaderState and SecretInjectionKey`() = runTest {
        val policyService = PolicyService(writePolicy("""
            version: 1
            defaults:
              action: allow
        """.trimIndent()))

        val pipeline = buildHttpPipeline(
            config = HandlerConfig(
                params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
                security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false),
                requestId = RequestIdConfig(injectRequestId = true)
            ),
            policyService = policyService,
            hostResolver = loopbackResolver,
            rateLimiterRegistry = RateLimiterRegistry(),
            sessionRequestTracker = null,
            dataBudgetTracker = DataBudgetTracker(),
            tokenBudgetTracker = TokenBudgetTracker(),
            secretMaterializer = SecretMaterializer(noopProvider),
            circuitBreakerRegistry = null
        )

        val context = buildPipelineContext()
        pipeline.run(context)

        assertNotNull(context.outputs.getOrNull(HeaderState), "HeaderState should be populated")
        assertNotNull(context.outputs.getOrNull(SecretInjectionKey), "SecretInjectionKey should be populated")
        assertNotNull(context.outputs.getOrNull(RequestIdKey), "RequestIdKey should be populated")
    }

    @Test
    fun `http pipeline phases execute in correct stage order`() = runTest {
        val policyService = PolicyService(writePolicy("version: 1\ndefaults:\n  action: allow\n"))

        val pipeline = buildHttpPipeline(
            config = HandlerConfig(
                params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
                security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false)
            ),
            policyService = policyService,
            hostResolver = loopbackResolver,
            rateLimiterRegistry = RateLimiterRegistry(),
            sessionRequestTracker = null,
            dataBudgetTracker = DataBudgetTracker(),
            tokenBudgetTracker = TokenBudgetTracker(),
            secretMaterializer = SecretMaterializer(noopProvider),
            circuitBreakerRegistry = null
        )

        // Pipeline.init validates stage ordering — if this doesn't throw, ordering is correct
        val names = pipeline.phaseNames()
        assertTrue(names.isNotEmpty())
        assertTrue(names.contains("policy_evaluation"), "Expected policy_evaluation in $names")
        assertTrue(names.contains("prepare_headers"), "Expected prepare_headers in $names")
    }

    @Test
    fun `connect pipeline populates PolicyEvalKey`() = runTest {
        val policyService = PolicyService(writePolicy("version: 1\ndefaults:\n  action: allow\n"))

        val pipeline = buildConnectPipeline(
            config = HandlerConfig(
                params = HandlerParams(agentId = "agent-1", sessionId = "session-1"),
                security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false)
            ),
            policyService = policyService,
            hostResolver = loopbackResolver,
            rateLimiterRegistry = RateLimiterRegistry(),
            sessionRequestTracker = null,
            circuitBreakerRegistry = null
        )

        val context = buildPipelineContext(method = "CONNECT")
        pipeline.run(context)

        val evalResult = context.outputs.getOrNull(PolicyEvalKey)
        assertNotNull(evalResult, "PolicyEvalKey should be populated in CONNECT pipeline")
    }

    @Test
    fun `mitm pipeline populates PolicyEvalKey when connect fallback set`() = runTest {
        val policyService = PolicyService(writePolicy("version: 1\ndefaults:\n  action: allow\n"))

        val pipeline = buildMitmPipeline(
            policyService = policyService,
            rateLimiterRegistry = RateLimiterRegistry(),
            sessionRequestTracker = null,
            dataBudgetTracker = DataBudgetTracker(),
            tokenBudgetTracker = TokenBudgetTracker(),
            secretMaterializer = SecretMaterializer(noopProvider)
        )

        val context = buildPipelineContext()
        // MITM pipeline needs ConnectFallbackKey for MitmPolicyEvalPhase
        context.outputs.put(ConnectFallbackKey, ConnectFallbackData(matchedRule = null, resolvedIps = emptyList()))
        pipeline.run(context)

        val evalResult = context.outputs.getOrNull(PolicyEvalKey)
        assertNotNull(evalResult, "PolicyEvalKey should be populated in MITM pipeline")
    }

    @Test
    fun `mitm pre-policy pipeline validates path`() = runTest {
        val policyService = PolicyService(writePolicy("version: 1\ndefaults:\n  action: allow\n"))
        val config = HandlerConfig(
            params = HandlerParams(agentId = "agent-1", sessionId = null),
            security = SecurityConfig(agentSigningSecret = null, requireSignedHeaders = false)
        )

        val pipeline = buildMitmPrePolicyPipeline(config, policyService)

        assertTrue(pipeline.phaseCount > 0)
        assertTrue(pipeline.phaseNames().contains("path_validation"))
    }
}
