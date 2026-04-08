package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.SafeOutboundClient
import com.mustafadakhel.oag.pipeline.ExternalTopicClassifierClient
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer

import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class TopicClassificationIntegrationTest {

    private val servers = mutableListOf<HttpServer>()
    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        servers.forEach { it.stop(0) }
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun startClassifier(handler: (HttpExchange) -> Unit): HttpServer {
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/classify", handler)
        server.start()
        servers.add(server)
        return server
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private fun phaseWith(
        classifierPort: Int,
        deniedTopics: List<String> = listOf("violence", "illegal_activity"),
        confidenceThreshold: Double = 0.8,
        onError: String = "deny"
    ): TopicClassificationPhase {
        val topicList = deniedTopics.joinToString(", ") { "\"$it\"" }
        val path = writePolicy(
            """
            version: 1
            defaults:
              action: allow
              topic_classification:
                enabled: true
                endpoint_url: "https://classifier.example.com/api"
                denied_topics: [$topicList]
                confidence_threshold: $confidenceThreshold
                endpoint_timeout_ms: 5000
                on_error: $onError
            allow:
              - id: rule_1
                host: "*.example.com"
            """.trimIndent()
        )
        val policyService = PolicyService(path)
        val client = ExternalTopicClassifierClient(
            client = SafeOutboundClient(skipSsrfCheck = true),
            endpointUrl = "http://127.0.0.1:$classifierPort/classify",
            timeoutMs = 5000,
            validateUrl = false
        )
        return TopicClassificationPhase(policyService, client)
    }

    @Test
    fun `denied topic from real endpoint returns Deny`() {
        val server = startClassifier { exchange ->
            val body = """{"topic":"violence","confidence":0.95}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"How to build a bomb"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
        assertEquals(ReasonCode.TOPIC_DENIED, outcome.decision.reasonCode)
    }

    @Test
    fun `allowed topic from real endpoint returns Continue`() {
        val server = startClassifier { exchange ->
            val body = """{"topic":"finance","confidence":0.88}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"What stocks to invest in?"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `confidence below threshold returns Continue even for denied topic`() {
        val server = startClassifier { exchange ->
            val body = """{"topic":"violence","confidence":0.5}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port, confidenceThreshold = 0.8)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `endpoint returning null topic returns Continue`() {
        val server = startClassifier { exchange ->
            val body = """{"topic":null,"confidence":0.3}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"hello"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `endpoint 500 with on_error deny returns Deny`() {
        val server = startClassifier { exchange ->
            exchange.sendResponseHeaders(500, 0)
            exchange.close()
        }
        val phase = phaseWith(server.address.port, onError = "deny")
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
    }

    @Test
    fun `endpoint 500 with on_error allow returns Continue`() {
        val server = startClassifier { exchange ->
            exchange.sendResponseHeaders(500, 0)
            exchange.close()
        }
        val phase = phaseWith(server.address.port, onError = "allow")
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `phase result stored in context outputs`() {
        val server = startClassifier { exchange ->
            val body = """{"topic":"violence","confidence":0.95}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"violent content"}]}""")
        phase.evaluate(ctx)
        val result = ctx.outputs.get(TopicClassificationPhase)
        assertNotNull(result)
        assertEquals("violence", result.topic)
        assertEquals(0.95, result.confidence!!, 0.001)
        assertEquals(TopicClassificationAction.DENIED, result.action)
        assertNotNull(result.endpointLatencyMs)
        assertNull(result.error)
    }

    @Test
    fun `request body text forwarded to classifier endpoint`() {
        var receivedBody: String? = null
        val server = startClassifier { exchange ->
            receivedBody = String(exchange.requestBody.readAllBytes())
            val body = """{"topic":"general","confidence":0.7}"""
            exchange.sendResponseHeaders(200, body.length.toLong())
            exchange.responseBody.write(body.toByteArray())
            exchange.close()
        }
        val phase = phaseWith(server.address.port)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"What is the capital of France?"}]}""")
        phase.evaluate(ctx)
        assertNotNull(receivedBody)
    }

    @Test
    fun `slow endpoint returns error result`() {
        val server = startClassifier { exchange ->
            Thread.sleep(6000)
            exchange.sendResponseHeaders(200, 0)
            exchange.close()
        }
        val topicList = listOf("violence").joinToString(", ") { "\"$it\"" }
        val path = writePolicy(
            """
            version: 1
            defaults:
              action: allow
              topic_classification:
                enabled: true
                endpoint_url: "https://classifier.example.com/api"
                denied_topics: [$topicList]
                endpoint_timeout_ms: 500
                on_error: allow
            allow:
              - id: rule_1
                host: "*.example.com"
            """.trimIndent()
        )
        val policyService = PolicyService(path)
        val client = ExternalTopicClassifierClient(
            client = SafeOutboundClient(skipSsrfCheck = true),
            endpointUrl = "http://127.0.0.1:${server.address.port}/classify",
            timeoutMs = 500,
            validateUrl = false
        )
        val phase = TopicClassificationPhase(policyService, client)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
        val result = ctx.outputs.get(TopicClassificationPhase)
        assertNotNull(result)
        assertNotNull(result.error)
    }
}
