package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.TopicClassificationException
import com.mustafadakhel.oag.pipeline.TopicClassificationRequest
import com.mustafadakhel.oag.pipeline.TopicClassificationResponse
import com.mustafadakhel.oag.pipeline.TopicClassifierClient
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.PolicyTopicClassification
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class TopicClassificationPhaseTest {

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

    private fun policyServiceWith(deniedTopics: List<String>? = null, allowedTopics: List<String>? = null): PolicyService {
        val topicLine = when {
            deniedTopics != null -> "    denied_topics: [${deniedTopics.joinToString(", ") { "\"$it\"" }}]"
            allowedTopics != null -> "    allowed_topics: [${allowedTopics.joinToString(", ") { "\"$it\"" }}]"
            else -> ""
        }
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  topic_classification:\n" +
            "    enabled: true\n" +
            "    endpoint_url: \"https://classifier.example.com/api\"\n" +
            (if (topicLine.isNotEmpty()) "$topicLine\n" else "") +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        return PolicyService(path)
    }

    private fun mockClient(topic: String?, confidence: Double = 0.9): TopicClassifierClient =
        TopicClassifierClient { TopicClassificationResponse(topic = topic, confidence = confidence) }

    private fun failingClient(): TopicClassifierClient =
        TopicClassifierClient { throw TopicClassificationException("connection timeout") }

    private fun capturingClient(): Pair<TopicClassifierClient, MutableList<String>> {
        val captured = mutableListOf<String>()
        val client = TopicClassifierClient { request ->
            captured.add(request.text)
            TopicClassificationResponse(topic = "finance", confidence = 0.9)
        }
        return client to captured
    }

    @Test
    fun `denied topic returns Deny with TOPIC_DENIED`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
        assertEquals(ReasonCode.TOPIC_DENIED, outcome.decision.reasonCode)
    }

    @Test
    fun `non-denied topic returns Continue`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("finance"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `confidence below threshold returns Continue`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("violence", confidence = 0.1))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `on_error deny blocks on client exception`() {
        val path = writePolicy("""
            version: 1
            defaults:
              action: allow
              topic_classification:
                enabled: true
                endpoint_url: "https://classifier.example.com/api"
                denied_topics: ["violence"]
                on_error: deny
            allow:
              - id: rule_1
                host: "*.example.com"
        """.trimIndent())
        val service = PolicyService(path)
        val phase = TopicClassificationPhase(service, failingClient())
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
    }

    @Test
    fun `on_error allow continues on client exception`() {
        val path = writePolicy("""
            version: 1
            defaults:
              action: allow
              topic_classification:
                enabled: true
                endpoint_url: "https://classifier.example.com/api"
                denied_topics: ["violence"]
                on_error: allow
            allow:
              - id: rule_1
                host: "*.example.com"
        """.trimIndent())
        val service = PolicyService(path)
        val phase = TopicClassificationPhase(service, failingClient())
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `no config in rule or defaults returns Continue`() {
        val path = writePolicy("""
            version: 1
            defaults:
              action: allow
            allow:
              - id: rule_1
                host: "*.example.com"
        """.trimIndent())
        val service = PolicyService(path)
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `no buffered body returns Continue`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext()
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `case-insensitive topic comparison`() {
        val service = policyServiceWith(deniedTopics = listOf("finance"))
        val phase = TopicClassificationPhase(service, mockClient("Finance"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
    }

    @Test
    fun `result stored in PhaseOutputs after evaluation`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("finance", 0.85))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        phase.evaluate(ctx)
        val result = ctx.outputs.getOrNull(TopicClassificationPhase)
        assertNotNull(result)
        assertEquals("finance", result.topic)
        assertEquals(0.85, result.confidence!!, 0.001)
    }

    @Test
    fun `enrichAudit stores result in outputs without throwing`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        phase.enrichAudit(ctx)
        val result = ctx.outputs.getOrNull(TopicClassificationPhase)
        assertNotNull(result)
    }

    @Test
    fun `allowed_topics mode denies unlisted topic`() {
        val service = policyServiceWith(allowedTopics = listOf("finance", "health"))
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
    }

    @Test
    fun `allowed_topics mode allows listed topic`() {
        val service = policyServiceWith(allowedTopics = listOf("finance", "health"))
        val phase = TopicClassificationPhase(service, mockClient("finance"))
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `circuit breaker open triggers deny with default on_error`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val breaker = CircuitBreakerCheck { false }
        val phase = TopicClassificationPhase(service, mockClient("finance"), breaker)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Deny>(outcome)
    }

    @Test
    fun `circuit breaker open with on_error allow continues`() {
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  topic_classification:\n" +
            "    enabled: true\n" +
            "    endpoint_url: \"https://classifier.example.com/api\"\n" +
            "    denied_topics: [\"violence\"]\n" +
            "    on_error: allow\n" +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        val service = PolicyService(path)
        val breaker = CircuitBreakerCheck { false }
        val phase = TopicClassificationPhase(service, mockClient("finance"), breaker)
        val ctx = buildTestContext(bodyText = """{"messages":[{"role":"user","content":"test"}]}""")
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
    }

    @Test
    fun `user-turn text preferred over full body`() {
        val service = policyServiceWith(deniedTopics = listOf("violence"))
        val (client, captured) = capturingClient()
        val phase = TopicClassificationPhase(service, client)
        val body = """{"messages":[{"role":"user","content":"user question here"}]}"""
        val ctx = buildTestContext(bodyText = body)
        phase.evaluate(ctx)
        assertEquals(1, captured.size)
        assertEquals("user question here", captured[0])
    }

    @Test
    fun `skipTopicClassification skips evaluation`() {
        val path = writePolicy("""
            version: 1
            defaults:
              action: allow
              topic_classification:
                enabled: true
                endpoint_url: "https://classifier.example.com/api"
                denied_topics: ["violence"]
            allow:
              - id: rule_1
                host: "*.example.com"
                skip_topic_classification: true
        """.trimIndent())
        val service = PolicyService(path)
        val phase = TopicClassificationPhase(service, mockClient("violence"))
        val ctx = buildTestContext(
            bodyText = """{"messages":[{"role":"user","content":"test"}]}""",
            rule = PolicyRule(id = "rule_1", host = "*", skipTopicClassification = true)
        )
        val outcome = phase.evaluate(ctx)
        assertIs<PhaseOutcome.Continue<Unit>>(outcome)
        assertNull(ctx.outputs.getOrNull(TopicClassificationPhase))
    }
}
