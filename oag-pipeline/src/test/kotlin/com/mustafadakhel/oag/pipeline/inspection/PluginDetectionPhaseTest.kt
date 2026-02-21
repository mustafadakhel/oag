package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectableArtifact
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.TextBody
import com.mustafadakhel.oag.inspection.spi.DetectorProvider
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.BodyBufferKey
import com.mustafadakhel.oag.pipeline.BodyBufferResult
import com.mustafadakhel.oag.pipeline.FindingAuditKey
import com.mustafadakhel.oag.pipeline.FindingRedactionKey
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HandlerParams
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.PluginDetectionKey
import com.mustafadakhel.oag.pipeline.PolicyEvalKey
import com.mustafadakhel.oag.pipeline.PolicyPhaseResult
import com.mustafadakhel.oag.pipeline.RequestContext
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyPluginDetection
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.io.ByteArrayOutputStream
import java.nio.file.Files

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PluginDetectionPhaseTest {

    private val tempFiles = mutableListOf<java.nio.file.Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
        tempFiles.clear()
    }

    private fun writePolicy(
        defaults: String = ""
    ): java.nio.file.Path {
        val content = buildString {
            appendLine("version: 1")
            appendLine("allow:")
            appendLine("  - id: test")
            appendLine("    host: \"*.example.com\"")
            if (defaults.isNotEmpty()) {
                appendLine("defaults:")
                appendLine(defaults.prependIndent("  "))
            }
        }
        return Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }
    }

    private fun policyService(defaults: String = "") =
        PolicyService(writePolicy(defaults))

    private fun buildContext(
        rule: PolicyRule? = null,
        policyDecision: PolicyDecision? = null,
        bodyText: String? = null,
        path: String = "/api/v1/chat"
    ): RequestPipelineContext {
        val target = ParsedTarget(scheme = "https", host = "api.example.com", port = 443, path = path)
        val request = HttpRequest(
            method = "POST",
            target = "https://api.example.com$path",
            version = "HTTP/1.1",
            headers = mapOf("Host" to "api.example.com", "Content-Type" to "application/json")
        )
        val config = HandlerConfig(
            params = HandlerParams(agentId = "agent-1", sessionId = "session-1")
        )
        val ctx = RequestPipelineContext(
            requestContext = RequestContext(config = config, target = target, request = request, trace = null),
            output = CountingOutputStream(ByteArrayOutputStream())
        )
        if (rule != null || policyDecision != null) {
            ctx.outputs.put(PolicyEvalKey, PolicyPhaseResult(
                decision = policyDecision ?: PolicyDecision(PolicyAction.ALLOW, rule?.id, ReasonCode.ALLOWED_BY_RULE),
                rule = rule,
                agentProfile = null,
                tags = null
            ))
        }
        if (bodyText != null) {
            ctx.outputs.put(BodyBufferKey, BodyBufferResult(
                body = bodyText.toByteArray(),
                bodyText = bodyText
            ))
        }
        return ctx
    }

    private fun denyFinding(detectorId: String = "test-detector") = Finding(
        type = FindingType.CUSTOM,
        severity = FindingSeverity.HIGH,
        confidence = 0.9,
        location = FindingLocation.Body,
        evidence = mapOf("source" to detectorId),
        recommendedActions = listOf(RecommendedAction.DENY)
    )

    private fun logFinding(detectorId: String = "test-detector") = Finding(
        type = FindingType.CUSTOM,
        severity = FindingSeverity.LOW,
        confidence = 0.5,
        location = FindingLocation.Body,
        evidence = mapOf("source" to detectorId),
        recommendedActions = listOf(RecommendedAction.LOG)
    )

    private fun textDetector(findings: List<Finding>): DetectorRegistration<TextBody> =
        DetectorRegistration(
            artifactType = TextBody::class.java,
            detector = Detector { _, _ -> findings },
            findingTypes = findings.map { it.type }.toSet(),
            id = "test-text-detector"
        )

    private fun textDetector(id: String, findings: List<Finding>): DetectorRegistration<TextBody> =
        DetectorRegistration(
            artifactType = TextBody::class.java,
            detector = Detector { _, _ -> findings },
            findingTypes = findings.map { it.type }.toSet(),
            id = id
        )

    private fun throwingDetector(id: String = "bad-detector"): DetectorRegistration<TextBody> =
        DetectorRegistration(
            artifactType = TextBody::class.java,
            detector = Detector { _, _ -> error("boom") },
            findingTypes = setOf(FindingType.CUSTOM),
            id = id
        )

    private fun registryFrom(vararg registrations: DetectorRegistration<*>): DetectorRegistry {
        val provider = object : DetectorProvider {
            override val id = "test-provider"
            override val description = "test"
            override fun detectors(): List<DetectorRegistration<*>> = registrations.toList()
        }
        return DetectorRegistry.fromProviders(listOf(provider))
    }

    @Test
    fun `skips when registry has no registrations`() {
        val phase = PluginDetectionPhase(DetectorRegistry.empty(), policyService())
        val context = buildContext(bodyText = "some body text")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        assertNull(context.outputs.getOrNull(PluginDetectionKey))
    }

    @Test
    fun `runs text detectors and produces findings`() {
        val finding = logFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val pluginResult = context.outputs.getOrNull(PluginDetectionKey)
        assertNotNull(pluginResult)
        assertTrue(pluginResult.findings.isNotEmpty())
    }

    @Test
    fun `produces Deny when findings have deny recommended action`() {
        val finding = denyFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Deny>(result)
    }

    @Test
    fun `respects skipPluginDetection flag`() {
        val finding = denyFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val rule = PolicyRule(host = "api.example.com", skipPluginDetection = true)
        val context = buildContext(rule = rule, bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        assertNull(context.outputs.getOrNull(PluginDetectionKey))
    }

    @Test
    fun `respects pluginDetection enabled equals false`() {
        val finding = denyFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val rule = PolicyRule(
            host = "api.example.com",
            pluginDetection = PolicyPluginDetection(enabled = false)
        )
        val context = buildContext(rule = rule, bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        assertNull(context.outputs.getOrNull(PluginDetectionKey))
    }

    @Test
    fun `filters by detectorIds allow-list`() {
        val finding = logFinding()
        val included = textDetector("included-detector", listOf(finding))
        val excluded = textDetector("other-detector", listOf(denyFinding()))
        val registry = registryFrom(included, excluded)
        val phase = PluginDetectionPhase(registry, policyService())
        val rule = PolicyRule(
            host = "api.example.com",
            pluginDetection = PolicyPluginDetection(detectorIds = listOf("included-detector"))
        )
        val context = buildContext(rule = rule, bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val pluginResult = context.outputs.getOrNull(PluginDetectionKey)
        assertNotNull(pluginResult)
        assertTrue(pluginResult.detectorIds.all { it == "included-detector" })
    }

    @Test
    fun `filters by excludeDetectorIds deny-list`() {
        val finding = denyFinding()
        val kept = textDetector("kept-detector", listOf(logFinding()))
        val excluded = textDetector("excluded-detector", listOf(finding))
        val registry = registryFrom(kept, excluded)
        val phase = PluginDetectionPhase(registry, policyService())
        val rule = PolicyRule(
            host = "api.example.com",
            pluginDetection = PolicyPluginDetection(excludeDetectorIds = listOf("excluded-detector"))
        )
        val context = buildContext(rule = rule, bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
        val pluginResult = context.outputs.getOrNull(PluginDetectionKey)
        assertNotNull(pluginResult)
        assertTrue(pluginResult.detectorIds.none { it == "excluded-detector" })
    }

    @Test
    fun `handles detector exceptions gracefully`() {
        val registry = registryFrom(throwingDetector())
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Continue<Unit>>(result)
    }

    @Test
    fun `skips when policyDenied and skipWhenPolicyDenied is true`() {
        val finding = denyFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())

        assertTrue(phase.skipWhenPolicyDenied)
    }

    @Test
    fun `LOG findings stored in FindingAuditKey`() {
        val finding = logFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "test body")

        phase.evaluate(context)

        val auditFindings = context.outputs.getOrNull(FindingAuditKey)
        assertNotNull(auditFindings)
        assertTrue(auditFindings.isNotEmpty())
    }

    @Test
    fun `REDACT findings stored in FindingRedactionKey`() {
        val finding = Finding(
            type = FindingType.PII,
            severity = FindingSeverity.MEDIUM,
            confidence = 0.8,
            location = FindingLocation.Body,
            evidence = mapOf("pattern" to "ssn"),
            recommendedActions = listOf(RecommendedAction.REDACT)
        )
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "SSN: 123-45-6789")

        phase.evaluate(context)

        val redactFindings = context.outputs.getOrNull(FindingRedactionKey)
        assertNotNull(redactFindings)
        assertTrue(redactFindings.isNotEmpty())
    }

    @Test
    fun `DENY findings do not populate redaction or audit keys`() {
        val finding = denyFinding()
        val registry = registryFrom(textDetector(listOf(finding)))
        val phase = PluginDetectionPhase(registry, policyService())
        val context = buildContext(bodyText = "test body")

        val result = phase.evaluate(context)

        assertIs<PhaseOutcome.Deny>(result)
        assertNull(context.outputs.getOrNull(FindingRedactionKey))
        assertNull(context.outputs.getOrNull(FindingAuditKey))
    }
}
