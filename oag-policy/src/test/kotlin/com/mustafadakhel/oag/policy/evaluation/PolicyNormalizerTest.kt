package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PatternAnchor
import com.mustafadakhel.oag.policy.core.PolicyAnchoredPattern
import com.mustafadakhel.oag.policy.core.PolicyCondition
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyMlClassifier
import com.mustafadakhel.oag.policy.core.PolicyRule

import kotlin.test.Test
import kotlin.test.assertEquals

class PolicyNormalizerTest {
    @Test
    fun `normalizer trims and normalizes fields`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "  rule ",
                    host = " API.EXAMPLE.COM ",
                    methods = listOf(" get ", "POST"),
                    paths = listOf(" /v1/* "),
                    secrets = listOf("  KEY1 ")
                )
            )
        )

        val normalized = policy.normalize()
        val rule = requireNotNull(normalized.allow).first()

        assertEquals("rule", rule.id)
        assertEquals("api.example.com", rule.host)
        assertEquals(listOf("GET", "POST"), rule.methods)
        assertEquals(listOf("/v1/*"), rule.paths)
        assertEquals(listOf("KEY1"), rule.secrets)
    }

    @Test
    fun `normalizer lowercases condition scheme`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "  HTTPS  ", ports = listOf(443))
                )
            )
        )

        val normalized = policy.normalize()
        val cond = requireNotNull(requireNotNull(normalized.allow).first().conditions)

        assertEquals("https", cond.scheme)
        assertEquals(listOf(443), cond.ports)
    }

    @Test
    fun `normalizer trims reason code`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule", host = "api.example.com", reasonCode = "  custom_code  ")
            )
        )

        val normalized = policy.normalize()
        assertEquals("custom_code", requireNotNull(normalized.allow).first().reasonCode)
    }

    @Test
    fun `normalizer preserves null conditions`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(id = "rule", host = "api.example.com", conditions = null)
            )
        )

        val normalized = policy.normalize()
        assertEquals(null, requireNotNull(normalized.allow).first().conditions)
    }

    @Test
    fun `normalizer preserves rule-level content_inspection`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    contentInspection = PolicyContentInspection(
                        enableBuiltinPatterns = true,
                        customPatterns = listOf("badword")
                    )
                )
            )
        )
        val normalized = policy.normalize()
        val rule = requireNotNull(normalized.allow).first()
        assertEquals(true, rule.contentInspection?.enableBuiltinPatterns)
        assertEquals(listOf("badword"), rule.contentInspection?.customPatterns)
    }

    @Test
    fun `normalizer preserves skip_content_inspection`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    skipContentInspection = true
                )
            )
        )
        val normalized = policy.normalize()
        assertEquals(true, requireNotNull(normalized.allow).first().skipContentInspection)
    }

    @Test
    fun `normalizer preserves skip_response_scanning`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    skipResponseScanning = true
                )
            )
        )
        val normalized = policy.normalize()
        assertEquals(true, requireNotNull(normalized.allow).first().skipResponseScanning)
    }

    @Test
    fun `normalizer preserves anchored_patterns in content_inspection`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    contentInspection = PolicyContentInspection(
                        anchoredPatterns = listOf(
                            PolicyAnchoredPattern("test_pattern", PatternAnchor.STANDALONE),
                            PolicyAnchoredPattern("another", null)
                        )
                    )
                )
            )
        )
        val normalized = policy.normalize()
        val anchored = requireNotNull(requireNotNull(normalized.allow).first().contentInspection?.anchoredPatterns)
        assertEquals(2, anchored.size)
        assertEquals("test_pattern", anchored[0].pattern)
        assertEquals(PatternAnchor.STANDALONE, anchored[0].anchor)
        assertEquals("another", anchored[1].pattern)
        assertEquals(null, anchored[1].anchor)
    }

    @Test
    fun `normalizer preserves tls_inspect`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    tlsInspect = true
                )
            )
        )
        val normalized = policy.normalize()
        assertEquals(true, requireNotNull(normalized.allow).first().tlsInspect)
    }

    @Test
    fun `normalizer preserves ml_classifier in defaults`() {
        val mlConfig = PolicyMlClassifier(
            enabled = true,
            modelPath = "/models/deberta.onnx",
            tokenizerPath = "/models/tokenizer.json",
            confidenceThreshold = 0.8,
            maxLength = 256
        )
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(mlClassifier = mlConfig)
        )
        val normalized = policy.normalize()
        assertEquals(mlConfig, requireNotNull(normalized.defaults).mlClassifier)
    }

    @Test
    fun `normalizer lowercases rule data classification categories`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rule",
                    host = "api.example.com",
                    dataClassification = PolicyDataClassification(
                        categories = listOf("FINANCIAL", "Pii", "credentials")
                    )
                )
            )
        )
        val normalized = policy.normalize()
        val dc = requireNotNull(requireNotNull(normalized.allow).first().dataClassification)
        assertEquals(listOf("financial", "pii", "credentials"), dc.categories)
    }

    @Test
    fun `normalizer lowercases defaults data classification categories`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                dataClassification = PolicyDataClassification(
                    categories = listOf("FINANCIAL", "PII"),
                    enableBuiltinPatterns = true
                )
            )
        )
        val normalized = policy.normalize()
        val dc = requireNotNull(requireNotNull(normalized.defaults).dataClassification)
        assertEquals(listOf("financial", "pii"), dc.categories)
        assertEquals(true, dc.enableBuiltinPatterns)
    }

    @Test
    fun `normalizer trims lowercases and deduplicates webhookEvents`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    webhookEvents = listOf("  CIRCUIT_OPEN ", "injection_detected", "CIRCUIT_OPEN")
                )
            )
        )
        val normalized = policy.normalize()
        val events = requireNotNull(requireNotNull(normalized.allow).first().webhookEvents)
        assertEquals(listOf("circuit_open", "injection_detected"), events)
    }

    @Test
    fun `normalizer preserves per-rule timeout fields`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    connectTimeoutMs = 3000,
                    readTimeoutMs = 15000
                )
            )
        )
        val normalized = policy.normalize()
        val rule = requireNotNull(normalized.allow).first()
        assertEquals(3000, rule.connectTimeoutMs)
        assertEquals(15000, rule.readTimeoutMs)
    }
}
