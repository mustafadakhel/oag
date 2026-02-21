package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.*

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PolicyValidatorTest {
    @Test
    fun `missing version fails validation`() {
        val policy = PolicyDocument(version = null)
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "version" })
    }

    @Test
    fun `invalid method fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "api.openai.com",
                    methods = listOf("FETCH"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        val methodError = errors.first { it.path == "allow[0].methods[0]" }
        assertEquals("Unsupported method 'FETCH'", methodError.message)
    }

    @Test
    fun `empty host fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" })
    }

    @Test
    fun `host with scheme or path fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "https://api.openai.com/v1",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("scheme") })
    }

    @Test
    fun `host with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "api.open ai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("whitespace") })
    }

    @Test
    fun `rule id with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad id",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].id" && it.message.contains("whitespace") })
    }

    @Test
    fun `invalid wildcard host fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "wildcard",
                    host = "api.*.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("Wildcard host") })
    }

    @Test
    fun `host of only dots fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dots",
                    host = "...",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" })
    }

    @Test
    fun `host starting with dot fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dot-host",
                    host = ".example.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("start with") })
    }

    @Test
    fun `host with consecutive dots fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dotdot",
                    host = "api..example.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("consecutive dots") })
    }

    @Test
    fun `host with port fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "host-port",
                    host = "api.openai.com:443",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].host" && it.message.contains("port") })
    }

    @Test
    fun `secret scope requires hosts or ip ranges`() {
        val policy = PolicyDocument(
            version = 1,
            secretScopes = listOf(
                SecretScope(
                    id = "OPENAI_KEY",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "secret_scopes[0].hosts" })
    }

    @Test
    fun `path without leading slash fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].paths[0]" && it.message.contains("start with") })
    }

    @Test
    fun `path with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/ bad")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].paths[0]" && it.message.contains("whitespace") })
    }

    @Test
    fun `secret id with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "openai",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*"),
                    secrets = listOf("OPENAI KEY")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].secrets[0]" && it.message.contains("whitespace") })
    }

    @Test
    fun `duplicate method fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dup-method",
                    host = "api.openai.com",
                    methods = listOf("GET", "get"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].methods[1]" && it.message.contains("Duplicate method") })
    }

    @Test
    fun `method with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad-method",
                    host = "api.openai.com",
                    methods = listOf("GE T"),
                    paths = listOf("/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].methods[0]" && it.message.contains("whitespace") })
    }

    @Test
    fun `duplicate path fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dup-path",
                    host = "api.openai.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*", "/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].paths[1]" && it.message.contains("Duplicate path") })
    }

    @Test
    fun `path with scheme fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad-path",
                    host = "api.openai.com",
                    methods = listOf("GET"),
                    paths = listOf("https://api.openai.com/v1/*")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].paths[0]" })
    }

    @Test
    fun `duplicate secret id fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dup-secret",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*"),
                    secrets = listOf("OPENAI_KEY", "OPENAI_KEY")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].secrets[1]" && it.message.contains("Duplicate secret id") })
    }

    @Test
    fun `condition with invalid scheme fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad_scheme",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "ftp")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].conditions.scheme" && it.message.contains("Unsupported scheme") })
    }

    @Test
    fun `condition with valid schemes passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "http_rule",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "http")
                ),
                PolicyRule(
                    id = "https_rule",
                    host = "api.example.com",
                    conditions = PolicyCondition(scheme = "https")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("conditions.scheme") })
    }

    @Test
    fun `condition with port out of range fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad_port",
                    host = "api.example.com",
                    conditions = PolicyCondition(ports = listOf(0, 70000))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].conditions.ports[0]" && it.message.contains("between 1 and 65535") })
        assertTrue(errors.any { it.path == "allow[0].conditions.ports[1]" && it.message.contains("between 1 and 65535") })
    }

    @Test
    fun `condition with duplicate ports fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "dup_port",
                    host = "api.example.com",
                    conditions = PolicyCondition(ports = listOf(443, 443))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].conditions.ports[1]" && it.message.contains("Duplicate port") })
    }

    @Test
    fun `condition with valid ports passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "good_ports",
                    host = "api.example.com",
                    conditions = PolicyCondition(ports = listOf(80, 443, 8443))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("conditions.ports") })
    }

    @Test
    fun `empty reason code fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "empty_rc",
                    host = "api.example.com",
                    reasonCode = "  "
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].reason_code" && it.message.contains("empty") })
    }

    @Test
    fun `reason code with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "ws_rc",
                    host = "api.example.com",
                    reasonCode = "bad code"
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].reason_code" && it.message.contains("whitespace") })
    }

    @Test
    fun `valid reason code passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "good_rc",
                    host = "api.example.com",
                    reasonCode = "approved_by_compliance"
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("reason_code") })
    }

    @Test
    fun `rate limit with zero requests per second fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rate_zero",
                    host = "api.example.com",
                    rateLimit = PolicyRateLimit(requestsPerSecond = 0.0, burst = 10)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].rate_limit.requests_per_second" })
    }

    @Test
    fun `rate limit with negative burst fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rate_neg",
                    host = "api.example.com",
                    rateLimit = PolicyRateLimit(requestsPerSecond = 10.0, burst = -1)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].rate_limit.burst" })
    }

    @Test
    fun `rate limit with neither field fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rate_empty",
                    host = "api.example.com",
                    rateLimit = PolicyRateLimit()
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].rate_limit" && it.message.contains("requests_per_second and burst") })
    }

    @Test
    fun `body match with neither contains nor patterns fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "empty_body",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch()
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].body_match" && it.message.contains("contains or patterns") })
    }

    @Test
    fun `body match with invalid regex fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "bad_regex",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(patterns = listOf("[invalid"))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].body_match.patterns[0]" && it.message.contains("Invalid regex") })
    }

    @Test
    fun `body match with empty contains entry fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "empty_contains",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(contains = listOf(""))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].body_match.contains[0]" && it.message.contains("empty") })
    }

    @Test
    fun `valid body match passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "valid_body",
                    host = "api.example.com",
                    bodyMatch = PolicyBodyMatch(contains = listOf("model"), patterns = listOf("gpt-\\d+"))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("body_match") })
    }

    @Test
    fun `valid rate limit passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "rate_ok",
                    host = "api.example.com",
                    rateLimit = PolicyRateLimit(requestsPerSecond = 10.0, burst = 20)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("rate_limit") })
    }

    @Test
    fun `duplicate rule ids are reported across allow and deny`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "duplicate",
                    host = "api.openai.com",
                    methods = listOf("POST"),
                    paths = listOf("/v1/*")
                )
            ),
            deny = listOf(
                PolicyRule(
                    id = "duplicate",
                    host = "api.openai.com",
                    methods = listOf("GET"),
                    paths = listOf("/v1/*")
                )
            )
        )

        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].id" && it.message.contains("Duplicate rule id") })
        assertTrue(errors.any { it.path == "deny[0].id" && it.message.contains("Duplicate rule id") })
    }

    @Test
    fun `rule with valid content_inspection passes`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    contentInspection = PolicyContentInspection(
                        enableBuiltinPatterns = true,
                        customPatterns = listOf("(?i)badword")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("content_inspection") })
    }

    @Test
    fun `rule with invalid custom pattern in content_inspection fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    contentInspection = PolicyContentInspection(
                        customPatterns = listOf("[invalid")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].content_inspection.custom_patterns[0]" && it.message.contains("Invalid regex") })
    }

    @Test
    fun `rule with both skip_content_inspection and content_inspection fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    skipContentInspection = true,
                    contentInspection = PolicyContentInspection(enableBuiltinPatterns = true)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "allow[0].skip_content_inspection" && it.message.contains("Cannot set both") })
    }

    @Test
    fun `rule with skip_content_inspection alone is valid`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    skipContentInspection = true
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("skip_content_inspection") })
    }

    @Test
    fun `rule with skip_response_scanning and response_body_match is valid`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    skipResponseScanning = true,
                    responseBodyMatch = PolicyBodyMatch(contains = listOf("bad"))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("skip_response_scanning") })
    }

    @Test
    fun `rule with skip_response_scanning alone is valid`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    skipResponseScanning = true
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("skip_response_scanning") })
    }

    @Test
    fun `anchored_patterns with valid pattern passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                contentInspection = PolicyContentInspection(
                    anchoredPatterns = listOf(
                        PolicyAnchoredPattern("(?i)badword", PatternAnchor.STANDALONE)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("anchored_patterns") })
    }

    @Test
    fun `anchored_patterns with empty pattern fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                contentInspection = PolicyContentInspection(
                    anchoredPatterns = listOf(
                        PolicyAnchoredPattern("", PatternAnchor.ANY)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.content_inspection.anchored_patterns[0].pattern" && it.message == "Must not be empty" })
    }

    @Test
    fun `anchored_patterns with invalid regex fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                contentInspection = PolicyContentInspection(
                    anchoredPatterns = listOf(
                        PolicyAnchoredPattern("[invalid", PatternAnchor.ANY)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.content_inspection.anchored_patterns[0].pattern" && it.message.contains("Invalid regex") })
    }

    @Test
    fun `anchored_patterns with null anchor is valid`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                contentInspection = PolicyContentInspection(
                    anchoredPatterns = listOf(
                        PolicyAnchoredPattern("some_pattern", null)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("anchored_patterns") })
    }

    @Test
    fun `valid injection_scoring passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(
                    mode = InjectionScoringMode.SCORE,
                    denyThreshold = 0.8,
                    logThreshold = 0.5,
                    entropyWeight = 0.1,
                    entropyBaseline = 4.5
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("injection_scoring") })
    }

    @Test
    fun `injection_scoring deny_threshold must be positive`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(denyThreshold = 0.0)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.injection_scoring.deny_threshold" })
    }

    @Test
    fun `injection_scoring log_threshold must be positive`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(logThreshold = -1.0)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.injection_scoring.log_threshold" })
    }

    @Test
    fun `injection_scoring log_threshold must not exceed deny_threshold`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(denyThreshold = 0.5, logThreshold = 0.8)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.injection_scoring.log_threshold" && it.message.contains("deny_threshold") })
    }

    @Test
    fun `injection_scoring entropy_weight must not be negative`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(entropyWeight = -0.5)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.injection_scoring.entropy_weight" })
    }

    @Test
    fun `injection_scoring entropy_baseline must be positive`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(entropyBaseline = 0.0)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.injection_scoring.entropy_baseline" })
    }

    @Test
    fun `injection_scoring unknown category fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(
                    categoryWeights = listOf(PolicyCategoryWeight("unknown_cat", 1.0))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("category_weights[0].category") && it.message.contains("Unknown category") })
    }

    @Test
    fun `injection_scoring valid category passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(
                    categoryWeights = listOf(PolicyCategoryWeight("jailbreak", 1.5))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("category_weights") })
    }

    @Test
    fun `injection_scoring negative weight fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(
                    categoryWeights = listOf(PolicyCategoryWeight("jailbreak", -1.0))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("category_weights[0].weight") })
    }

    @Test
    fun `injection_scoring empty category fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                injectionScoring = PolicyInjectionScoring(
                    categoryWeights = listOf(PolicyCategoryWeight("", 1.0))
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("category_weights[0].category") && it.message.contains("empty") })
    }

    @Test
    fun `valid ml_classifier passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(
                    enabled = true,
                    modelPath = "/models/deberta.onnx",
                    tokenizerPath = "/models/tokenizer.json",
                    confidenceThreshold = 0.8,
                    maxLength = 512
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.startsWith("defaults.ml_classifier") })
    }

    @Test
    fun `ml_classifier enabled without model_path fails`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(enabled = true, tokenizerPath = "/tok.json")
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.ml_classifier.model_path" })
    }

    @Test
    fun `ml_classifier enabled without tokenizer_path fails`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(enabled = true, modelPath = "/model.onnx")
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.ml_classifier.tokenizer_path" })
    }

    @Test
    fun `ml_classifier disabled without paths passes`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(enabled = false)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.startsWith("defaults.ml_classifier") })
    }

    @Test
    fun `ml_classifier confidence_threshold zero fails`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(confidenceThreshold = 0.0)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.ml_classifier.confidence_threshold" })
    }

    @Test
    fun `ml_classifier confidence_threshold above 1 fails`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(confidenceThreshold = 1.5)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.ml_classifier.confidence_threshold" })
    }

    @Test
    fun `ml_classifier max_length zero fails`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier(maxLength = 0)
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path == "defaults.ml_classifier.max_length" })
    }

    @Test
    fun `ml_classifier null fields pass validation`() {
        val policy = PolicyDocument(
            version = 1,
            defaults = PolicyDefaults(
                mlClassifier = PolicyMlClassifier()
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.startsWith("defaults.ml_classifier") })
    }

    @Test
    fun `valid header rewrite passes`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "X-Custom", value = "val"),
                        PolicyHeaderRewrite(action = HeaderRewriteAction.APPEND, header = "X-Extra", value = "more"),
                        PolicyHeaderRewrite(action = HeaderRewriteAction.REMOVE, header = "X-Remove")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("header_rewrites") })
    }

    @Test
    fun `header rewrite blank header fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "  ", value = "val")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].header") && it.message.contains("blank") })
    }

    @Test
    fun `header rewrite whitespace in header fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "X Custom", value = "val")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].header") && it.message.contains("whitespace") })
    }

    @Test
    fun `header rewrite set without value fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "X-Custom")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].value") && it.message.contains("empty") })
    }

    @Test
    fun `header rewrite append without value fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.APPEND, header = "X-Custom")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].value") })
    }

    @Test
    fun `header rewrite remove without value passes`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.REMOVE, header = "X-Custom")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("header_rewrites") })
    }

    @Test
    fun `header rewrite reserved header host fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "Host", value = "evil.com")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].header") && it.message.contains("reserved") })
    }

    @Test
    fun `header rewrite reserved header content-length fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerRewrites = listOf(
                        PolicyHeaderRewrite(action = HeaderRewriteAction.SET, header = "Content-Length", value = "0")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_rewrites[0].header") && it.message.contains("reserved") })
    }

    @Test
    fun `valid per-rule timeouts pass`() {
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
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("connect_timeout_ms") || it.path.contains("read_timeout_ms") })
    }

    @Test
    fun `zero connect_timeout_ms fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    connectTimeoutMs = 0
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("connect_timeout_ms") && it.message.contains("greater than 0") })
    }

    @Test
    fun `negative read_timeout_ms fails`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    readTimeoutMs = -1
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("read_timeout_ms") && it.message.contains("greater than 0") })
    }

    @Test
    fun `null timeouts pass`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    connectTimeoutMs = null,
                    readTimeoutMs = null
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("timeout") })
    }

    @Test
    fun `valid retry config passes`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    retry = PolicyRetry(maxRetries = 3, retryDelayMs = 100)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("retry") })
    }

    @Test
    fun `retry max_retries must be greater than 0`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    retry = PolicyRetry(maxRetries = 0)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("max_retries") })
    }

    @Test
    fun `retry retry_delay_ms must be greater than 0`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    retry = PolicyRetry(maxRetries = 2, retryDelayMs = 0)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("retry_delay_ms") })
    }

    @Test
    fun `retry must specify at least one field`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    retry = PolicyRetry()
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("retry") })
    }

    @Test
    fun `valid header_match passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "Authorization", present = true)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("header_match") })
    }

    @Test
    fun `header_match blank header fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "", present = true)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_match") && it.message.contains("blank") })
    }

    @Test
    fun `header_match must specify one of value, pattern, present`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Test")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_match") && it.message.contains("Must specify") })
    }

    @Test
    fun `header_match with multiple specs fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Test", value = "foo", pattern = "bar")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_match") && it.message.contains("only one") })
    }

    @Test
    fun `valid query_match passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "model", value = "gpt-4")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("query_match") })
    }

    @Test
    fun `query_match blank param fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    queryMatch = listOf(
                        PolicyQueryMatch(param = "", present = true)
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("query_match") && it.message.contains("blank") })
    }

    @Test
    fun `header_match invalid regex fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    headerMatch = listOf(
                        PolicyHeaderMatch(header = "X-Test", pattern = "[invalid")
                    )
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("header_match") && it.message.contains("Invalid regex") })
    }

    @Test
    fun `valid tags pass validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    tags = listOf("billing", "high-priority")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("tags") })
    }

    @Test
    fun `blank tag fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    tags = listOf("")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("tags") && it.message.contains("blank") })
    }

    @Test
    fun `tag with whitespace fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            allow = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    tags = listOf("bad tag")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("tags") && it.message.contains("whitespace") })
    }

    @Test
    fun `valid error_response passes validation`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    errorResponse = PolicyErrorResponse(status = 451, body = "blocked")
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.none { it.path.contains("error_response") })
    }

    @Test
    fun `error_response with status below 400 fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    errorResponse = PolicyErrorResponse(status = 200)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("error_response") && it.message.contains("400") })
    }

    @Test
    fun `blank include path fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            includes = listOf("")
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("includes") && it.message.contains("blank") })
    }

    @Test
    fun `error_response with status above 599 fails validation`() {
        val policy = PolicyDocument(
            version = 1,
            deny = listOf(
                PolicyRule(
                    id = "r1",
                    host = "api.example.com",
                    errorResponse = PolicyErrorResponse(status = 600)
                )
            )
        )
        val errors = validatePolicy(policy)
        assertTrue(errors.any { it.path.contains("error_response") && it.message.contains("599") })
    }
}
