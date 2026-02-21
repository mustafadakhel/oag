package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.distribution.decodeFromPath
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import kotlinx.serialization.Serializable

import java.nio.file.Path
import java.util.Locale


@Serializable
data class PolicyTestDocument(
    val cases: List<PolicyTestCase> = emptyList()
)

@Serializable
data class PolicyTestCase(
    val name: String,
    val request: String,
    val expectAction: String,
    val expectReason: String? = null
)

internal data class PolicyTestResult(
    val total: Int,
    val passed: Int,
    val failed: Int,
    val failures: List<String> = emptyList(),
    val caseResults: List<PolicyCaseResult> = emptyList()
)

internal data class PolicyCaseResult(
    val name: String,
    val ok: Boolean,
    val expectedAction: String,
    val expectedReason: String?,
    val actualAction: String,
    val actualReason: String
)


internal fun runPolicyCases(policyService: PolicyService, casesPath: Path): PolicyTestResult {
    val doc = loadPolicyTestDocument(casesPath)
    if (doc.cases.isEmpty()) throw InvalidArgumentException.of("No cases found in $casesPath")

    val caseResults = doc.cases.map { case ->
        val request = parsePolicyRequest(case.request)
        val decision = policyService.evaluate(request)
        val expectedAction = parseExpectedAction(case.expectAction)
        val actionOk = decision.action == expectedAction
        val reasonOk = case.expectReason?.let { it == decision.reasonCode.label() } ?: true
        PolicyCaseResult(
            name = case.name,
            ok = actionOk && reasonOk,
            expectedAction = expectedAction.label(),
            expectedReason = case.expectReason,
            actualAction = decision.action.label(),
            actualReason = decision.reasonCode.label()
        )
    }
    val failures = caseResults.filterNot { it.ok }.map { result ->
        val expectedReasonForMessage = result.expectedReason ?: "*"
        val expected = "action=${result.expectedAction} reason=$expectedReasonForMessage"
        val actual = "action=${result.actualAction} reason=${result.actualReason}"
        "${result.name}: expected($expected) actual($actual)"
    }

    return PolicyTestResult(
        total = doc.cases.size,
        passed = doc.cases.size - failures.size,
        failed = failures.size,
        failures = failures,
        caseResults = caseResults
    )
}

private fun loadPolicyTestDocument(casesPath: Path): PolicyTestDocument =
    try {
        decodeFromPath(casesPath)
    } catch (e: Exception) {
        throw IllegalArgumentException(
            "Failed to parse test cases from $casesPath. " +
                "Expected format: cases: [{name: \"...\", request: \"METHOD https://host/path\", expectAction: allow|deny}]. " +
                "Error: ${e.message}",
            e
        )
    }

private fun parsePolicyRequest(spec: String) =
    parseRequestSpec(spec, "Invalid case request format: $spec")

private fun parseExpectedAction(action: String): PolicyAction =
    when (action.trim().lowercase(Locale.ROOT)) {
        PolicyAction.ALLOW.label() -> PolicyAction.ALLOW
        PolicyAction.DENY.label() -> PolicyAction.DENY
        else -> throw InvalidArgumentException.of("Invalid expectAction '$action', use allow|deny")
    }

