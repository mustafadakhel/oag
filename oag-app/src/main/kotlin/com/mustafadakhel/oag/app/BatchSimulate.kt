package com.mustafadakhel.oag.app

import com.mustafadakhel.oag.http.defaultPortForScheme
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.distribution.decodeFromPath
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import kotlinx.serialization.Serializable

import java.nio.file.Path
import java.util.Locale

@Serializable
data class BatchRequest(
    val name: String? = null,
    val method: String,
    val host: String,
    val path: String? = null,
    val scheme: String? = null,
    val port: Int? = null
)

@Serializable
data class BatchDocument(
    val requests: List<BatchRequest> = emptyList()
)

internal data class BatchResultEntry(
    val name: String?,
    val method: String,
    val host: String,
    val port: Int,
    val path: String,
    val scheme: String,
    val action: String,
    val reasonCode: String,
    val ruleId: String?,
    val eligibleSecrets: List<String>?
)

internal data class BatchSummary(
    val total: Int,
    val allowCount: Int,
    val denyCount: Int,
    val ruleHitCounts: Map<String, Int>
)

internal data class BatchSimulateResult(
    val results: List<BatchResultEntry>,
    val summary: BatchSummary
)

internal fun runBatchSimulate(policyService: PolicyService, batchPath: Path): BatchSimulateResult {
    val doc = loadBatchDocument(batchPath)
    if (doc.requests.isEmpty()) throw InvalidArgumentException.of("No requests found in $batchPath")

    val results = doc.requests.map { batchRequest ->
        val scheme = (batchRequest.scheme ?: DEFAULT_SCHEME).lowercase(Locale.ROOT)
        val port = batchRequest.port ?: defaultPortForScheme(scheme)
        val path = batchRequest.path ?: DEFAULT_PATH

        val request = PolicyRequest(
            scheme = scheme,
            host = batchRequest.host.lowercase(Locale.ROOT),
            port = port,
            method = batchRequest.method.uppercase(Locale.ROOT),
            path = path
        )

        val match = policyService.evaluateWithRule(request)
        val decision = match.decision
        val secrets = match.rule?.secrets?.takeIf { it.isNotEmpty() }

        BatchResultEntry(
            name = batchRequest.name,
            method = request.method,
            host = request.host,
            port = port,
            path = path,
            scheme = scheme,
            action = decision.action.label(),
            reasonCode = decision.effectiveReasonCode(),
            ruleId = decision.ruleId,
            eligibleSecrets = secrets
        )
    }

    val allowAction = PolicyAction.ALLOW.label()
    val allowCount = results.count { it.action == allowAction }

    return BatchSimulateResult(
        results = results,
        summary = BatchSummary(
            total = results.size,
            allowCount = allowCount,
            denyCount = results.size - allowCount,
            ruleHitCounts = results.groupingBy { it.ruleId ?: "(no rule)" }.eachCount().toSortedMap()
        )
    )
}

private fun loadBatchDocument(path: Path): BatchDocument = decodeFromPath(path)
