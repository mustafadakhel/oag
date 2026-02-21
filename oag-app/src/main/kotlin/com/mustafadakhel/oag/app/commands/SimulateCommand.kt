package com.mustafadakhel.oag.app.commands

import com.mustafadakhel.oag.app.CliCommand
import com.mustafadakhel.oag.app.CliFlags
import com.mustafadakhel.oag.app.DEFAULT_PATH
import com.mustafadakhel.oag.app.DEFAULT_SCHEME
import com.mustafadakhel.oag.app.configDirPath
import com.mustafadakhel.oag.app.policyService
import com.mustafadakhel.oag.app.runBatchSimulate
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.http.defaultPortForScheme
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.io.PrintStream
import java.nio.file.Path
import java.util.Locale

internal val SimulateCommand = CliCommand { args, out ->
    val jsonMode = args.hasFlag(CliFlags.JSON)
    val configDir = args.configDirPath()
    val batchFile = args.value(CliFlags.BATCH)
    val policyService = args.policyService(configDir, allowPositional = false)

    if (batchFile != null) {
        printBatchResult(policyService, Path.of(batchFile), jsonMode, out)
        return@CliCommand 0
    }

    val method = args.requireValue(CliFlags.METHOD).uppercase(Locale.ROOT)
    val host = args.requireValue(CliFlags.HOST)
    val path = args.value(CliFlags.PATH) ?: DEFAULT_PATH
    val scheme = args.value(CliFlags.SCHEME) ?: DEFAULT_SCHEME
    val port = args.intValue(CliFlags.PORT, defaultPortForScheme(scheme))

    val request = PolicyRequest(
        scheme = scheme.lowercase(Locale.ROOT),
        host = host.lowercase(Locale.ROOT),
        port = port,
        method = method,
        path = path
    )

    val match = policyService.evaluateWithRule(request)
    val decision = match.decision

    if (jsonMode) {
        val output = SimulateJsonOutput(
            action = decision.action.label(),
            reasonCode = decision.effectiveReasonCode(),
            ruleId = decision.ruleId,
            request = request.toJson(),
            eligibleSecrets = match.rule?.secrets
        )
        out.println(cliJson.encodeToString(output))
    } else {
        val reasonCode = decision.effectiveReasonCode()
        out.println("action=${decision.action.label()} reason=$reasonCode rule=${decision.ruleId ?: "-"}")
        out.println("request: ${request.method} ${request.scheme}://${request.host}:${request.port}${request.path}")
        val rule = match.rule
        val secrets = rule?.secrets
        if (secrets != null) {
            out.println("eligible_secrets: ${secrets.joinToString(", ")}")
        }
    }
    0
}

private fun PolicyRequest.toJson() = RequestSummary(
    scheme = scheme,
    host = host,
    port = port,
    method = method,
    path = path
)

private fun printBatchResult(policyService: PolicyService, batchPath: Path, jsonMode: Boolean, out: PrintStream) {
    val result = runBatchSimulate(policyService, batchPath)
    val summary = result.summary

    if (jsonMode) {
        val output = BatchSimulateJsonOutput(
            total = summary.total,
            allowCount = summary.allowCount,
            denyCount = summary.denyCount,
            ruleHitCounts = summary.ruleHitCounts,
            results = result.results.map { entry ->
                BatchResultJson(
                    name = entry.name,
                    action = entry.action,
                    reasonCode = entry.reasonCode,
                    ruleId = entry.ruleId,
                    request = RequestSummary(
                        scheme = entry.scheme,
                        host = entry.host,
                        port = entry.port,
                        method = entry.method,
                        path = entry.path
                    ),
                    eligibleSecrets = entry.eligibleSecrets
                )
            }
        )
        out.println(cliJson.encodeToString(output))
    } else {
        result.results.forEach { entry ->
            val label = entry.name ?: "${entry.method} ${entry.scheme}://${entry.host}:${entry.port}${entry.path}"
            out.println("$label: action=${entry.action} reason=${entry.reasonCode} rule=${entry.ruleId ?: "-"}")
        }
        out.println()
        out.println("total=${summary.total} allow=${summary.allowCount} deny=${summary.denyCount}")
        if (summary.ruleHitCounts.isNotEmpty()) {
            out.println("rule hits:")
            summary.ruleHitCounts.forEach { (rule, count) ->
                out.println("  $rule: $count")
            }
        }
    }
}

@Serializable
internal data class SimulateJsonOutput(
    val ok: Boolean = true,
    val action: String,
    @SerialName("reason_code") val reasonCode: String,
    @SerialName("rule_id") val ruleId: String? = null,
    val request: RequestSummary,
    @SerialName("eligible_secrets") val eligibleSecrets: List<String>? = null
)

@Serializable
internal data class BatchSimulateJsonOutput(
    val ok: Boolean = true,
    val total: Int,
    @SerialName("allow_count") val allowCount: Int,
    @SerialName("deny_count") val denyCount: Int,
    @SerialName("rule_hit_counts") val ruleHitCounts: Map<String, Int>,
    val results: List<BatchResultJson>
)

@Serializable
internal data class BatchResultJson(
    val name: String? = null,
    val action: String,
    @SerialName("reason_code") val reasonCode: String,
    @SerialName("rule_id") val ruleId: String? = null,
    val request: RequestSummary,
    @SerialName("eligible_secrets") val eligibleSecrets: List<String>? = null
)
