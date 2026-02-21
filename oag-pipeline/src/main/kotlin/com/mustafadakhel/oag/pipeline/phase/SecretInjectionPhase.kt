package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.AuditExtras
import com.mustafadakhel.oag.pipeline.EMPTY_INJECTION_RESULT
import com.mustafadakhel.oag.pipeline.HeaderState
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.SecretInjectionKey
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.MutationPhase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.hasInvalidHeaderValueChars
import com.mustafadakhel.oag.secrets.SecretInjectionResult
import com.mustafadakhel.oag.secrets.SecretMaterializer
import com.mustafadakhel.oag.telemetry.RequestProfiler

class SecretInjectionPhase(
    private val policyService: PolicyService,
    private val secretMaterializer: SecretMaterializer
) : GatePhase {
    override val name = "secret_injection"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        context.profiler.measure(RequestProfiler.PHASE_SECRET_MATERIALIZATION) {
            injectSecretsPhase(context, policyService, secretMaterializer)
        }
}

class SecretInjectionFallbackPhase : MutationPhase {
    override val name = "secret_injection_fallback"
    override fun mutate(context: RequestPipelineContext) {
        if (context.policyDenied) {
            context.outputs.put(SecretInjectionKey, EMPTY_INJECTION_RESULT)
        }
    }
}

fun injectSecretsPhase(
    context: RequestPipelineContext,
    policyService: PolicyService,
    secretMaterializer: SecretMaterializer
): PhaseOutcome<Unit> {
    val policyRequest = context.toPolicyRequest()
    val ruleSecrets = context.matchedRule?.secrets
    val allowedSecrets = policyService.allowedSecrets(policyRequest, ruleSecrets)
    context.debugLog { "secret materialization secrets=${allowedSecrets.size}" }
    if (allowedSecrets.isEmpty() && !ruleSecrets.isNullOrEmpty()) {
        context.debugLog { "secret scope eliminated all rule secrets for ${context.target.host}${context.target.path}" }
    }
    val injectionOutcome = secretMaterializer.inject(context.headers, allowedSecrets)
    val result = injectionOutcome.result

    if (result.errors.isNotEmpty()) {
        return denySecretMaterialization(context, result)
    }

    if (injectionOutcome.headers.values.any { it.hasInvalidHeaderValueChars() }) {
        return denySecretMaterialization(context, result)
    }

    context.outputs.put(HeaderState, injectionOutcome.headers)
    context.outputs.put(SecretInjectionKey, result)

    return PhaseOutcome.Continue(Unit)
}

private fun denySecretMaterialization(
    context: RequestPipelineContext,
    result: SecretInjectionResult
): PhaseOutcome.Deny = PhaseOutcome.Deny(
    decision = PolicyDecision(
        action = PolicyAction.DENY,
        ruleId = context.policyDecision?.ruleId,
        reasonCode = ReasonCode.SECRET_MATERIALIZATION_FAILED
    ),
    statusCode = HttpStatus.FORBIDDEN,
    auditExtras = AuditExtras(
        secretIds = result.secretIds,
        injectionAttempted = result.attemptedIds.isNotEmpty(),
        secretVersions = result.secretVersions,
        tags = context.matchedTags
    )
)
