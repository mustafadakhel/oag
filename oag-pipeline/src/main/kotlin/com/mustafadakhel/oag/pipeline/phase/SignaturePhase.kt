package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.AuthnMethod
import com.mustafadakhel.oag.IdentityProvider
import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.SignatureInfo
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.pipeline.verifySignedHeaders
import com.mustafadakhel.oag.pipeline.VerificationResult
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.SignatureKey
import com.mustafadakhel.oag.pipeline.Phase
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.orDenyDryRunnable

class SignaturePhase : Phase {
    override val stage = PipelineStage.IDENTITY
    override val name = "signature"
    override suspend fun execute(context: RequestPipelineContext) {
        checkSignaturePhase(context).orDenyDryRunnable(context)?.let {
            context.outputs.put(SignatureKey, it)
        }
    }
}

fun checkSignaturePhase(context: RequestPipelineContext): PhaseOutcome<IdentityResult?> {
    val secret = context.config.security.agentSigningSecret
    val headers = context.request.headers
    val hasSignature = headers.containsKey(HttpConstants.OAG_SIGNATURE)

    if (secret == null) {
        if (context.config.security.requireSignedHeaders) {
            context.debugLog { "unsigned request rejected: require_signed_headers=true but no signing secret configured" }
            return PhaseOutcome.Deny(
                decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.SIGNATURE_INVALID),
                statusCode = HttpStatus.UNAUTHORIZED
            )
        }
        return PhaseOutcome.Continue(null)
    }

    if (!hasSignature) {
        if (context.config.security.requireSignedHeaders) {
            context.debugLog { "unsigned request rejected require_signed_headers=true" }
            return PhaseOutcome.Deny(
                decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.SIGNATURE_INVALID),
                statusCode = HttpStatus.UNAUTHORIZED
            )
        }
        return PhaseOutcome.Continue(null)
    }

    val provider = signatureIdentityProvider(
        secret = secret,
        method = context.request.method,
        host = context.target.host,
        path = context.target.path
    )
    val identity = provider.extract(headers)

    if (!identity.authenticated) {
        context.debugLog { "signature verification failed" }
        return PhaseOutcome.Deny(
            decision = PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.SIGNATURE_INVALID),
            statusCode = HttpStatus.UNAUTHORIZED
        )
    }

    return PhaseOutcome.Continue(identity)
}

fun signatureIdentityProvider(
    secret: String,
    method: String,
    host: String,
    path: String
) = IdentityProvider { headers ->
    val result = verifySignedHeaders(
        headers = headers,
        method = method,
        host = host,
        path = path,
        secret = secret
    )
    if (!result.valid) return@IdentityProvider IdentityResult()
    IdentityResult(
        actorId = result.agentId,
        authnMethod = AuthnMethod.SIGNATURE,
        signatureInfo = result.agentId?.let { SignatureInfo(agentId = it, verified = true) }
    )
}
