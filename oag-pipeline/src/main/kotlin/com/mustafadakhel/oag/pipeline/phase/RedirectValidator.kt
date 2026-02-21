package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.audit.AuditRedirectHop
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyRequest
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.http.isIpLiteralHost
import com.mustafadakhel.oag.http.parseAbsoluteTarget
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.network.resolvedIpBlockDecision

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

import java.net.URI

private const val REDIRECT_DNS_TIMEOUT_MS = 5_000L

data class RedirectValidationResult(
    val redirectChain: List<AuditRedirectHop>,
    val denied: RedirectDenial? = null
)

suspend fun validateRedirect(
    statusCode: Int,
    location: String?,
    requestTarget: ParsedTarget,
    requestMethod: String,
    policyService: PolicyService,
    blockIpLiterals: Boolean,
    blockPrivateResolvedIps: Boolean,
    hostResolver: HostResolver
): RedirectValidationResult {
    if (!isRedirect(statusCode) || location == null) {
        return RedirectValidationResult(emptyList())
    }

    val redirectTarget = resolveRedirectTarget(location, requestTarget)
    val chain = listOf(
        AuditRedirectHop(
            status = statusCode,
            location = location,
            targetHost = redirectTarget?.host,
            targetPort = redirectTarget?.port,
            targetScheme = redirectTarget?.scheme,
            targetPath = redirectTarget?.path
        )
    )

    if (redirectTarget == null) return RedirectValidationResult(chain)

    if (blockIpLiterals && isIpLiteralHost(redirectTarget.host)) {
        return RedirectValidationResult(
            chain,
            RedirectDenial(PolicyDecision(action = PolicyAction.DENY, ruleId = null, reasonCode = ReasonCode.RAW_IP_LITERAL_BLOCKED), HttpStatus.FORBIDDEN.code)
        )
    }

    if (blockPrivateResolvedIps) {
        val resolvedRedirectIps = runCatching {
            withTimeout(REDIRECT_DNS_TIMEOUT_MS) {
                withContext(Dispatchers.IO) { hostResolver.resolve(redirectTarget.host) }
            }
        }.getOrNull().orEmpty()
        val resolvedDecision = resolvedIpBlockDecision(redirectTarget.host, resolvedRedirectIps, blockPrivateResolvedIps)
        if (resolvedDecision != null) {
            return RedirectValidationResult(chain, RedirectDenial(resolvedDecision, HttpStatus.FORBIDDEN.code))
        }
    }

    val redirectDecision = policyService.evaluate(
        PolicyRequest(
            scheme = redirectTarget.scheme,
            host = redirectTarget.host,
            port = redirectTarget.port,
            method = requestMethod,
            path = redirectTarget.path
        )
    )
    if (redirectDecision.action == PolicyAction.DENY) {
        return RedirectValidationResult(
            chain,
            RedirectDenial(PolicyDecision(action = PolicyAction.DENY, ruleId = redirectDecision.ruleId, reasonCode = ReasonCode.REDIRECT_TARGET_DENIED), HttpStatus.FORBIDDEN.code)
        )
    }

    return RedirectValidationResult(chain)
}

fun resolveRedirectTarget(location: String, base: ParsedTarget): ParsedTarget? {
    val trimmed = location.trim()
    return when {
        trimmed.startsWith("http://", ignoreCase = true) || trimmed.startsWith("https://", ignoreCase = true) ->
            runCatching { parseAbsoluteTarget(trimmed) }.getOrNull()
        trimmed.startsWith("/") ->
            ParsedTarget(base.scheme, base.host, base.port, trimmed)
        else -> {
            val basePath = base.path.substringBeforeLast('/', "/")
            val resolved = URI("$basePath/$trimmed").normalize().path
            ParsedTarget(base.scheme, base.host, base.port, resolved)
        }
    }
}
