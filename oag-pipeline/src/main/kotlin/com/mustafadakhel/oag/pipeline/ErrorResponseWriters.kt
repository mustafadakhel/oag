package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.enforcement.CircuitBreakerRegistry
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.policy.core.shouldNotifyWebhook

fun buildRequestExceptionHandler(
    circuitBreakerRegistry: CircuitBreakerRegistry?,
    webhookCallback: WebhookCallback? = null,
    errorStrategy: ErrorStrategy = defaultErrorStrategy(circuitBreakerRegistry, webhookCallback)
): RequestExceptionHandler = RequestExceptionHandler { context, exception ->
    errorStrategy.handle(context, exception)
}

fun defaultErrorStrategy(
    circuitBreakerRegistry: CircuitBreakerRegistry?,
    webhookCallback: WebhookCallback? = null
) = ErrorStrategy { context, exception ->
    if (exception is OagRequestException.UpstreamFailure) {
        circuitBreakerRegistry?.get(context.target.host)?.recordFailure()
    }
    if (exception is OagRequestException.PolicyDenied) {
        dispatchRequestEnforcementActions(exception.enforcementActions, context, webhookCallback)
    }
    val skipResponse = exception is OagRequestException.PolicyDenied && context.dryRun
    val customResponse = (exception as? OagRequestException.PolicyDenied)?.errorResponse
    if (context.output.bytesWritten == 0L && !skipResponse) {
        if (customResponse != null) {
            writeCustomDenied(context.output, customResponse)
        } else {
            writeErrorResponse(context.output, exception.status.code)
        }
    }
    val retryCount = (exception as? OagRequestException.UpstreamFailure)?.retryCount?.takeIf { it > 0 }
    val effectiveStatus = customResponse?.status ?: exception.status.code
    logAudit(
        context, exception.decision,
        RelayOutcome(statusCode = effectiveStatus, retryCount = retryCount),
        extras = exception.extras
    )
}

private fun dispatchRequestEnforcementActions(
    actions: List<EnforcementAction>,
    context: RequestPipelineContext,
    webhookCallback: WebhookCallback?
) {
    for (action in actions) {
        when (action) {
            is EnforcementAction.Notify -> {
                if (context.matchedRule?.shouldNotifyWebhook(action.message) == false) continue
                val payload = webhookData(
                    WebhookPayloadKeys.DATA_HOST to context.target.host,
                    WebhookPayloadKeys.DATA_PATH to context.target.path,
                    WebhookPayloadKeys.DATA_METHOD to context.request.method,
                    *action.data.map { (k, v) -> k to v }.toTypedArray()
                )
                webhookCallback?.send(action.message, payload)
            }
            is EnforcementAction.Deny -> {} // deny response already written by error strategy above
            is EnforcementAction.Allow -> {} // no-op in deny context
            is EnforcementAction.Redact -> {} // response-phase action, handled by relay
            is EnforcementAction.Truncate -> {} // response-phase action, handled by relay
        }
    }
}

fun handleRequestException(
    context: RequestPipelineContext,
    exception: OagRequestException,
    circuitBreakerRegistry: CircuitBreakerRegistry? = null,
    webhookCallback: WebhookCallback? = null
) {
    defaultErrorStrategy(circuitBreakerRegistry, webhookCallback).handle(context, exception)
}
