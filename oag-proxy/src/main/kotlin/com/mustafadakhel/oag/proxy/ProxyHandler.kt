package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.audit.AuditDecision
import com.mustafadakhel.oag.audit.AuditError
import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditRequest
import com.mustafadakhel.oag.audit.AuditResponse
import com.mustafadakhel.oag.audit.AuditSecrets
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HttpStatus

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

private const val UNPARSEABLE = "<unparseable>"

internal fun interface ProxyHandler {
    suspend fun handle(
        clientInput: InputStream,
        clientOutput: OutputStream,
        clientSocket: Socket?,
        connectionIdentity: IdentityResult?
    )
}

internal suspend fun ProxyHandler.handle(clientInput: InputStream, clientOutput: OutputStream) =
    handle(clientInput, clientOutput, null, null)

internal fun buildErrorAuditEvent(
    config: HandlerConfig,
    policyHash: String,
    agentId: String?,
    statusCode: Int,
    reasonCode: ReasonCode,
    errorMessage: String
) = AuditEvent(
    oagVersion = config.params.oagVersion,
    policyHash = policyHash,
    agentId = agentId,
    sessionId = config.params.sessionId,
    request = AuditRequest(host = UNPARSEABLE, port = 0, scheme = UNPARSEABLE, method = UNPARSEABLE, path = UNPARSEABLE, bytesOut = 0),
    response = AuditResponse(bytesIn = 0, status = statusCode),
    decision = AuditDecision(action = PolicyAction.DENY.label(), ruleId = null, reasonCode = reasonCode.label()),
    secrets = AuditSecrets(injectionAttempted = false, injected = false, secretIds = emptyList()),
    errors = listOf(AuditError(code = reasonCode.label(), message = errorMessage))
)
