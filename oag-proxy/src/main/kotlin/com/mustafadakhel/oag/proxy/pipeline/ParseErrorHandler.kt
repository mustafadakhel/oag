package com.mustafadakhel.oag.proxy.pipeline

import com.mustafadakhel.oag.pipeline.HandlerConfig
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.proxy.buildErrorAuditEvent
import com.mustafadakhel.oag.pipeline.writeBadRequest

import java.io.OutputStream

fun interface ParseErrorHandler {
    fun handleBadRequest(output: OutputStream, error: Throwable, connectionAgentId: String?)
}

internal fun buildParseErrorHandler(
    config: HandlerConfig,
    policyHashProvider: () -> String,
    auditLogger: AuditLogger
): ParseErrorHandler = ParseErrorHandler { output, error, connectionAgentId ->
    writeBadRequest(output)
    auditLogger.log(
        buildErrorAuditEvent(
            config = config,
            policyHash = policyHashProvider(),
            agentId = connectionAgentId ?: config.params.agentId,
            statusCode = HttpStatus.BAD_REQUEST.code,
            reasonCode = ReasonCode.INVALID_REQUEST,
            errorMessage = error.message ?: "failed_to_parse_request"
        )
    )
}
