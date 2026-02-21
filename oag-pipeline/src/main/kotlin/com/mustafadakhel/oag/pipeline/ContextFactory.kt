package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.IdentityResult
import com.mustafadakhel.oag.audit.parseTraceParent
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.relay.CountingOutputStream
import com.mustafadakhel.oag.telemetry.DebugLogger
import com.mustafadakhel.oag.telemetry.OagTracer

import java.io.InputStream
import java.net.Socket

fun interface ContextFactory {
    fun build(
        target: ParsedTarget,
        request: HttpRequest,
        output: CountingOutputStream,
        connectionIdentity: IdentityResult?,
        clientInput: InputStream?,
        clientSocket: Socket?
    ): RequestPipelineContext
}

fun buildContextFactory(
    config: HandlerConfig,
    policyHashProvider: () -> String,
    tracer: OagTracer?,
    debugLogger: DebugLogger,
    auditEmitter: AuditEmitter
): ContextFactory = ContextFactory { target, request, output, connectionIdentity, clientInput, clientSocket ->
    val trace = parseTraceParent(request.headers[HttpConstants.TRACEPARENT])
    val requestSpan = tracer?.startRequestSpan(request.method, target.host, target.path, trace)
    val requestContext = RequestContext(
        config = config, target = target, request = request,
        trace = trace, connectionIdentity = connectionIdentity,
        policyHash = policyHashProvider()
    )
    RequestPipelineContext(
        requestContext = requestContext, output = output,
        clientInput = clientInput, clientSocket = clientSocket,
        debugLog = debugLogger::log,
        emitAudit = auditEmitter,
        requestSpan = requestSpan
    )
}
