package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.audit.AuditHeaderRewrite
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.HeaderRewriteAction
import com.mustafadakhel.oag.policy.core.PolicyHeaderRewrite
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.HeaderRewritesKey
import com.mustafadakhel.oag.pipeline.HeaderState
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestIdKey
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.MutationPhase
import com.mustafadakhel.oag.pipeline.REQUEST_HOP_BY_HOP_HEADERS
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.denyPhase
import com.mustafadakhel.oag.pipeline.hostHeaderValue
import com.mustafadakhel.oag.pipeline.inspection.HeaderRewriteResult
import com.mustafadakhel.oag.pipeline.RequestId

import java.util.Locale

class PrepareHeadersPhase : MutationPhase {
    override val name = "prepare_headers"
    override fun mutate(context: RequestPipelineContext) = prepareHeaders(context)
}

class PrepareHeadersMitmPhase : MutationPhase {
    override val name = "prepare_headers_mitm"
    override fun mutate(context: RequestPipelineContext) = prepareHeadersMitm(context)
}

class TransferEncodingPhase : GatePhase {
    override val name = "transfer_encoding"
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkTransferEncodingPhase(context)
}

class BodySizePhase(
    private val policyService: PolicyService
) : GatePhase {
    override val name = "body_size"
    override val skipWhenPolicyDenied = true
    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> =
        checkBodySizePhase(context, policyService)
}

class HeaderRewritesPhase : MutationPhase {
    override val name = "header_rewrites"
    override fun mutate(context: RequestPipelineContext) = applyHeaderRewritesPhase(context)
}

class RequestIdPhase : MutationPhase {
    override val name = "request_id"
    override fun mutate(context: RequestPipelineContext) = injectRequestIdPhase(context)
}

private fun stripHopByHopHeaders(headers: Map<String, String>): MutableMap<String, String> =
    headers.toMutableMap().apply {
        keys.removeAll { it.lowercase(Locale.ROOT) in REQUEST_HOP_BY_HOP_HEADERS }
    }

fun prepareHeaders(context: RequestPipelineContext) {
    val headers = stripHopByHopHeaders(context.request.headers)
    headers[HttpConstants.HOST] = hostHeaderValue(context.target)
    context.outputs.put(HeaderState, headers)
}

// MITM inner requests already carry the correct Host header from the decrypted
// TLS stream — no need to rewrite it like prepareHeaders does for plain HTTP.
fun prepareHeadersMitm(context: RequestPipelineContext) =
    context.outputs.put(HeaderState, stripHopByHopHeaders(context.request.headers))

fun checkTransferEncodingPhase(context: RequestPipelineContext): PhaseOutcome<Unit> {
    if (context.request.headers[HttpConstants.TRANSFER_ENCODING] != null) {
        return context.denyPhase(ReasonCode.INVALID_REQUEST, HttpStatus.BAD_REQUEST)
    }
    return PhaseOutcome.Continue(Unit)
}

fun checkBodySizePhase(context: RequestPipelineContext, policyService: PolicyService): PhaseOutcome<Unit> {
    val maxBodyBytes = context.matchedRule?.maxBodyBytes ?: policyService.current.defaults?.maxBodyBytes
    val contentLength = context.request.headers[HttpConstants.CONTENT_LENGTH]?.toLongOrNull()
    if (maxBodyBytes != null && contentLength != null && contentLength > maxBodyBytes) {
        return context.denyPhase(ReasonCode.BODY_TOO_LARGE)
    }
    return PhaseOutcome.Continue(Unit)
}

fun applyHeaderRewrites(headers: Map<String, String>, rewrites: List<PolicyHeaderRewrite>?): HeaderRewriteResult {
    if (rewrites.isNullOrEmpty()) return HeaderRewriteResult(headers, emptyList())
    val result = headers.toMutableMap()
    val audit = buildList {
        for (rewrite in rewrites) {
            val key = rewrite.header.lowercase(Locale.ROOT)
            when (rewrite.action) {
                HeaderRewriteAction.SET -> {
                    result[key] = rewrite.value ?: ""
                    add(AuditHeaderRewrite(action = rewrite.action.label(), header = rewrite.header))
                }
                HeaderRewriteAction.REMOVE -> {
                    if (result.remove(key) != null) {
                        add(AuditHeaderRewrite(action = rewrite.action.label(), header = rewrite.header))
                    }
                }
                HeaderRewriteAction.APPEND -> {
                    val existing = result[key]
                    val value = rewrite.value ?: ""
                    result[key] = if (existing != null) "$existing, $value" else value
                    add(AuditHeaderRewrite(action = rewrite.action.label(), header = rewrite.header))
                }
            }
        }
    }
    return HeaderRewriteResult(result, audit)
}

fun applyHeaderRewritesPhase(context: RequestPipelineContext) {
    val rewriteResult = applyHeaderRewrites(context.headers, context.matchedRule?.headerRewrites)
    context.outputs.put(HeaderState, rewriteResult.headers)
    rewriteResult.auditEntries.ifEmpty { null }?.let { context.outputs.put(HeaderRewritesKey, it) }
}

fun injectRequestIdPhase(context: RequestPipelineContext) {
    val requestId = RequestId.generate()
    context.outputs.put(RequestIdKey, requestId)
    val updatedHeaders = context.headers.toMutableMap()
    updatedHeaders[context.config.requestId.requestIdHeader.lowercase(Locale.ROOT)] = requestId.value
    context.outputs.put(HeaderState, updatedHeaders)
}
