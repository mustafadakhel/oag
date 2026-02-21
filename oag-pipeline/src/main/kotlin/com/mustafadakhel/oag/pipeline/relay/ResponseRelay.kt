package com.mustafadakhel.oag.pipeline.relay
import com.mustafadakhel.oag.pipeline.NetworkConfig
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.audit.AuditRedirectHop
import com.mustafadakhel.oag.audit.AuditResponseRewrite
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyResponseRewrite
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.core.ResponseRewriteAction
import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.enforcement.TokenUsage
import com.mustafadakhel.oag.enforcement.TokenUsageExtractor
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.ResponseTextBody
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.pipeline.inspection.resolveResponseDataClassification
import com.mustafadakhel.oag.pipeline.inspection.scanStreamingResponseBody
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.DEFAULT_RESPONSE_SCAN_LIMIT
import com.mustafadakhel.oag.pipeline.HTTP_TOKEN_REGEX
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.MAX_RESPONSE_HEADER_LINES
import com.mustafadakhel.oag.pipeline.RESPONSE_HOP_BY_HOP_HEADERS
import com.mustafadakhel.oag.pipeline.SINGLETON_FRAMING_HEADERS
import com.mustafadakhel.oag.pipeline.SSE_CONTENT_TYPE
import com.mustafadakhel.oag.pipeline.hasFinalChunkedEncoding
import com.mustafadakhel.oag.pipeline.hasInvalidHeaderValueChars
import com.mustafadakhel.oag.pipeline.inspection.ResponseRelayResult
import com.mustafadakhel.oag.pipeline.inspection.StreamingScanner
import com.mustafadakhel.oag.pipeline.inspection.resolveStreamingScanEnabled
import com.mustafadakhel.oag.pipeline.phase.RedirectValidationResult
import com.mustafadakhel.oag.pipeline.phase.parseStatusCode
import com.mustafadakhel.oag.pipeline.phase.responseHasBody
import com.mustafadakhel.oag.pipeline.phase.validateRedirect
import com.mustafadakhel.oag.pipeline.readLine
import com.mustafadakhel.oag.pipeline.writeDenied

import java.io.InputStream
import java.io.OutputStream
import java.util.Locale

internal class ResponseInspectionPlan(
    val redact: Boolean,
    val bodyMatch: PolicyBodyMatch?,
    val pluginScan: Boolean,
    val dataClassification: PolicyDataClassification?
)

data class HttpHeader(val name: String, val value: String)

private fun List<HttpHeader>.headerValue(name: String): String? =
    firstOrNull { it.name.equals(name, ignoreCase = true) }?.value

private fun List<HttpHeader>.hasConnectionClose(): Boolean =
    any {
        it.name.equals(HttpConstants.CONNECTION, ignoreCase = true) &&
            it.value.equals(HttpConstants.CONNECTION_CLOSE, ignoreCase = true)
    }

class ResponseRelayer(
    private val policyService: PolicyService,
    private val hostResolver: HostResolver,
    private val networkConfig: NetworkConfig,
    private val dryRun: Boolean = false,
    private val detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    private val onError: (String) -> Unit = defaultRelayErrorHandler
) {
    suspend fun relay(
        upstreamIn: InputStream,
        clientOutput: OutputStream,
        request: HttpRequest,
        requestTarget: ParsedTarget,
        matchedRule: PolicyRule?,
        responseRewriteAuditCollector: MutableList<AuditResponseRewrite>? = null,
        preReadStatusLine: String? = null
    ): ResponseRelayResult {
        val parsed = parseUpstreamResponse(upstreamIn, preReadStatusLine)

        val redirectResult = evaluateRedirect(parsed.headers, requestTarget, request.method, parsed.statusCode)
        val redirectDenial = redirectResult.denied
        if (redirectDenial != null) {
            writeDenied(clientOutput)
            return ResponseRelayResult(
                bytesIn = 0,
                statusCode = redirectDenial.statusCode,
                decisionOverride = redirectDenial.decision,
                redirectChain = redirectResult.redirectChain
            )
        }

        val state = buildRelayState(
            parsed = parsed,
            upstreamIn = upstreamIn,
            clientOutput = clientOutput,
            matchedRule = matchedRule,
            redirectChain = redirectResult.redirectChain,
            responseRewriteAuditCollector = responseRewriteAuditCollector
        )

        return dispatchRelay(state, request, responseRewriteAuditCollector)
    }

    private suspend fun evaluateRedirect(
        headers: List<HttpHeader>,
        requestTarget: ParsedTarget,
        method: String,
        statusCode: Int
    ): RedirectValidationResult = if (networkConfig.enforceRedirectPolicy) {
        val location = headers.headerValue(HttpConstants.LOCATION)
        validateRedirect(
            statusCode = statusCode,
            location = location,
            requestTarget = requestTarget,
            requestMethod = method,
            policyService = policyService,
            blockIpLiterals = networkConfig.blockIpLiterals,
            blockPrivateResolvedIps = networkConfig.blockPrivateResolvedIps,
            hostResolver = hostResolver
        )
    } else {
        RedirectValidationResult(emptyList())
    }

    private data class ParsedResponse(
        val statusLine: String,
        val statusCode: Int,
        val headers: List<HttpHeader>
    )

    private fun parseUpstreamResponse(
        upstreamIn: InputStream,
        preReadStatusLine: String?
    ): ParsedResponse {
        val statusLine = preReadStatusLine ?: requireNotNull(readLine(upstreamIn)) { "Missing upstream status line" }
        return ParsedResponse(
            statusLine = statusLine,
            statusCode = parseStatusCode(statusLine),
            headers = parseResponseHeaders(upstreamIn)
        )
    }

    private fun buildRelayState(
        parsed: ParsedResponse,
        upstreamIn: InputStream,
        clientOutput: OutputStream,
        matchedRule: PolicyRule?,
        redirectChain: List<AuditRedirectHop>,
        responseRewriteAuditCollector: MutableList<AuditResponseRewrite>?
    ): RelayState {
        val framing = parseFraming(parsed.headers)
        val forwardedHeaders = applyResponseHeaderRewrites(
            parsed.headers.filter { (name, _) -> name.lowercase(Locale.ROOT) !in RESPONSE_HOP_BY_HOP_HEADERS },
            matchedRule?.responseRewrites, responseRewriteAuditCollector
        )
        val responseMatch = if (matchedRule?.skipResponseScanning == true) null else matchedRule?.responseBodyMatch
        return RelayState(
            upstreamIn = upstreamIn,
            clientOutput = clientOutput,
            statusLine = parsed.statusLine,
            statusCode = parsed.statusCode,
            headers = parsed.headers,
            forwardedHeaders = forwardedHeaders,
            framing = framing,
            matchedRule = matchedRule,
            responseMatch = responseMatch,
            redirectChain = redirectChain
        )
    }

    private fun dispatchRelay(
        state: RelayState,
        request: HttpRequest,
        responseRewriteAuditCollector: MutableList<AuditResponseRewrite>?
    ): ResponseRelayResult {
        val plan = buildInspectionPlan(state)
        if (plan != null && isBufferable(state)) {
            return relayBuffered(state, plan, responseRewriteAuditCollector)
        }
        return relayStreaming(state, request)
    }

    private fun buildInspectionPlan(state: RelayState): ResponseInspectionPlan? {
        val defaults = policyService.current.defaults
        val hasBodyRedact = state.matchedRule?.responseRewrites?.any { it is PolicyResponseRewrite.Redact } == true
        val pluginScanResponses = (state.matchedRule?.pluginDetection ?: defaults?.pluginDetection)?.scanResponses == true
        val hasResponsePlugins = pluginScanResponses && detectorRegistry.registrationsFor(ResponseTextBody::class.java).isNotEmpty()
        val responseDataClass = resolveResponseDataClassification(state.matchedRule, defaults)
        if (!hasBodyRedact && state.responseMatch == null && !hasResponsePlugins && responseDataClass == null) return null
        return ResponseInspectionPlan(
            redact = hasBodyRedact,
            bodyMatch = state.responseMatch,
            pluginScan = hasResponsePlugins,
            dataClassification = responseDataClass
        )
    }

    private fun isBufferable(state: RelayState): Boolean {
        val defaults = policyService.current.defaults
        val scanLimit = defaults?.maxResponseScanBytes ?: DEFAULT_RESPONSE_SCAN_LIMIT
        return state.framing.contentLength != null &&
            state.framing.contentLength in 1..scanLimit &&
            state.framing.transferEncoding == null
    }

    private fun relayBuffered(
        state: RelayState,
        plan: ResponseInspectionPlan,
        responseRewriteAuditCollector: MutableList<AuditResponseRewrite>?
    ): ResponseRelayResult {
        val contentLength = requireNotNull(state.framing.contentLength)
        val bodyBytes = readFullBody(state.upstreamIn, contentLength)
        val bodyText = bodyBytes.toString(Charsets.UTF_8)

        val contentType = state.headers.firstOrNull { it.name.equals(HttpConstants.CONTENT_TYPE, ignoreCase = true) }?.value
        val context = BufferedInspectionContext(
            statusCode = state.statusCode,
            contentType = contentType,
            matchedRule = state.matchedRule,
            onError = onError
        )
        val chain = buildInspectionChain(plan, state.matchedRule, detectorRegistry)
        val outcome = chain.run(bodyText, context)
        val acc = context.accumulator
        responseRewriteAuditCollector?.addAll(acc.auditEntries)

        return when (outcome) {
            is StepOutcome.Deny -> {
                if (dryRun) {
                    var bytes = writeResponseHead(state.clientOutput, state.statusLine, state.forwardedHeaders)
                    state.clientOutput.write(bodyBytes)
                    state.clientOutput.flush()
                    bytes += bodyBytes.size
                    ResponseRelayResult(
                        bytesIn = bytes,
                        statusCode = state.statusCode,
                        decisionOverride = outcome.decision,
                        redirectChain = state.redirectChain,
                        redactionActions = acc.redactionActions,
                        connectionReusable = !state.headers.hasConnectionClose(),
                        responsePluginFindings = acc.pluginFindings,
                        responseDataClassification = acc.dataClassification
                    )
                } else {
                    writeDenied(state.clientOutput)
                    ResponseRelayResult(
                        bytesIn = 0,
                        statusCode = HttpStatus.FORBIDDEN.code,
                        decisionOverride = outcome.decision,
                        redirectChain = state.redirectChain,
                        redactionActions = acc.redactionActions
                    )
                }
            }
            is StepOutcome.Continue -> {
                val anyRedaction = acc.redactionActions.isNotEmpty()
                val modifiedBodyBytes = if (anyRedaction) outcome.bodyText.toByteArray(Charsets.UTF_8) else bodyBytes
                val updatedHeaders = if (anyRedaction) {
                    state.forwardedHeaders.map { (name, value) ->
                        if (name.equals(HttpConstants.CONTENT_LENGTH, ignoreCase = true)) HttpHeader(name, modifiedBodyBytes.size.toString())
                        else HttpHeader(name, value)
                    }
                } else state.forwardedHeaders

                var bytes = writeResponseHead(state.clientOutput, state.statusLine, updatedHeaders)
                state.clientOutput.write(modifiedBodyBytes)
                state.clientOutput.flush()
                bytes += modifiedBodyBytes.size

                ResponseRelayResult(
                    bytesIn = bytes,
                    statusCode = state.statusCode,
                    redirectChain = state.redirectChain,
                    redactionActions = acc.redactionActions,
                    connectionReusable = !state.headers.hasConnectionClose(),
                    tokenUsage = TokenUsageExtractor.extract(outcome.bodyText),
                    responsePluginFindings = acc.pluginFindings,
                    responseDataClassification = acc.dataClassification
                )
            }
        }
    }

    private data class ResponseFraming(val transferEncoding: String?, val contentLength: Long?)

    private class RelayState(
        val upstreamIn: InputStream,
        val clientOutput: OutputStream,
        val statusLine: String,
        val statusCode: Int,
        val headers: List<HttpHeader>,
        val forwardedHeaders: List<HttpHeader>,
        val framing: ResponseFraming,
        val matchedRule: PolicyRule?,
        val responseMatch: PolicyBodyMatch?,
        val redirectChain: List<AuditRedirectHop>
    )

    private fun parseFraming(headers: List<HttpHeader>): ResponseFraming {
        val transferEncoding = headers.headerValue(HttpConstants.TRANSFER_ENCODING)
        val contentLengthHeader = headers.headerValue(HttpConstants.CONTENT_LENGTH)
        val contentLength = contentLengthHeader?.toLongOrNull()
        if (transferEncoding != null) {
            require(transferEncoding.hasFinalChunkedEncoding()) { "Unsupported response transfer-encoding" }
        }
        if (contentLengthHeader != null) {
            require(contentLength != null && contentLength >= 0) { "Invalid response content-length" }
        }
        return ResponseFraming(transferEncoding, contentLength)
    }

    /**
     * A connection is reusable when the response has a well-defined framing mechanism
     * (Content-Length or Transfer-Encoding: chunked) so the proxy knows exactly where
     * the response ends, the server hasn't sent Connection: close, and the response
     * was fully relayed without truncation or policy-level override.
     */
    private fun isConnectionReusable(
        framing: ResponseFraming,
        headers: List<HttpHeader>,
        truncationAction: EnforcementAction.Truncate?,
        decisionOverride: PolicyDecision?
    ): Boolean {
        val hasDefinedFraming = framing.contentLength != null || framing.transferEncoding != null
        return hasDefinedFraming && !headers.hasConnectionClose() && truncationAction == null && decisionOverride == null
    }


    private data class StreamingRelayOutcome(
        val bytesRelayed: Long,
        val matchedPatterns: List<String> = emptyList(),
        val truncationAction: EnforcementAction.Truncate? = null,
        val tokenUsage: TokenUsage? = null,
        val accumulatedBody: String? = null,
        val truncated: Boolean = false
    )

    private fun relayStreaming(state: RelayState, request: HttpRequest): ResponseRelayResult {
        val headerBytes = writeResponseHead(state.clientOutput, state.statusLine, state.forwardedHeaders)
        val bodyOutcome = relayStreamingBody(state, request)
        val bytes = headerBytes + bodyOutcome.bytesRelayed

        val streamingDecisionOverride = bodyOutcome.matchedPatterns.takeIf { it.isNotEmpty() }?.let {
            PolicyDecision(action = PolicyAction.DENY, ruleId = state.matchedRule?.id, reasonCode = ReasonCode.RESPONSE_INJECTION_DETECTED)
        }
        val reusable = isConnectionReusable(state.framing, state.headers, bodyOutcome.truncationAction, streamingDecisionOverride)

        val accumulatedText = bodyOutcome.accumulatedBody

        val streamingPlugins = accumulatedText?.takeIf { hasStreamingResponsePlugins() }?.let { text ->
            val contentType = state.headers.headerValue(HttpConstants.CONTENT_TYPE)
            val inspectionContext = InspectionContext(
                host = state.matchedRule?.host,
                ruleId = state.matchedRule?.id
            )
            scanStreamingResponseBody(text, state.statusCode, contentType, bodyOutcome.truncated, detectorRegistry, inspectionContext, onError)
        }

        val streamingDataClass = accumulatedText?.let { text ->
            val defaults = policyService.current.defaults
            resolveResponseDataClassification(state.matchedRule, defaults)?.let { config ->
                runResponseDataClassification(text, config, onError)
            }
        }

        return ResponseRelayResult(
            bytesIn = bytes,
            statusCode = state.statusCode,
            decisionOverride = streamingDecisionOverride,
            redirectChain = state.redirectChain,
            streamingMatchedPatterns = bodyOutcome.matchedPatterns,
            truncationAction = bodyOutcome.truncationAction,
            connectionReusable = reusable,
            tokenUsage = bodyOutcome.tokenUsage,
            streamingPluginFindings = streamingPlugins,
            responseDataClassification = streamingDataClass
        )
    }

    private fun relayStreamingBody(
        state: RelayState,
        request: HttpRequest
    ): StreamingRelayOutcome {
        if (!responseHasBody(state.statusCode, request.method)) {
            state.clientOutput.flush()
            return StreamingRelayOutcome(bytesRelayed = 0L)
        }
        if (state.framing.transferEncoding != null) {
            val scanner = resolveStreamingScanner(state)
            val scanResult = relayChunkedResponse(
                upstreamIn = state.upstreamIn,
                clientOutput = state.clientOutput,
                scanner = scanner,
                enforcementMode = !dryRun,
                policyService = policyService,
                onError = onError
            )
            return StreamingRelayOutcome(
                bytesRelayed = scanResult.bytesRelayed,
                matchedPatterns = scanResult.matchedPatterns,
                truncationAction = if (scanResult.truncated) EnforcementAction.Truncate(maxLength = scanResult.bytesRelayed.toInt()) else null,
                tokenUsage = scanResult.accumulatedBody?.let { TokenUsageExtractor.extract(it) },
                accumulatedBody = scanResult.accumulatedBody,
                truncated = scanResult.truncated
            )
        }
        if (state.framing.contentLength != null && state.framing.contentLength >= 0) {
            return StreamingRelayOutcome(
                bytesRelayed = relayFixedLengthResponse(state.upstreamIn, state.clientOutput, state.framing.contentLength, onError)
            )
        }
        return StreamingRelayOutcome(
            bytesRelayed = relayResponse(state.upstreamIn, state.clientOutput)
        )
    }

    private fun resolveStreamingScanner(state: RelayState): StreamingScanner? {
        val defaults = policyService.current.defaults
        val hasStreamingPlugins = hasStreamingResponsePlugins()
        val hasStreamingDataClass = resolveResponseDataClassification(state.matchedRule, defaults) != null
        val needsAccumulation = hasStreamingPlugins || hasStreamingDataClass
        val responseMatch = state.responseMatch
        if (responseMatch == null && !needsAccumulation) return null
        val contentType = state.headers.headerValue(HttpConstants.CONTENT_TYPE)?.lowercase(Locale.ROOT)
        val isSSE = contentType?.contains(SSE_CONTENT_TYPE) == true
        val enabled = resolveStreamingScanEnabled(state.matchedRule, defaults)
        if (!enabled && !needsAccumulation) return null
        if (!isSSE && state.framing.transferEncoding == null) return null
        val scanner = responseMatch?.let { buildStreamingScanner(it, onError) }
        return scanner?.copy(accumulateForPlugins = needsAccumulation)
            ?: StreamingScanner(automaton = null, regexPatterns = emptyList(), accumulateForPlugins = true)
    }

    private fun hasStreamingResponsePlugins(): Boolean {
        val pluginScanEnabled = (policyService.current.defaults?.pluginDetection)?.scanResponses == true
        return pluginScanEnabled && detectorRegistry.registrationsFor(
            com.mustafadakhel.oag.inspection.StreamingResponseBody::class.java
        ).isNotEmpty()
    }

}

private fun parseResponseHeaders(upstreamIn: InputStream): List<HttpHeader> {
    val headerCounts = mutableMapOf<String, Int>()
    var headerLineCount = 0
    return buildList {
        while (true) {
            val line = readLine(upstreamIn) ?: break
            if (line.isEmpty()) break
            require(!line.first().isWhitespace()) { "Invalid response header line" }
            headerLineCount += 1
            require(headerLineCount <= MAX_RESPONSE_HEADER_LINES) { "Too many response headers" }
            val idx = line.indexOf(':')
            require(idx > 0) { "Invalid response header line" }
            val name = line.substring(0, idx).trim()
            require(name.isNotBlank()) { "Invalid response header name" }
            require(name.matches(HTTP_TOKEN_REGEX)) { "Invalid response header name token" }
            val key = name.lowercase(Locale.ROOT)
            val count = (headerCounts[key] ?: 0) + 1
            headerCounts[key] = count
            require(key !in SINGLETON_FRAMING_HEADERS || count <= 1) { "Duplicate response framing header: $key" }
            val value = line.substring(idx + 1).trim()
            require(!value.hasInvalidHeaderValueChars()) { "Invalid response header value" }
            add(HttpHeader(name, value))
        }
        require(!headerCounts.containsKey(HttpConstants.CONTENT_LENGTH) || !headerCounts.containsKey(HttpConstants.TRANSFER_ENCODING)) {
            "Conflicting response framing headers"
        }
    }
}

private fun applyResponseHeaderRewrites(
    headers: List<HttpHeader>,
    responseRewrites: List<PolicyResponseRewrite>?,
    auditCollector: MutableList<AuditResponseRewrite>?
): List<HttpHeader> {
    if (responseRewrites.isNullOrEmpty()) return headers
    val mutableHeaders = headers.toMutableList()
    for (rw in responseRewrites) {
        when (rw) {
            is PolicyResponseRewrite.RemoveHeader -> {
                val before = mutableHeaders.size
                mutableHeaders.removeAll { it.name.equals(rw.header, ignoreCase = true) }
                if (mutableHeaders.size < before) {
                    auditCollector?.add(AuditResponseRewrite(
                        action = ResponseRewriteAction.REMOVE_HEADER.label(),
                        header = rw.header
                    ))
                }
            }
            is PolicyResponseRewrite.SetHeader -> {
                mutableHeaders.removeAll { it.name.equals(rw.header, ignoreCase = true) }
                mutableHeaders += HttpHeader(rw.header, rw.value)
                auditCollector?.add(AuditResponseRewrite(
                    action = ResponseRewriteAction.SET_HEADER.label(),
                    header = rw.header
                ))
            }
            is PolicyResponseRewrite.Redact -> {} // handled during body processing
        }
    }
    return mutableHeaders
}

private fun writeResponseHead(
    clientOutput: OutputStream,
    statusLine: String,
    headers: List<HttpHeader>
): Long {
    var bytes = 0L
    val statusBytes = "$statusLine${HttpConstants.CRLF}".toByteArray(Charsets.US_ASCII)
    clientOutput.write(statusBytes)
    bytes += statusBytes.size
    headers.forEach { (name, value) ->
        val headerBytes = "$name${HttpConstants.HEADER_SEPARATOR}$value${HttpConstants.CRLF}".toByteArray(Charsets.US_ASCII)
        clientOutput.write(headerBytes)
        bytes += headerBytes.size
    }
    clientOutput.write(HttpConstants.CRLF.toByteArray(Charsets.US_ASCII))
    bytes += HttpConstants.CRLF.length
    return bytes
}

private fun readFullBody(upstreamIn: InputStream, contentLength: Long): ByteArray {
    require(contentLength <= Int.MAX_VALUE) { "Response body too large for buffered read: $contentLength bytes" }
    val buffer = ByteArray(contentLength.toInt())
    var offset = 0
    while (offset < buffer.size) {
        val read = upstreamIn.read(buffer, offset, buffer.size - offset)
        if (read == -1) break
        offset += read
    }
    if (offset.toLong() != contentLength) {
        throw java.io.IOException("Truncated response body: expected $contentLength bytes, got $offset")
    }
    return buffer
}
