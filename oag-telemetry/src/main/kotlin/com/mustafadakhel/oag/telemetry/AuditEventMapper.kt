package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.audit.AuditAdminAccessEvent
import com.mustafadakhel.oag.audit.AuditCircuitBreakerEvent
import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditEventType
import com.mustafadakhel.oag.audit.AuditIntegrityCheckEvent
import com.mustafadakhel.oag.audit.AuditPolicyFetchEvent
import com.mustafadakhel.oag.audit.AuditPolicyReloadEvent
import com.mustafadakhel.oag.audit.AuditStartupEvent
import com.mustafadakhel.oag.audit.AuditToolEvent
import com.mustafadakhel.oag.audit.AuditTrace
import com.mustafadakhel.oag.label

import io.opentelemetry.api.common.AttributeKey
import io.opentelemetry.api.common.Attributes
import io.opentelemetry.api.common.AttributesBuilder
import io.opentelemetry.api.trace.Span
import io.opentelemetry.api.trace.SpanContext
import io.opentelemetry.api.trace.TraceFlags
import io.opentelemetry.api.trace.TraceState
import io.opentelemetry.context.Context

internal fun attributesForEvent(event: AuditEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.REQUEST.label())
        .put(OagAttributes.POLICY_HASH, event.policyHash)
        .put(OagAttributes.DECISION_ACTION, event.decision.action)
        .put(OagAttributes.DECISION_REASON_CODE, event.decision.reasonCode)
        .put(OagAttributes.SECRETS_INJECTION_ATTEMPTED, event.secrets.injectionAttempted)
        .put(OagAttributes.SECRETS_INJECTED, event.secrets.injected)
        .put(OagAttributes.HTTP_REQUEST_METHOD, event.request.method)
        .put(OagAttributes.URL_SCHEME, event.request.scheme)
        .put(OagAttributes.SERVER_ADDRESS, event.request.host)
        .put(OagAttributes.SERVER_PORT, event.request.port.toLong())
        .put(OagAttributes.URL_PATH, event.request.path)

    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)
    builder.putIfNotNull(OagAttributes.DECISION_RULE_ID, event.decision.ruleId)
    builder.putLongIfNotNull(OagAttributes.HTTP_RESPONSE_STATUS_CODE, event.response?.status)
    builder.putIfNotNull(OagAttributes.RESPONSE_BYTES_IN, event.response?.bytesIn)
    builder.put(OagAttributes.REQUEST_BYTES_OUT, event.request.bytesOut)

    if (event.request.resolvedIps.isNotEmpty()) {
        builder.put(OagAttributes.REQUEST_RESOLVED_IPS, event.request.resolvedIps)
    }
    if (event.secrets.secretIds.isNotEmpty()) {
        builder.put(OagAttributes.SECRETS_IDS, event.secrets.secretIds)
    }
    if (event.secrets.secretVersions.isNotEmpty()) {
        val versions = event.secrets.secretVersions.map { (id, version) -> "$id=$version" }
        builder.put(OagAttributes.SECRETS_VERSIONS, versions)
    }
    if (event.redirectChain.isNotEmpty()) {
        builder.put(OagAttributes.REDIRECT_COUNT, event.redirectChain.size.toLong())
        builder.put(OagAttributes.REDIRECT_LOCATIONS, event.redirectChain.map { it.location })
    }
    if (event.errors.isNotEmpty()) {
        val errors = event.errors.map { "${it.code}:${it.message}" }
        builder.put(OagAttributes.ERRORS, errors)
    }

    event.dryRunOverride?.let { builder.put(OagAttributes.DRY_RUN_OVERRIDE, it) }

    event.tokenUsage?.let { tu ->
        tu.promptTokens?.let { builder.put(OagAttributes.TOKEN_PROMPT_TOKENS, it) }
        tu.completionTokens?.let { builder.put(OagAttributes.TOKEN_COMPLETION_TOKENS, it) }
        builder.put(OagAttributes.TOKEN_TOTAL_TOKENS, tu.totalTokens)
    }

    event.phaseTimings?.let { timings ->
        PHASE_TIMING_ATTRIBUTES.forEach { (key, attr) ->
            timings[key]?.let { builder.put(attr, it) }
        }
    }

    return builder.build()
}

internal fun attributesForTool(event: AuditToolEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.TOOL.label())
        .put(OagAttributes.TOOL_NAME, event.tool.name)

    builder.putIfNotNull(OagAttributes.POLICY_HASH, event.policyHash)
    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)
    if (event.tool.parameterKeys.isNotEmpty()) {
        builder.put(OagAttributes.TOOL_PARAMETER_KEYS, event.tool.parameterKeys)
    }
    builder.putIfNotNull(OagAttributes.TOOL_RESPONSE_BYTES, event.tool.responseBytes)
    builder.putIfNotNull(OagAttributes.TOOL_DURATION_MS, event.tool.durationMs)
    builder.putIfNotNull(OagAttributes.TOOL_ERROR_CODE, event.tool.errorCode)

    return builder.build()
}

internal fun attributesForStartup(event: AuditStartupEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.STARTUP.label())
        .put(OagAttributes.POLICY_HASH, event.policyHash)
        .put(OagAttributes.CONFIG_POLICY_PATH, event.config.policyPath)
        .put(OagAttributes.CONFIG_POLICY_REQUIRE_SIGNATURE, event.config.policyRequireSignature)
        .put(OagAttributes.CONFIG_LISTEN_HOST, event.config.listenHost)
        .put(OagAttributes.CONFIG_LISTEN_PORT, event.config.listenPort.toLong())
        .put(OagAttributes.CONFIG_MAX_THREADS, event.config.maxThreads.toLong())
        .put(OagAttributes.CONFIG_SECRET_ENV_PREFIX, event.config.secretEnvPrefix)
        .put(OagAttributes.CONFIG_SECRET_PROVIDER, event.config.secretProvider)
        .put(OagAttributes.CONFIG_DRY_RUN, event.config.dryRun)
        .put(OagAttributes.CONFIG_BLOCK_IP_LITERALS, event.config.blockIpLiterals)
        .put(OagAttributes.CONFIG_ENFORCE_REDIRECT_POLICY, event.config.enforceRedirectPolicy)
        .put(OagAttributes.CONFIG_BLOCK_PRIVATE_RESOLVED_IPS, event.config.blockPrivateResolvedIps)
        .put(OagAttributes.CONFIG_CONNECT_TIMEOUT_MS, event.config.connectTimeoutMs.toLong())
        .put(OagAttributes.CONFIG_READ_TIMEOUT_MS, event.config.readTimeoutMs.toLong())

    builder.putIfNotNull(OagAttributes.CONFIG_POLICY_PUBLIC_KEY_PATH, event.config.policyPublicKeyPath)
    builder.putIfNotNull(OagAttributes.CONFIG_LOG_PATH, event.config.logPath)
    builder.putIfNotNull(OagAttributes.CONFIG_SECRET_FILE_DIR, event.config.secretFileDir)
    builder.putIfNotNull(OagAttributes.CONFIG_OTEL_EXPORTER, event.config.otelExporter)
    builder.putIfNotNull(OagAttributes.CONFIG_OTEL_ENDPOINT, event.config.otelEndpoint)
    if (event.config.otelHeadersKeys.isNotEmpty()) {
        builder.put(OagAttributes.CONFIG_OTEL_HEADERS_KEYS, event.config.otelHeadersKeys)
    }
    builder.putLongIfNotNull(OagAttributes.CONFIG_OTEL_TIMEOUT_MS, event.config.otelTimeoutMs)
    builder.putIfNotNull(OagAttributes.CONFIG_OTEL_SERVICE_NAME, event.config.otelServiceName)
    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun attributesForPolicyReload(event: AuditPolicyReloadEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.POLICY_RELOAD.label())
        .put(OagAttributes.POLICY_RELOAD_PREVIOUS_HASH, event.previousPolicyHash)
        .put(OagAttributes.POLICY_RELOAD_CHANGED, event.changed)
        .put(OagAttributes.POLICY_RELOAD_SUCCESS, event.success)

    builder.putIfNotNull(OagAttributes.POLICY_RELOAD_NEW_HASH, event.newPolicyHash)
    builder.putIfNotNull(OagAttributes.POLICY_RELOAD_ERROR_MESSAGE, event.errorMessage)
    builder.putIfNotNull(OagAttributes.POLICY_RELOAD_TRIGGER, event.trigger)
    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun attributesForCircuitBreaker(event: AuditCircuitBreakerEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.CIRCUIT_BREAKER.label())
        .put(OagAttributes.CIRCUIT_BREAKER_HOST, event.host)
        .put(OagAttributes.CIRCUIT_BREAKER_PREVIOUS_STATE, event.previousState)
        .put(OagAttributes.CIRCUIT_BREAKER_NEW_STATE, event.newState)

    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun attributesForPolicyFetch(event: AuditPolicyFetchEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.POLICY_FETCH.label())
        .put(OagAttributes.POLICY_FETCH_SOURCE_URL, event.sourceUrl)
        .put(OagAttributes.POLICY_FETCH_SUCCESS, event.success)
        .put(OagAttributes.POLICY_FETCH_CHANGED, event.changed)

    builder.putIfNotNull(OagAttributes.POLICY_FETCH_CONTENT_HASH, event.contentHash)
    builder.putIfNotNull(OagAttributes.POLICY_FETCH_ERROR_MESSAGE, event.errorMessage)
    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun attributesForAdminAccess(event: AuditAdminAccessEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.ADMIN_ACCESS.label())
        .put(OagAttributes.ADMIN_ENDPOINT, event.endpoint)
        .put(OagAttributes.ADMIN_SOURCE_IP, event.sourceIp)
        .put(OagAttributes.ADMIN_ALLOWED, event.allowed)

    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun attributesForIntegrityCheck(event: AuditIntegrityCheckEvent): Attributes {
    val builder = Attributes.builder()
        .put(OagAttributes.EVENT_TYPE, AuditEventType.INTEGRITY_CHECK.label())
        .put(OagAttributes.INTEGRITY_STATUS, event.status)
        .put(OagAttributes.INTEGRITY_POLICY_HASH_MATCH, event.policyHashMatch)
        .put(OagAttributes.INTEGRITY_CONFIG_FINGERPRINT_MATCH, event.configFingerprintMatch)

    builder.putIfNotNull(OagAttributes.AGENT_ID, event.agentId)
    builder.putIfNotNull(OagAttributes.SESSION_ID, event.sessionId)

    return builder.build()
}

internal fun contextForTrace(trace: AuditTrace): Context {
    val flags = trace.traceFlags?.let { parseTraceFlagsHex(it) } ?: TraceFlags.getDefault()
    val spanContext = SpanContext.createFromRemoteParent(
        trace.traceId,
        trace.spanId,
        flags,
        TraceState.getDefault()
    )
    return Context.root().with(Span.wrap(spanContext))
}

private fun <T : Any> AttributesBuilder.putIfNotNull(key: AttributeKey<T>, value: T?) {
    value?.let { put(key, it) }
}

private fun AttributesBuilder.putLongIfNotNull(key: AttributeKey<Long>, value: Int?) {
    value?.let { put(key, it.toLong()) }
}

private val PHASE_TIMING_ATTRIBUTES: Map<String, AttributeKey<Double>> = mapOf(
    PhaseTimings.AUDIT_POLICY_EVALUATION_MS to OagAttributes.PHASE_POLICY_EVALUATION_MS,
    PhaseTimings.AUDIT_DNS_RESOLUTION_MS to OagAttributes.PHASE_DNS_RESOLUTION_MS,
    PhaseTimings.AUDIT_UPSTREAM_CONNECT_MS to OagAttributes.PHASE_UPSTREAM_CONNECT_MS,
    PhaseTimings.AUDIT_REQUEST_RELAY_MS to OagAttributes.PHASE_REQUEST_RELAY_MS,
    PhaseTimings.AUDIT_RESPONSE_RELAY_MS to OagAttributes.PHASE_RESPONSE_RELAY_MS,
    PhaseTimings.AUDIT_SECRET_MATERIALIZATION_MS to OagAttributes.PHASE_SECRET_MATERIALIZATION_MS,
    PhaseTimings.AUDIT_TOTAL_MS to OagAttributes.PHASE_TOTAL_MS
)

