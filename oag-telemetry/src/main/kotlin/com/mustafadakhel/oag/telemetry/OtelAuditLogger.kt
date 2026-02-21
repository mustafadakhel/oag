package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.audit.AuditAdminAccessEvent
import com.mustafadakhel.oag.audit.AuditCircuitBreakerEvent
import com.mustafadakhel.oag.audit.AuditEvent
import com.mustafadakhel.oag.audit.AuditExternalSink
import com.mustafadakhel.oag.audit.AuditIntegrityCheckEvent
import com.mustafadakhel.oag.audit.AuditLogEvent
import com.mustafadakhel.oag.audit.AuditPolicyFetchEvent
import com.mustafadakhel.oag.audit.AuditPolicyReloadEvent
import com.mustafadakhel.oag.audit.AuditStartupEvent
import com.mustafadakhel.oag.audit.AuditToolEvent

import io.opentelemetry.api.logs.Severity
import io.opentelemetry.exporter.logging.SystemOutLogRecordExporter
import io.opentelemetry.exporter.otlp.http.logs.OtlpHttpLogRecordExporter
import io.opentelemetry.exporter.otlp.logs.OtlpGrpcLogRecordExporter
import io.opentelemetry.sdk.OpenTelemetrySdk
import io.opentelemetry.sdk.logs.SdkLoggerProvider
import io.opentelemetry.sdk.logs.export.BatchLogRecordProcessor
import io.opentelemetry.sdk.resources.Resource

import java.time.Duration

class OtelAuditLogger(
    private val config: OtelConfig,
    private val oagVersion: String,
    providerOverride: SdkLoggerProvider? = null
) : AuditExternalSink {
    init {
        require(providerOverride != null || config.exporter != OtelExporterType.NONE) {
            "OtelAuditLogger must not be constructed with NONE exporter"
        }
    }

    private val resource: Resource? = if (providerOverride != null) null else buildResource()
    private val loggerProvider: SdkLoggerProvider = providerOverride ?: buildLogProvider(requireNotNull(resource))
    private val sdk: OpenTelemetrySdk? = if (providerOverride != null) null else OpenTelemetrySdk.builder()
        .setLoggerProvider(loggerProvider)
        .build()
    private val logger = (sdk?.logsBridge ?: loggerProvider)
        .loggerBuilder(OagAttributes.LOGGER_SCOPE)
        .setInstrumentationVersion(oagVersion)
        .build()

    override fun log(event: AuditLogEvent) {
        when (event) {
            is AuditEvent -> {
                val builder = logger.logRecordBuilder()
                    .setSeverity(Severity.INFO)
                    .setBody(OagAttributes.BODY_REQUEST)
                    .setAllAttributes(attributesForEvent(event))
                event.trace?.let { builder.setContext(contextForTrace(it)) }
                builder.emit()
            }
            is AuditToolEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setBody(OagAttributes.BODY_TOOL)
                .setAllAttributes(attributesForTool(event))
                .emit()
            is AuditStartupEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setBody(OagAttributes.BODY_STARTUP)
                .setAllAttributes(attributesForStartup(event))
                .emit()
            is AuditPolicyReloadEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setBody(OagAttributes.BODY_POLICY_RELOAD)
                .setAllAttributes(attributesForPolicyReload(event))
                .emit()
            is AuditCircuitBreakerEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.WARN)
                .setBody(OagAttributes.BODY_CIRCUIT_BREAKER)
                .setAllAttributes(attributesForCircuitBreaker(event))
                .emit()
            is AuditPolicyFetchEvent -> {
                val severity = if (event.success) Severity.INFO else Severity.WARN
                logger.logRecordBuilder()
                    .setSeverity(severity)
                    .setBody(OagAttributes.BODY_POLICY_FETCH)
                    .setAllAttributes(attributesForPolicyFetch(event))
                    .emit()
            }
            is AuditAdminAccessEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setBody(OagAttributes.BODY_ADMIN_ACCESS)
                .setAllAttributes(attributesForAdminAccess(event))
                .emit()
            is AuditIntegrityCheckEvent -> logger.logRecordBuilder()
                .setSeverity(Severity.INFO)
                .setBody(OagAttributes.BODY_INTEGRITY_CHECK)
                .setAllAttributes(attributesForIntegrityCheck(event))
                .emit()
        }
    }

    override fun close() {
        sdk?.close() ?: loggerProvider.shutdown()
    }

    private fun buildLogProvider(resource: Resource): SdkLoggerProvider {
        val exporter = when (config.exporter) {
            OtelExporterType.NONE -> error("OtelAuditLogger should not be instantiated with NONE exporter")
            OtelExporterType.STDOUT -> SystemOutLogRecordExporter.create()
            OtelExporterType.OTLP_HTTP -> OtlpHttpLogRecordExporter.builder()
                .setEndpoint(requireNotNull(config.endpoint))
                .apply { config.headers.forEach { (key, value) -> addHeader(key, value) } }
                .setTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
                .build()
            OtelExporterType.OTLP_GRPC -> OtlpGrpcLogRecordExporter.builder()
                .setEndpoint(requireNotNull(config.endpoint))
                .apply { config.headers.forEach { (key, value) -> addHeader(key, value) } }
                .setTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
                .build()
        }

        return SdkLoggerProvider.builder()
            .setResource(resource)
            .addLogRecordProcessor(BatchLogRecordProcessor.builder(exporter).build())
            .build()
    }

    private fun buildResource(): Resource =
        Resource.getDefault().toBuilder()
            .put(OagAttributes.SERVICE_NAME, config.serviceName)
            .put(OagAttributes.SERVICE_VERSION, oagVersion)
            .build()
}
