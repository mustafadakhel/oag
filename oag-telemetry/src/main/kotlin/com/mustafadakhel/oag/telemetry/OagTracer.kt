package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.audit.AuditTrace

import io.opentelemetry.api.trace.SpanKind
import io.opentelemetry.api.trace.Tracer
import io.opentelemetry.context.Context
import io.opentelemetry.exporter.logging.LoggingSpanExporter
import io.opentelemetry.exporter.otlp.http.trace.OtlpHttpSpanExporter
import io.opentelemetry.exporter.otlp.trace.OtlpGrpcSpanExporter
import io.opentelemetry.sdk.resources.Resource
import io.opentelemetry.sdk.trace.SdkTracerProvider
import io.opentelemetry.sdk.trace.export.BatchSpanProcessor

import java.io.Closeable
import java.time.Duration

class OagTracer(
    private val tracer: Tracer,
    private val tracerProvider: SdkTracerProvider? = null
) : Closeable {

    fun startRequestSpan(method: String, host: String, path: String, trace: AuditTrace?): RequestSpan {
        val parentContext = trace?.let { contextForTrace(it) } ?: Context.current()
        val span = tracer.spanBuilder("$method $host$path")
            .setParent(parentContext)
            .setSpanKind(SpanKind.SERVER)
            .setAttribute(OagAttributes.HTTP_REQUEST_METHOD, method)
            .setAttribute(OagAttributes.SERVER_ADDRESS, host)
            .setAttribute(OagAttributes.URL_PATH, path)
            .startSpan()
        return OtelRequestSpan(span)
    }

    override fun close() {
        tracerProvider?.shutdown()
    }
}

fun buildOagTracer(config: OtelConfig, oagVersion: String): OagTracer? {
    if (!config.enabled) return null

    val resource = Resource.getDefault().toBuilder()
        .put(OagAttributes.SERVICE_NAME, config.serviceName)
        .put(OagAttributes.SERVICE_VERSION, oagVersion)
        .build()

    val spanExporter = when (config.exporter) {
        OtelExporterType.NONE -> return null
        OtelExporterType.STDOUT -> LoggingSpanExporter.create()
        OtelExporterType.OTLP_HTTP -> OtlpHttpSpanExporter.builder()
            .setEndpoint(requireNotNull(config.endpoint))
            .apply { config.headers.forEach { (key, value) -> addHeader(key, value) } }
            .setTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
            .build()
        OtelExporterType.OTLP_GRPC -> OtlpGrpcSpanExporter.builder()
            .setEndpoint(requireNotNull(config.endpoint))
            .apply { config.headers.forEach { (key, value) -> addHeader(key, value) } }
            .setTimeout(Duration.ofMillis(config.timeoutMs.toLong()))
            .build()
    }

    val tracerProvider = SdkTracerProvider.builder()
        .setResource(resource)
        .addSpanProcessor(BatchSpanProcessor.builder(spanExporter).build())
        .build()

    val tracer = tracerProvider.tracerBuilder(OagAttributes.LOGGER_SCOPE)
        .setInstrumentationVersion(oagVersion)
        .build()

    return OagTracer(tracer, tracerProvider)
}
