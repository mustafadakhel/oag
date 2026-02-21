package com.mustafadakhel.oag.telemetry

import com.mustafadakhel.oag.label

import java.util.Locale

data class OtelConfig(
    val exporter: OtelExporterType = OtelExporterType.NONE,
    val endpoint: String? = null,
    val headers: Map<String, String> = emptyMap(),
    val timeoutMs: Int = DEFAULT_OTEL_TIMEOUT_MS,
    val serviceName: String = DEFAULT_OTEL_SERVICE_NAME
) {
    val enabled: Boolean
        get() = exporter != OtelExporterType.NONE

    override fun toString(): String =
        "OtelConfig(exporter=$exporter, endpoint=$endpoint, headers=${headers.keys}, " +
            "timeoutMs=$timeoutMs, serviceName=$serviceName)"

    companion object {
        const val DEFAULT_OTEL_TIMEOUT_MS = 10_000
        const val DEFAULT_OTEL_SERVICE_NAME = "oag"
    }
}

enum class OtelExporterType {
    NONE,
    OTLP_HTTP,
    OTLP_GRPC,
    STDOUT;

    companion object {
        fun from(raw: String?): OtelExporterType? =
            entries.firstOrNull { it.label() == raw?.trim()?.lowercase(Locale.ROOT) }
    }
}
