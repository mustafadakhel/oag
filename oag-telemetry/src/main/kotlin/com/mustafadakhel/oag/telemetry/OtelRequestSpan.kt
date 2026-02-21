package com.mustafadakhel.oag.telemetry

import io.opentelemetry.api.trace.Span
import io.opentelemetry.api.trace.StatusCode

internal class OtelRequestSpan(private val span: Span) : RequestSpan {

    override fun setAttribute(key: String, value: String) {
        span.setAttribute(key, value)
    }

    override fun setAttribute(key: String, value: Long) {
        span.setAttribute(key, value)
    }

    override fun setErrorStatus() {
        span.setStatus(StatusCode.ERROR)
    }

    override fun end() {
        span.end()
    }

    override fun traceParentHeader(): String {
        val sc = span.spanContext
        return "00-${sc.traceId}-${sc.spanId}-${sc.traceFlags.asHex()}"
    }
}
