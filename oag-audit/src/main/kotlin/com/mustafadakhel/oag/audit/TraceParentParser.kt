package com.mustafadakhel.oag.audit

import java.util.Locale

private val TRACEPARENT_HEX_REGEX = Regex("^[0-9a-fA-F]+$")
private const val VERSION_LENGTH = 2
private const val TRACE_ID_LENGTH = 32
private const val SPAN_ID_LENGTH = 16
private const val FLAGS_LENGTH = 2
private const val TRACEPARENT_PART_COUNT = 4

fun parseTraceParent(header: String?): AuditTrace? {
    val value = header?.trim().orEmpty()
    if (value.isEmpty()) return null
    val parts = value.split("-", limit = TRACEPARENT_PART_COUNT)
    if (parts.size != TRACEPARENT_PART_COUNT) return null

    val (version, traceId, spanId, flags) = parts

    if (version.length != VERSION_LENGTH || !version.matches(TRACEPARENT_HEX_REGEX)) return null
    if (version.equals("ff", ignoreCase = true)) return null
    if (traceId.length != TRACE_ID_LENGTH || !traceId.matches(TRACEPARENT_HEX_REGEX)) return null
    if (traceId.all { it == '0' }) return null
    if (spanId.length != SPAN_ID_LENGTH || !spanId.matches(TRACEPARENT_HEX_REGEX)) return null
    if (spanId.all { it == '0' }) return null
    if (flags.length != FLAGS_LENGTH || !flags.matches(TRACEPARENT_HEX_REGEX)) return null

    return AuditTrace(
        traceId = traceId.lowercase(Locale.ROOT),
        spanId = spanId.lowercase(Locale.ROOT),
        traceFlags = flags.lowercase(Locale.ROOT)
    )
}
