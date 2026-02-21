package com.mustafadakhel.oag.telemetry

import io.opentelemetry.api.trace.TraceFlags

internal fun parseTraceFlagsHex(flags: String): TraceFlags =
    runCatching {
        TraceFlags.fromByte(flags.toInt(16).toByte())
    }.getOrDefault(TraceFlags.getDefault())
