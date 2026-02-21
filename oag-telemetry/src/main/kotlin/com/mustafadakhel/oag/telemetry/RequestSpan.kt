package com.mustafadakhel.oag.telemetry

interface RequestSpan {
    fun setAttribute(key: String, value: String)
    fun setAttribute(key: String, value: Long)
    fun setErrorStatus()
    fun end()
    fun traceParentHeader(): String
}
