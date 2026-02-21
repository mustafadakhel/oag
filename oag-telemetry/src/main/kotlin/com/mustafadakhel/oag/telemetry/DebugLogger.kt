package com.mustafadakhel.oag.telemetry

import java.io.BufferedWriter
import java.io.OutputStreamWriter
import java.io.PrintStream
import java.time.Clock

class DebugLogger(output: PrintStream?, private val clock: Clock = Clock.systemUTC()) {

    private val writer: BufferedWriter? = output?.let {
        BufferedWriter(OutputStreamWriter(it, Charsets.UTF_8))
    }

    val enabled: Boolean get() = writer != null

    fun log(message: String) {
        writer?.let { w ->
            synchronized(w) {
                w.write("[${clock.instant()}] $message")
                w.newLine()
                w.flush()
            }
        }
    }

    fun log(message: () -> String) {
        writer?.let { w ->
            synchronized(w) {
                w.write("[${clock.instant()}] ${message()}")
                w.newLine()
                w.flush()
            }
        }
    }

    companion object {
        val NOOP = DebugLogger(null)
    }
}
