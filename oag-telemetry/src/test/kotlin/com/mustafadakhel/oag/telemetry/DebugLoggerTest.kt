package com.mustafadakhel.oag.telemetry

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import java.io.ByteArrayOutputStream
import java.io.PrintStream

class DebugLoggerTest {
    @Test
    fun `enabled logger writes timestamped message`() {
        val buffer = ByteArrayOutputStream()
        val logger = DebugLogger(PrintStream(buffer))

        logger.log("test message")

        val output = buffer.toString(Charsets.UTF_8)
        assertContains(output, "test message")
        assertTrue(output.startsWith("["))
        assertTrue(output.contains("]"))
    }

    @Test
    fun `enabled is true when output provided`() {
        val logger = DebugLogger(PrintStream(ByteArrayOutputStream()))
        assertTrue(logger.enabled)
    }

    @Test
    fun `enabled is false for NOOP`() {
        assertFalse(DebugLogger.NOOP.enabled)
    }

    @Test
    fun `NOOP does not throw`() {
        DebugLogger.NOOP.log("ignored")
        DebugLogger.NOOP.log { "also ignored" }
    }

    @Test
    fun `lazy log only invokes lambda when enabled`() {
        var invoked = false
        DebugLogger.NOOP.log {
            invoked = true
            "should not run"
        }
        assertFalse(invoked)

        val buffer = ByteArrayOutputStream()
        val logger = DebugLogger(PrintStream(buffer))
        logger.log {
            invoked = true
            "lazy message"
        }
        assertTrue(invoked)
        assertContains(buffer.toString(Charsets.UTF_8), "lazy message")
    }

    @Test
    fun `multiple messages are written on separate lines`() {
        val buffer = ByteArrayOutputStream()
        val logger = DebugLogger(PrintStream(buffer))

        logger.log("first")
        logger.log("second")

        val lines = buffer.toString(Charsets.UTF_8).trim().lines()
        assertEquals(2, lines.size)
        assertContains(lines[0], "first")
        assertContains(lines[1], "second")
    }
}
