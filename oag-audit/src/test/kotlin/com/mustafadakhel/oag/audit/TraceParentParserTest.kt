package com.mustafadakhel.oag.audit

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class TraceParentParserTest {
    @Test
    fun `parseTraceParent returns trace for valid header`() {
        val trace = parseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

        requireNotNull(trace)
        assertEquals("4bf92f3577b34da6a3ce929d0e0e4736", trace.traceId)
        assertEquals("00f067aa0ba902b7", trace.spanId)
        assertEquals("01", trace.traceFlags)
    }

    @Test
    fun `parseTraceParent returns null for invalid header`() {
        assertNull(parseTraceParent("00-00000000000000000000000000000000-00f067aa0ba902b7-01"))
        assertNull(parseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01"))
        assertNull(parseTraceParent("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"))
        assertNull(parseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-zz"))
        assertNull(parseTraceParent("bad-value"))
    }

    @Test
    fun `parseTraceParent rejects 5-part traceparent with future extension`() {
        assertNull(parseTraceParent("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"))
    }
}
