package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.http.startRelay

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

class StreamRelayTest {
    @Test
    fun `relay flushes output after reaching eof`() = runTest {
        val input = ByteArrayInputStream("hello".toByteArray(Charsets.US_ASCII))
        val output = TrackingOutputStream()

        val relay = startRelay(input, output)
        withContext(Dispatchers.Default) { withTimeout(1_000) { relay.join() } }

        assertTrue(!relay.isActive, "relay job should complete")
        assertEquals("hello", output.buffer.toString(Charsets.US_ASCII))
        assertTrue(output.flushCount > 0, "output should be flushed to signal relay completion")
        assertTrue(!output.closed, "output should remain open for CONNECT relay")
    }

    @Test
    fun `relay flushes output when input read fails`() = runTest {
        val input = object : InputStream() {
            override fun read(): Int = throw IOException("read failed")
        }
        val output = TrackingOutputStream()

        val relay = startRelay(input, output)
        withContext(Dispatchers.Default) { withTimeout(1_000) { relay.join() } }

        assertTrue(!relay.isActive, "relay job should complete on read failure")
        assertTrue(output.flushCount > 0, "output should be flushed when relay fails")
        assertTrue(!output.closed, "output should remain open for CONNECT relay")
    }
}

private class TrackingOutputStream : OutputStream() {
    val buffer = ByteArrayOutputStream()
    var flushCount = 0
    var closed = false
        private set

    override fun write(b: Int) = buffer.write(b)

    override fun write(b: ByteArray, off: Int, len: Int) = buffer.write(b, off, len)

    override fun close() {
        closed = true
    }

    override fun flush() {
        flushCount += 1
    }
}
