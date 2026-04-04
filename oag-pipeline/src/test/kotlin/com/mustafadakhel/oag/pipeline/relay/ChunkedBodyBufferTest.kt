package com.mustafadakhel.oag.pipeline.relay

import java.io.ByteArrayInputStream

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ChunkedBodyBufferTest {

    private fun chunked(vararg chunks: String): ByteArrayInputStream {
        val sb = StringBuilder()
        for (chunk in chunks) {
            sb.append(Integer.toHexString(chunk.length)).append("\r\n")
            sb.append(chunk).append("\r\n")
        }
        sb.append("0\r\n\r\n")
        return ByteArrayInputStream(sb.toString().toByteArray())
    }

    @Test
    fun `reads single chunk`() {
        val input = chunked("hello")
        val result = readChunkedBody(input, 1024)
        assertNotNull(result)
        assertEquals("hello", String(result))
    }

    @Test
    fun `reads multiple chunks`() {
        val input = chunked("hello", " ", "world")
        val result = readChunkedBody(input, 1024)
        assertNotNull(result)
        assertEquals("hello world", String(result))
    }

    @Test
    fun `returns null when exceeds maxBytes`() {
        val input = chunked("this is more than 5 bytes")
        val result = readChunkedBody(input, 5)
        assertNull(result)
    }

    @Test
    fun `handles empty chunked body`() {
        val input = ByteArrayInputStream("0\r\n\r\n".toByteArray())
        val result = readChunkedBody(input, 1024)
        assertNull(result)
    }

    @Test
    fun `handles malformed chunk size`() {
        val input = ByteArrayInputStream("xyz\r\n".toByteArray())
        val result = readChunkedBody(input, 1024)
        assertNull(result)
    }

    @Test
    fun `handles chunk extensions`() {
        val input = ByteArrayInputStream("5;ext=val\r\nhello\r\n0\r\n\r\n".toByteArray())
        val result = readChunkedBody(input, 1024)
        assertNotNull(result)
        assertEquals("hello", String(result))
    }

    @Test
    fun `respects maxBytes exactly at boundary`() {
        val input = chunked("12345")
        val result = readChunkedBody(input, 5)
        assertNotNull(result)
        assertEquals("12345", String(result))
    }

    @Test
    fun `reads large chunked body`() {
        val data = "x".repeat(10000)
        val input = chunked(data)
        val result = readChunkedBody(input, 20000)
        assertNotNull(result)
        assertEquals(10000, result.size)
    }
}
