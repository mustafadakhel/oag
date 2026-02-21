package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.websocket.WebSocketFrame
import com.mustafadakhel.oag.proxy.websocket.readWebSocketFrame
import com.mustafadakhel.oag.proxy.websocket.writeWebSocketFrame

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class WebSocketFrameTest {

    private fun roundTrip(frame: WebSocketFrame): WebSocketFrame? {
        val out = ByteArrayOutputStream()
        writeWebSocketFrame(out, frame)
        val input = ByteArrayInputStream(out.toByteArray())
        return readWebSocketFrame(input)
    }

    private fun buildRawFrame(
        fin: Boolean = true,
        rsv1: Boolean = false,
        opcode: Int,
        masked: Boolean = false,
        payload: ByteArray = ByteArray(0),
        declaredPayloadSize: Long = payload.size.toLong()
    ): ByteArray {
        val b0 = ((if (fin) 0x80 else 0) or (if (rsv1) 0x40 else 0) or opcode).toByte()
        val out = ByteArrayOutputStream()
        out.write(b0.toInt() and 0xFF)
        val maskBit = if (masked) 0x80 else 0
        when {
            declaredPayloadSize < 126 -> out.write(maskBit or declaredPayloadSize.toInt())
            declaredPayloadSize < 65536 -> {
                out.write(maskBit or 126)
                out.write((declaredPayloadSize shr 8).toInt() and 0xFF)
                out.write(declaredPayloadSize.toInt() and 0xFF)
            }
            else -> {
                out.write(maskBit or 127)
                for (i in 56 downTo 0 step 8) {
                    out.write((declaredPayloadSize shr i).toInt() and 0xFF)
                }
            }
        }
        out.write(payload)
        return out.toByteArray()
    }

    @Test
    fun `write and read back text frame`() {
        val payload = "Hello, WebSocket!"
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = payload.toByteArray(Charsets.UTF_8)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.fin)
        assertEquals(WebSocketFrame.OPCODE_TEXT, result.opcode)
        assertEquals(payload, result.textPayload)
    }

    @Test
    fun `write and read back binary frame`() {
        val payload = byteArrayOf(0x00, 0x01, 0x02, 0xFF.toByte(), 0xFE.toByte())
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_BINARY,
            masked = false,
            payload = payload
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.fin)
        assertEquals(WebSocketFrame.OPCODE_BINARY, result.opcode)
        assertTrue(payload.contentEquals(result.payload))
    }

    @Test
    fun `close frame has isClose true`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_CLOSE,
            masked = false,
            payload = ByteArray(0)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.isClose)
        assertFalse(result.isText)
        assertFalse(result.isPing)
        assertFalse(result.isPong)
    }

    @Test
    fun `ping frame has isPing true`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_PING,
            masked = false,
            payload = ByteArray(0)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.isPing)
        assertFalse(result.isClose)
        assertFalse(result.isPong)
        assertTrue(result.isControl)
    }

    @Test
    fun `pong frame has isPong true`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_PONG,
            masked = false,
            payload = ByteArray(0)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.isPong)
        assertFalse(result.isPing)
        assertFalse(result.isClose)
        assertTrue(result.isControl)
    }

    @Test
    fun `isText property works correctly`() {
        val textFrame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = "test".toByteArray()
        )
        val binaryFrame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_BINARY,
            masked = false,
            payload = ByteArray(0)
        )

        assertTrue(textFrame.isText)
        assertFalse(textFrame.isBinary)
        assertFalse(binaryFrame.isText)
        assertTrue(binaryFrame.isBinary)
    }

    @Test
    fun `textPayload returns correct string for text frames`() {
        val message = "The quick brown fox jumps over the lazy dog"
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = message.toByteArray(Charsets.UTF_8)
        )

        assertEquals(message, frame.textPayload)
    }

    @Test
    fun `reading from empty stream returns null`() {
        val input = ByteArrayInputStream(ByteArray(0))
        val result = readWebSocketFrame(input)

        assertNull(result)
    }

    @Test
    fun `masked frame round trips correctly`() {
        val payload = "masked payload"
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = true,
            payload = payload.toByteArray(Charsets.UTF_8)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.masked)
        assertEquals(payload, result.textPayload)
    }

    @Test
    fun `non-fin frame preserves fin flag`() {
        val frame = WebSocketFrame(
            fin = false,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = "fragment".toByteArray(Charsets.UTF_8)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertFalse(result.fin)
        assertEquals(WebSocketFrame.OPCODE_TEXT, result.opcode)
        assertEquals("fragment", result.textPayload)
    }

    @Test
    fun `empty payload frame round trips`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = ByteArray(0)
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertEquals(0, result.payload.size)
    }

    @Test
    fun `16-bit extended payload round trips`() {
        val payload = ByteArray(200) { (it % 256).toByte() }
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_BINARY,
            masked = false,
            payload = payload
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertEquals(200, result.payload.size)
        assertTrue(payload.contentEquals(result.payload))
    }

    @Test
    fun `rsv bits cause rejection`() {
        val bytes = buildRawFrame(rsv1 = true, opcode = WebSocketFrame.OPCODE_TEXT, payload = "Hello".toByteArray())
        val input = ByteArrayInputStream(bytes)

        assertFailsWith<IllegalArgumentException>("Non-zero RSV bits") {
            readWebSocketFrame(input)
        }
    }

    @Test
    fun `control frame with payload over 125 bytes is rejected`() {
        val oversizedControlPayload = ByteArray(126)
        val bytes = buildRawFrame(opcode = WebSocketFrame.OPCODE_CLOSE, payload = oversizedControlPayload)
        val input = ByteArrayInputStream(bytes)

        assertFailsWith<IllegalArgumentException>("Control frame payload exceeds 125 bytes") {
            readWebSocketFrame(input)
        }
    }

    @Test
    fun `fragmented control frame is rejected`() {
        val bytes = buildRawFrame(fin = false, opcode = WebSocketFrame.OPCODE_CLOSE)
        val input = ByteArrayInputStream(bytes)

        assertFailsWith<IllegalArgumentException>("Fragmented control frame") {
            readWebSocketFrame(input)
        }
    }

    @Test
    fun `frame exceeding max size is rejected`() {
        val exceedsMaxSize = 32L * 1024 * 1024
        val bytes = buildRawFrame(opcode = WebSocketFrame.OPCODE_BINARY, declaredPayloadSize = exceedsMaxSize)
        val input = ByteArrayInputStream(bytes)

        assertFailsWith<IllegalArgumentException>("Frame payload") {
            readWebSocketFrame(input)
        }
    }

    @Test
    fun `masked frame write produces non-zero mask key`() {
        val payload = "test masked write"
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = true,
            payload = payload.toByteArray(Charsets.UTF_8)
        )
        val out = ByteArrayOutputStream()
        writeWebSocketFrame(out, frame)
        val bytes = out.toByteArray()
        val frameHeaderSize = 2
        val maskKey = bytes.sliceArray(frameHeaderSize until frameHeaderSize + 4)
        assertFalse(maskKey.all { it.toInt() == 0 })
        val result = readWebSocketFrame(ByteArrayInputStream(bytes))
        assertNotNull(result)
        assertEquals(payload, result.textPayload)
    }

    @Test
    fun `ping frame with payload round trips`() {
        val payload = "ping data".toByteArray(Charsets.UTF_8)
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_PING,
            masked = false,
            payload = payload
        )

        val result = roundTrip(frame)

        assertNotNull(result)
        assertTrue(result.isPing)
        assertTrue(payload.contentEquals(result.payload))
    }
}
