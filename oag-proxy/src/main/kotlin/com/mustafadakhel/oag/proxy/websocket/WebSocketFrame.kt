package com.mustafadakhel.oag.proxy.websocket

import com.mustafadakhel.oag.readFully

import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

data class WebSocketFrame(
    val fin: Boolean,
    val opcode: Int,
    val masked: Boolean,
    val payload: ByteArray
) {
    val isText: Boolean get() = opcode == OPCODE_TEXT
    val isBinary: Boolean get() = opcode == OPCODE_BINARY
    val isClose: Boolean get() = opcode == OPCODE_CLOSE
    val isPing: Boolean get() = opcode == OPCODE_PING
    val isPong: Boolean get() = opcode == OPCODE_PONG
    val isControl: Boolean get() = opcode >= OPCODE_CLOSE

    val textPayload: String get() = payload.toString(Charsets.UTF_8)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is WebSocketFrame) return false
        return fin == other.fin && opcode == other.opcode && masked == other.masked && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = fin.hashCode()
        result = 31 * result + opcode
        result = 31 * result + masked.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    companion object {
        const val OPCODE_TEXT = 0x1
        const val OPCODE_BINARY = 0x2
        const val OPCODE_CLOSE = 0x8
        const val OPCODE_PING = 0x9
        const val OPCODE_PONG = 0xA

        const val NORMAL_CLOSE_CODE = 1000
        const val MAX_FRAME_SIZE = 16 * 1024 * 1024L // 16 MB
        const val PAYLOAD_LENGTH_16BIT = 126L
        const val PAYLOAD_LENGTH_64BIT = 127L
        const val MAX_CONTROL_PAYLOAD = 125L

        fun buildCloseFrame(code: Int = NORMAL_CLOSE_CODE): WebSocketFrame {
            val payload = ByteArray(2)
            payload[0] = (code shr 8 and 0xFF).toByte()
            payload[1] = (code and 0xFF).toByte()
            return WebSocketFrame(fin = true, opcode = OPCODE_CLOSE, masked = false, payload = payload)
        }
    }
}

private val maskRandom = SecureRandom()
private const val MASK_CHUNK_SIZE = 8192

fun readWebSocketFrame(input: InputStream): WebSocketFrame? {
    val b0 = input.read()
    if (b0 == -1) return null
    val b1 = input.read()
    if (b1 == -1) return null

    val fin = (b0 and 0x80) != 0
    val rsv = (b0 and 0x70)
    val opcode = b0 and 0x0F
    val masked = (b1 and 0x80) != 0
    var payloadLength = (b1 and 0x7F).toLong()

    // RSV bits must be 0 unless extensions are negotiated
    require(rsv == 0) { "Non-zero RSV bits without extension negotiation" }

    when (payloadLength) {
        WebSocketFrame.PAYLOAD_LENGTH_16BIT -> {
            val buf = readExact(input, 2) ?: return null
            payloadLength = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).short.toLong() and 0xFFFF
        }
        WebSocketFrame.PAYLOAD_LENGTH_64BIT -> {
            val buf = readExact(input, 8) ?: return null
            payloadLength = ByteBuffer.wrap(buf).order(ByteOrder.BIG_ENDIAN).long
            require(payloadLength >= 0) { "Negative 64-bit payload length" }
        }
    }

    // Control frames must not exceed 125 bytes and must have FIN set
    if (opcode >= WebSocketFrame.OPCODE_CLOSE) {
        require(payloadLength <= WebSocketFrame.MAX_CONTROL_PAYLOAD) {
            "Control frame payload exceeds ${WebSocketFrame.MAX_CONTROL_PAYLOAD} bytes"
        }
        require(fin) { "Fragmented control frame" }
    }

    require(payloadLength <= WebSocketFrame.MAX_FRAME_SIZE) {
        "Frame payload $payloadLength exceeds max ${WebSocketFrame.MAX_FRAME_SIZE}"
    }

    val maskKey = if (masked) {
        readExact(input, 4) ?: return null
    } else {
        null
    }

    val payload = if (payloadLength > 0) {
        readExact(input, payloadLength.toInt()) ?: return null
    } else {
        ByteArray(0)
    }

    if (maskKey != null) {
        for (i in payload.indices) {
            payload[i] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
        }
    }

    return WebSocketFrame(fin, opcode, masked, payload)
}

fun writeWebSocketFrame(output: OutputStream, frame: WebSocketFrame) {
    val b0 = (if (frame.fin) 0x80 else 0x00) or frame.opcode
    output.write(b0)

    val maskBit = if (frame.masked) 0x80 else 0x00
    val length = frame.payload.size

    when {
        length < WebSocketFrame.PAYLOAD_LENGTH_16BIT.toInt() -> output.write(maskBit or length)
        length < 65536 -> {
            output.write(maskBit or WebSocketFrame.PAYLOAD_LENGTH_16BIT.toInt())
            output.write(length shr 8 and 0xFF)
            output.write(length and 0xFF)
        }
        else -> {
            output.write(maskBit or WebSocketFrame.PAYLOAD_LENGTH_64BIT.toInt())
            val buf = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(length.toLong()).array()
            output.write(buf)
        }
    }

    if (frame.masked) {
        val maskKey = ByteArray(4)
        maskRandom.nextBytes(maskKey)
        output.write(maskKey)
        val payload = frame.payload
        val chunk = ByteArray(minOf(MASK_CHUNK_SIZE, payload.size))
        var offset = 0
        while (offset < payload.size) {
            val end = minOf(offset + chunk.size, payload.size)
            for (i in offset until end) {
                chunk[i - offset] = (payload[i].toInt() xor maskKey[i % 4].toInt()).toByte()
            }
            output.write(chunk, 0, end - offset)
            offset = end
        }
    } else {
        output.write(frame.payload)
    }

    output.flush()
}

private fun readExact(input: InputStream, count: Int): ByteArray? {
    val buf = ByteArray(count)
    return buf.takeIf { readFully(input, it) }
}
