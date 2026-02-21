package com.mustafadakhel.oag.proxy.websocket

import com.mustafadakhel.oag.TrafficUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class WsFramePhasesTest {

    @Test
    fun `text frame converts to WsFrame TrafficUnit with text`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_TEXT,
            masked = false,
            payload = "hello".toByteArray()
        )
        val unit = frame.toTrafficUnit()
        assertEquals(TrafficUnit.WsFrame(text = "hello", isText = true), unit)
    }

    @Test
    fun `binary frame converts to WsFrame TrafficUnit with empty text`() {
        val frame = WebSocketFrame(
            fin = true,
            opcode = WebSocketFrame.OPCODE_BINARY,
            masked = false,
            payload = byteArrayOf(0x01, 0x02)
        )
        val unit = frame.toTrafficUnit()
        assertEquals(TrafficUnit.WsFrame(text = "", isText = false), unit)
    }

    @Test
    fun `close frame converts to WsFrame TrafficUnit with empty text`() {
        val frame = WebSocketFrame.buildCloseFrame()
        val unit = frame.toTrafficUnit()
        assertFalse(unit.isText)
        assertEquals("", unit.text)
    }
}
