package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class TrafficUnitTest {

    @Test
    fun `connect request carries host and port`() {
        val unit = TrafficUnit.ConnectRequest(host = "api.example.com", port = 443)
        assertEquals("api.example.com", unit.host)
        assertEquals(443, unit.port)
    }

    @Test
    fun `http request carries method host port path scheme and headers`() {
        val unit = TrafficUnit.HttpRequest(
            method = "POST",
            host = "api.example.com",
            port = 443,
            path = "/v1/chat",
            scheme = "https",
            headers = mapOf("Content-Type" to "application/json")
        )
        assertEquals("POST", unit.method)
        assertEquals("api.example.com", unit.host)
        assertEquals("/v1/chat", unit.path)
        assertEquals("https", unit.scheme)
        assertEquals("application/json", unit.headers["Content-Type"])
    }

    @Test
    fun `ws frame carries text and isText flag`() {
        val textFrame = TrafficUnit.WsFrame(text = "hello", isText = true)
        assertEquals("hello", textFrame.text)
        assertEquals(true, textFrame.isText)
    }

    @Test
    fun `when expression covers all variants`() {
        val unit: TrafficUnit = TrafficUnit.HttpRequest(
            method = "GET", host = "h", port = 80, path = "/", scheme = "http", headers = emptyMap()
        )
        val label = when (unit) {
            is TrafficUnit.ConnectRequest -> "connect"
            is TrafficUnit.HttpRequest -> "http_request"
            is TrafficUnit.WsFrame -> "ws_frame"
        }
        assertEquals("http_request", label)
    }

    @Test
    fun `all variants are TrafficUnit subtypes`() {
        val units: List<TrafficUnit> = listOf(
            TrafficUnit.ConnectRequest("h", 443),
            TrafficUnit.HttpRequest("GET", "h", 80, "/", "http", emptyMap()),
            TrafficUnit.WsFrame("msg", true)
        )
        assertEquals(3, units.size)
        assertIs<TrafficUnit.ConnectRequest>(units[0])
        assertIs<TrafficUnit.HttpRequest>(units[1])
        assertIs<TrafficUnit.WsFrame>(units[2])
    }
}
