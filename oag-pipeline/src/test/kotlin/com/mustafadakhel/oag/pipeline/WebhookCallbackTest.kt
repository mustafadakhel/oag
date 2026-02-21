package com.mustafadakhel.oag.pipeline

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals

class WebhookCallbackTest {

    @Test
    fun `webhookData converts string values`() {
        val data = webhookData("key" to "value")
        assertEquals(JsonPrimitive("value"), data["key"])
    }

    @Test
    fun `webhookData converts null`() {
        val data = webhookData("key" to null)
        assertEquals(JsonNull, data["key"])
    }

    @Test
    fun `webhookData converts number`() {
        val data = webhookData("count" to 42)
        assertEquals(JsonPrimitive(42), data["count"])
    }

    @Test
    fun `webhookData converts boolean`() {
        val data = webhookData("flag" to true)
        assertEquals(JsonPrimitive(true), data["flag"])
    }

    @Test
    fun `webhookData converts list of strings`() {
        val data = webhookData("patterns" to listOf("pat1", "pat2"))
        val expected = JsonArray(listOf(JsonPrimitive("pat1"), JsonPrimitive("pat2")))
        assertEquals(expected, data["patterns"])
    }

    @Test
    fun `webhookData converts nested list`() {
        val data = webhookData("nested" to listOf("a", 1, null))
        val expected = JsonArray(listOf(JsonPrimitive("a"), JsonPrimitive(1), JsonNull))
        assertEquals(expected, data["nested"])
    }

    @Test
    fun `webhookData converts unknown type via toString`() {
        data class Custom(val x: Int)
        val data = webhookData("obj" to Custom(5))
        assertEquals(JsonPrimitive("Custom(x=5)"), data["obj"])
    }

    @Test
    fun `webhookData passes through JsonElement`() {
        val element = JsonPrimitive("already json")
        val data = webhookData("el" to element)
        assertEquals(element, data["el"])
    }
}
