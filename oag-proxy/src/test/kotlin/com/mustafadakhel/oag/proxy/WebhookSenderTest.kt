package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.WebhookEventLabels
import com.mustafadakhel.oag.computeHmacSha256
import com.mustafadakhel.oag.proxy.webhook.WebhookConfig
import com.mustafadakhel.oag.proxy.webhook.WebhookEventType
import com.mustafadakhel.oag.proxy.webhook.WebhookPayload
import com.mustafadakhel.oag.pipeline.WebhookPayloadKeys
import com.mustafadakhel.oag.proxy.webhook.WebhookSender
import com.mustafadakhel.oag.pipeline.webhookData

import com.mustafadakhel.oag.label

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class WebhookSenderTest {

    @Test
    fun `shouldSend returns true when events filter is empty`() {
        val sender = WebhookSender(validateUrl = false, config = WebhookConfig(url = "http://localhost:9999/hook"))
        assertTrue(sender.shouldSend("injection_detected"))
        assertTrue(sender.shouldSend("circuit_open"))
        assertTrue(sender.shouldSend("any_event"))
    }

    @Test
    fun `shouldSend returns true only for configured events`() {
        val sender = WebhookSender(validateUrl = false, config = WebhookConfig(
            url = "http://localhost:9999/hook",
            events = setOf(WebhookEventType.INJECTION_DETECTED)
        ))
        assertTrue(sender.shouldSend("injection_detected"))
        assertFalse(sender.shouldSend("circuit_open"))
        assertFalse(sender.shouldSend("unknown"))
    }

    @Test
    fun `computeHmacSha256 produces expected signature`() {
        val signature = computeHmacSha256("mysecret", "hello".toByteArray())
        assertEquals("f09399f0c446d84b31a080e57ec483392d41e6f512f3e7ada5027abbcd358c2a", signature)
    }

    @Test
    fun `computeHmacSha256 is deterministic`() {
        val sig1 = computeHmacSha256("key", "data".toByteArray())
        val sig2 = computeHmacSha256("key", "data".toByteArray())
        assertEquals(sig1, sig2)
    }

    @Test
    fun `computeHmacSha256 differs with different keys`() {
        val sig1 = computeHmacSha256("key1", "data".toByteArray())
        val sig2 = computeHmacSha256("key2", "data".toByteArray())
        assertTrue(sig1 != sig2)
    }

    @Test
    fun `send to unreachable URL does not throw`() = runTest {
        val sender = WebhookSender(validateUrl = false, config = WebhookConfig(
            url = "http://127.0.0.1:1/hook",
            timeoutMs = 500
        ))
        sender.send(WebhookPayload(
            eventType = "test_event",
            timestamp = "2026-01-01T00:00:00Z",
            data = webhookData("key" to "value")
        ))
    }

    @Test
    fun `webhook payload keys match event type labels`() {
        assertEquals(WebhookEventType.CIRCUIT_OPEN.label(), WebhookPayloadKeys.EVENT_CIRCUIT_OPEN)
        assertEquals(WebhookEventType.RELOAD_FAILED.label(), WebhookPayloadKeys.EVENT_RELOAD_FAILED)
        assertEquals(WebhookEventType.INJECTION_DETECTED.label(), WebhookPayloadKeys.EVENT_INJECTION_DETECTED)
        assertEquals(WebhookEventType.CREDENTIAL_DETECTED.label(), WebhookPayloadKeys.EVENT_CREDENTIAL_DETECTED)
        assertEquals(WebhookEventType.INTEGRITY_DRIFT.label(), WebhookPayloadKeys.EVENT_INTEGRITY_DRIFT)
        assertEquals(WebhookEventType.ADMIN_DENIED.label(), WebhookPayloadKeys.EVENT_ADMIN_DENIED)
    }

    @Test
    fun `send skips filtered events`() = runTest {
        val sender = WebhookSender(validateUrl = false, config = WebhookConfig(
            url = "http://127.0.0.1:1/hook",
            events = setOf(WebhookEventType.INJECTION_DETECTED),
            timeoutMs = 500
        ))
        sender.send(WebhookPayload(
            eventType = "circuit_open",
            timestamp = "2026-01-01T00:00:00Z",
            data = webhookData("host" to "api.example.com")
        ))
    }

    @Test
    fun `WebhookEventType entries match WebhookEventLabels valid set`() {
        assertEquals(
            WebhookEventType.entries.map { it.label() }.toSet(),
            WebhookEventLabels.valid
        )
    }
}
