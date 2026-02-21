package com.mustafadakhel.oag.policy.core

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebhookNotifyTest {

    @Test
    fun `rule with no webhook events notifies all`() {
        val rule = PolicyRule()
        assertTrue(rule.shouldNotifyWebhook("any_event"))
    }

    @Test
    fun `rule with matching webhook event notifies`() {
        val rule = PolicyRule(webhookEvents = listOf("injection_detected", "circuit_open"))
        assertTrue(rule.shouldNotifyWebhook("injection_detected"))
        assertTrue(rule.shouldNotifyWebhook("circuit_open"))
    }

    @Test
    fun `rule with webhook events does not notify unmatched event`() {
        val rule = PolicyRule(webhookEvents = listOf("injection_detected"))
        assertFalse(rule.shouldNotifyWebhook("circuit_open"))
    }

    @Test
    fun `rule with empty webhook events notifies all`() {
        val rule = PolicyRule(webhookEvents = emptyList())
        assertTrue(rule.shouldNotifyWebhook("any_event"))
    }
}
