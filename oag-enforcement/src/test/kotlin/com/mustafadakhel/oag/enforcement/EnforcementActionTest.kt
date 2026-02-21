package com.mustafadakhel.oag.enforcement

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class EnforcementActionTest {

    @Test
    fun `all variants are EnforcementAction subtypes`() {
        val actions: List<EnforcementAction> = listOf(
            EnforcementAction.Allow,
            EnforcementAction.Deny("blocked"),
            EnforcementAction.Notify(message = "alert"),
            EnforcementAction.Redact("api_key"),
            EnforcementAction.Truncate(1024)
        )
        assertEquals(5, actions.size)
    }

    @Test
    fun `deny has default status code 403`() {
        val deny = EnforcementAction.Deny("forbidden")
        assertEquals(403, deny.statusCode)
    }

    @Test
    fun `deny accepts custom status code`() {
        val deny = EnforcementAction.Deny("rate limited", statusCode = 429)
        assertEquals(429, deny.statusCode)
    }

    @Test
    fun `allow is a singleton`() {
        assertIs<EnforcementAction>(EnforcementAction.Allow)
        assertEquals(EnforcementAction.Allow, EnforcementAction.Allow)
    }

    @Test
    fun `when expression covers all variants`() {
        val action: EnforcementAction = EnforcementAction.Deny("test")
        val label = when (action) {
            is EnforcementAction.Allow -> "allow"
            is EnforcementAction.Deny -> "deny"
            is EnforcementAction.Notify -> "notify"
            is EnforcementAction.Redact -> "redact"
            is EnforcementAction.Truncate -> "truncate"
        }
        assertEquals("deny", label)
    }
}
