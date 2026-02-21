package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.policy.distribution.policyYaml
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class PolicyResponseRewriteSerializerTest {

    private fun decode(yaml: String): PolicyResponseRewrite =
        policyYaml.decodeFromString(PolicyResponseRewrite.serializer(), yaml)

    @Test
    fun `deserializes REDACT with pattern`() {
        val rewrite = decode("action: redact\npattern: \"SSN-\\\\d+\"")
        assertIs<PolicyResponseRewrite.Redact>(rewrite)
        assertEquals("SSN-\\d+", rewrite.pattern)
    }

    @Test
    fun `deserializes REMOVE_HEADER`() {
        val rewrite = decode("action: remove_header\nheader: X-Internal")
        assertIs<PolicyResponseRewrite.RemoveHeader>(rewrite)
        assertEquals("X-Internal", rewrite.header)
    }

    @Test
    fun `deserializes SET_HEADER`() {
        val rewrite = decode("action: set_header\nheader: X-Custom\nvalue: safe")
        assertIs<PolicyResponseRewrite.SetHeader>(rewrite)
        assertEquals("X-Custom", rewrite.header)
        assertEquals("safe", rewrite.value)
    }

    @Test
    fun `unknown action throws`() {
        assertFailsWith<IllegalArgumentException> {
            decode("action: unknown_action")
        }
    }

    @Test
    fun `REDACT without pattern throws`() {
        assertFailsWith<IllegalArgumentException> {
            decode("action: redact")
        }
    }

    @Test
    fun `REMOVE_HEADER without header throws`() {
        assertFailsWith<IllegalArgumentException> {
            decode("action: remove_header")
        }
    }

    @Test
    fun `SET_HEADER without header throws`() {
        assertFailsWith<IllegalArgumentException> {
            decode("action: set_header\nvalue: something")
        }
    }

    @Test
    fun `SET_HEADER without value throws`() {
        assertFailsWith<IllegalArgumentException> {
            decode("action: set_header\nheader: X-Custom")
        }
    }
}
