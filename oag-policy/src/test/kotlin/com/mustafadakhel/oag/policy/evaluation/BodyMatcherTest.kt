package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyBodyMatch

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BodyMatcherTest {
    @Test
    fun `null body match always matches`() {
        assertTrue(matchesBody(null, "anything"))
        assertTrue(matchesBody(null, null))
    }

    @Test
    fun `null body fails when body match is defined`() {
        val match = PolicyBodyMatch(contains = listOf("token"))
        assertFalse(matchesBody(match, null))
    }

    @Test
    fun `contains matches when all literals present`() {
        val match = PolicyBodyMatch(contains = listOf("model", "gpt-4"))
        assertTrue(matchesBody(match, """{"model":"gpt-4","prompt":"hello"}"""))
    }

    @Test
    fun `contains fails when any literal missing`() {
        val match = PolicyBodyMatch(contains = listOf("model", "gpt-5"))
        assertFalse(matchesBody(match, """{"model":"gpt-4","prompt":"hello"}"""))
    }

    @Test
    fun `pattern matches with valid regex`() {
        val match = PolicyBodyMatch(patterns = listOf("\"model\":\\s*\"gpt-[34]\""))
        assertTrue(matchesBody(match, """{"model": "gpt-4"}"""))
        assertFalse(matchesBody(match, """{"model": "gpt-5"}"""))
    }

    @Test
    fun `contains and patterns both must match`() {
        val match = PolicyBodyMatch(
            contains = listOf("model"),
            patterns = listOf("gpt-\\d+")
        )
        assertTrue(matchesBody(match, """{"model":"gpt-4"}"""))
        assertFalse(matchesBody(match, """{"model":"claude-3"}"""))
        assertFalse(matchesBody(match, """{"name":"gpt-4"}"""))
    }

    @Test
    fun `invalid regex does not match (fail-closed)`() {
        val match = PolicyBodyMatch(patterns = listOf("[invalid"))
        assertFalse(matchesBody(match, "any content"))
    }

    @Test
    fun `empty contains and patterns lists match everything`() {
        val match = PolicyBodyMatch(contains = emptyList(), patterns = emptyList())
        assertTrue(matchesBody(match, "anything"))
    }

    @Test
    fun `body with zero-width characters still matches contains`() {
        val match = PolicyBodyMatch(contains = listOf("ignore previous instructions"))
        val body = "ignore\u200B previous\u200C instructions"
        assertTrue(matchesBody(match, body))
    }

    @Test
    fun `body with fullwidth characters still matches pattern`() {
        val match = PolicyBodyMatch(patterns = listOf("ignore.*instructions"))
        val body = "i\uFF47nore previous instructions"
        assertTrue(matchesBody(match, body))
    }
}
