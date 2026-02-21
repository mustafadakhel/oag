package com.mustafadakhel.oag.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CliParserTest {

    @Test
    fun `value returns value after matching flag`() {
        val parsed = ParsedArgs(arrayOf("--policy", "policy.yaml", "--port", "8080"))
        assertEquals("policy.yaml", parsed.value("--policy"))
        assertEquals("8080", parsed.value("--port"))
    }

    @Test
    fun `value returns null for missing flag`() {
        val parsed = ParsedArgs(arrayOf("--policy", "policy.yaml"))
        assertNull(parsed.value("--port"))
    }

    @Test
    fun `ParsedArgs throws when value flag missing value`() {
        assertFailsWith<CliException> { ParsedArgs(arrayOf("--policy")) }
    }

    @Test
    fun `value accepts value starting with double dash`() {
        val parsed = ParsedArgs(arrayOf("--policy", "--my-policy"))
        assertEquals("--my-policy", parsed.value("--policy"))
    }

    @Test
    fun `hasFlag detects present flag`() {
        val parsed = ParsedArgs(arrayOf("--dry-run", "--policy", "test.yaml"))
        assertTrue(parsed.hasFlag("--dry-run"))
    }

    @Test
    fun `hasFlag returns false for missing flag`() {
        val parsed = ParsedArgs(arrayOf("--policy", "test.yaml"))
        assertFalse(parsed.hasFlag("--dry-run"))
    }

    @Test
    fun `requireValue returns value when present`() {
        val parsed = ParsedArgs(arrayOf("--policy", "policy.yaml"))
        assertEquals("policy.yaml", parsed.requireValue("--policy"))
    }

    @Test
    fun `requireValue throws when missing`() {
        val parsed = ParsedArgs(arrayOf("--port", "8080"))
        assertFailsWith<CliException> { parsed.requireValue("--policy") }
    }

    @Test
    fun `intValue returns parsed int`() {
        val parsed = ParsedArgs(arrayOf("--port", "8080"))
        assertEquals(8080, parsed.intValue("--port", 3000))
    }

    @Test
    fun `intValue returns default when missing`() {
        val parsed = ParsedArgs(emptyArray())
        assertEquals(3000, parsed.intValue("--port", 3000))
    }

    @Test
    fun `intValue throws on non-integer value`() {
        val parsed = ParsedArgs(arrayOf("--port", "abc"))
        assertFailsWith<CliException> { parsed.intValue("--port", 3000) }
    }

    @Test
    fun `longValue returns parsed long`() {
        val parsed = ParsedArgs(arrayOf("--drain-timeout-ms", "30000"))
        assertEquals(30000L, parsed.longValue("--drain-timeout-ms", 5000L))
    }

    @Test
    fun `doubleValue returns parsed double`() {
        val parsed = ParsedArgs(arrayOf("--velocity-spike-threshold", "0.75"))
        assertEquals(0.75, parsed.doubleValue("--velocity-spike-threshold", 0.5))
    }

    @Test
    fun `commaSeparatedList splits on commas`() {
        val parsed = ParsedArgs(arrayOf("--webhook-events", "a,b,c"))
        assertEquals(listOf("a", "b", "c"), parsed.commaSeparatedList("--webhook-events"))
    }

    @Test
    fun `commaSeparatedList trims whitespace and drops empties`() {
        val parsed = ParsedArgs(arrayOf("--webhook-events", " a , , b "))
        assertEquals(listOf("a", "b"), parsed.commaSeparatedList("--webhook-events"))
    }

    @Test
    fun `commaSeparatedList returns empty when missing`() {
        val parsed = ParsedArgs(emptyArray())
        assertEquals(emptyList(), parsed.commaSeparatedList("--webhook-events"))
    }

    @Test
    fun `parseOtelConfig parses headers`() {
        val parsed = ParsedArgs(arrayOf("--otel-headers", "key1=val1,key2=val2"))
        val config = parsed.parseOtelConfig()
        assertEquals(mapOf("key1" to "val1", "key2" to "val2"), config.headers)
    }

    @Test
    fun `parseOtelConfig returns empty headers for blank value`() {
        val parsed = ParsedArgs(arrayOf("--otel-headers", "  "))
        assertEquals(emptyMap(), parsed.parseOtelConfig().headers)
    }

    @Test
    fun `parseOtelConfig throws on invalid header entry without equals`() {
        val parsed = ParsedArgs(arrayOf("--otel-headers", "badentry"))
        assertFailsWith<CliException> { parsed.parseOtelConfig() }
    }

    @Test
    fun `ParsedArgs separates flags values and positionals`() {
        val parsed = ParsedArgs(arrayOf("--dry-run", "--policy", "test.yaml", "positional-arg"))
        assertTrue(parsed.hasFlag("--dry-run"))
        assertEquals("test.yaml", parsed.value("--policy"))
        assertEquals(listOf("positional-arg"), parsed.positional)
    }

    @Test
    fun `ParsedArgs handles empty args`() {
        val parsed = ParsedArgs(emptyArray())
        assertFalse(parsed.hasFlag("--dry-run"))
        assertNull(parsed.value("--policy"))
        assertTrue(parsed.positional.isEmpty())
    }

    @Test
    fun `positional args skip value flags`() {
        val parsed = ParsedArgs(arrayOf("--policy", "test.yaml", "myfile.yaml"))
        assertEquals("myfile.yaml", parsed.positional.firstOrNull())
    }

    @Test
    fun `positional returns empty when no positional args`() {
        val parsed = ParsedArgs(arrayOf("--policy", "test.yaml", "--dry-run"))
        assertTrue(parsed.positional.isEmpty())
    }

    @Test
    fun `parseRequestSpec parses method and target`() {
        val result = parseRequestSpec("GET https://api.example.com/v1/models", "bad spec")
        assertEquals("GET", result.method)
        assertEquals("api.example.com", result.host)
        assertEquals("/v1/models", result.path)
        assertEquals("https", result.scheme)
    }

    @Test
    fun `parseRequestSpec throws on missing method`() {
        assertFailsWith<CliException> { parseRequestSpec("https://example.com", "bad spec") }
    }
}
