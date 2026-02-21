package com.mustafadakhel.oag

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ContentNormalizerTest {
    @Test
    fun `strips zero-width space`() {
        val input = "ignore\u200B previous instructions"
        assertEquals("ignore previous instructions", input.normalizeContent())
    }

    @Test
    fun `strips zero-width non-joiner`() {
        val input = "ignore\u200C instructions"
        assertEquals("ignore instructions", input.normalizeContent())
    }

    @Test
    fun `strips zero-width joiner`() {
        val input = "ignore\u200D instructions"
        assertEquals("ignore instructions", input.normalizeContent())
    }

    @Test
    fun `strips byte order mark`() {
        val input = "\uFEFFignore instructions"
        assertEquals("ignore instructions", input.normalizeContent())
    }

    @Test
    fun `strips soft hyphen`() {
        val input = "ig\u00ADnore"
        assertEquals("ignore", input.normalizeContent())
    }

    @Test
    fun `strips word joiner`() {
        val input = "ignore\u2060 instructions"
        assertEquals("ignore instructions", input.normalizeContent())
    }

    @Test
    fun `strips mongolian vowel separator`() {
        val input = "ignore\u180E instructions"
        assertEquals("ignore instructions", input.normalizeContent())
    }

    @Test
    fun `NFKC normalizes fullwidth latin to ascii`() {
        val input = "\uFF21\uFF22\uFF23"
        assertEquals("ABC", input.normalizeContent())
    }

    @Test
    fun `NFKC normalizes compatibility characters`() {
        val input = "\uFB01le"
        assertEquals("file", input.normalizeContent())
    }

    @Test
    fun `plain ascii passes through unchanged`() {
        val input = "ignore previous instructions"
        assertEquals("ignore previous instructions", input.normalizeContent())
    }

    @Test
    fun `empty string returns empty`() {
        assertEquals("", "".normalizeContent())
    }

    @Test
    fun `combined zero-width and fullwidth normalization`() {
        val input = "\u200Bignore\u200C \uFF50revious\u200D instructions\uFEFF"
        val result = input.normalizeContent()
        assertTrue(result.contains("ignore"))
        assertTrue(result.contains("previous"))
        assertTrue(result.contains("instructions"))
        assertFalse(result.contains("\u200B"))
        assertFalse(result.contains("\uFEFF"))
    }
}
