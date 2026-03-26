package com.mustafadakhel.oag.inspection.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CharCodeTokenizerTest {

    private val tokenizer = CharCodeTokenizer()

    @Test
    fun `encode wraps text with CLS and SEP tokens`() {
        val encoding = tokenizer.encode("Hi", 512)
        assertEquals(101L, encoding.ids.first(), "First token should be CLS=101")
        assertEquals(102L, encoding.ids.last(), "Last token should be SEP=102")
    }

    @Test
    fun `encode converts characters to unicode code points`() {
        val encoding = tokenizer.encode("A", 512)
        assertEquals(3, encoding.ids.size)
        assertEquals(101L, encoding.ids[0])
        assertEquals(65L, encoding.ids[1])
        assertEquals(102L, encoding.ids[2])
    }

    @Test
    fun `encode respects maxLength`() {
        val longText = "a".repeat(1000)
        val encoding = tokenizer.encode(longText, 10)
        assertEquals(12, encoding.ids.size, "Should be CLS + 10 chars + SEP")
    }

    @Test
    fun `attention mask is all ones`() {
        val encoding = tokenizer.encode("test", 512)
        assertTrue(encoding.attentionMask.all { it == 1L })
        assertEquals(encoding.ids.size, encoding.attentionMask.size)
    }

    @Test
    fun `empty string produces CLS and SEP only`() {
        val encoding = tokenizer.encode("", 512)
        assertEquals(2, encoding.ids.size)
        assertEquals(101L, encoding.ids[0])
        assertEquals(102L, encoding.ids[1])
    }
}
