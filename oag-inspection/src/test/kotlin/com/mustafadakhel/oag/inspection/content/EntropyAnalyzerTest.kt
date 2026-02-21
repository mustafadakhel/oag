package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.shannonEntropy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import java.util.Base64

class EntropyAnalyzerTest {
    @Test
    fun `empty string has zero entropy`() {
        assertEquals(0.0, "".shannonEntropy())
    }

    @Test
    fun `single character repeated has zero entropy`() {
        assertEquals(0.0, "aaaaaaa".shannonEntropy())
    }

    @Test
    fun `two equally distributed characters have entropy 1`() {
        val entropy = "abababab".shannonEntropy()
        assertTrue(entropy > 0.99 && entropy < 1.01)
    }

    @Test
    fun `english text has moderate entropy`() {
        val entropy = "the quick brown fox jumps over the lazy dog".shannonEntropy()
        assertTrue(entropy in 3.0..5.0, "Expected 3-5 bits, got $entropy")
    }

    @Test
    fun `base64 encoded data has high entropy`() {
        val encoded = Base64.getEncoder().encodeToString("This is a secret message with sensitive data inside".toByteArray())
        val entropy = encoded.shannonEntropy()
        assertTrue(entropy > 4.0, "Expected >4.0 bits for base64, got $entropy")
    }

    @Test
    fun `looksLikeBase64 detects encoded secrets`() {
        val encoded = Base64.getEncoder().encodeToString("user:admin token:ABC123 secret:XYZ789 data:sensitive".toByteArray())
        assertTrue(encoded.looksLikeBase64())
    }

    @Test
    fun `looksLikeBase64 rejects short strings`() {
        assertFalse("abc123".looksLikeBase64())
    }

    @Test
    fun `looksLikeBase64 rejects normal english text`() {
        assertFalse("This is a normal english sentence that is fairly long".looksLikeBase64())
    }

    @Test
    fun `looksLikeBase64 rejects low entropy long strings`() {
        assertFalse("a".repeat(100).looksLikeBase64())
    }

}
