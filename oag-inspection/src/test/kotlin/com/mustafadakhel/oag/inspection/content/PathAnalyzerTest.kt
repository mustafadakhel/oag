package com.mustafadakhel.oag.inspection.content

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PathAnalyzerTest {

    @Test
    fun `detectPathTraversal detects dot dot slash`() {
        assertTrue(PathAnalyzer.detectPathTraversal("../etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects embedded dot dot slash`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/../etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects percent-encoded dot dot slash lowercase`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/%2e%2e/etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects percent-encoded dot dot slash uppercase`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/%2E%2E/etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects mixed encoded dot dot slash`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/%2e./etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects dot percent-encoded dot slash`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/.%2e/etc/passwd"))
    }

    @Test
    fun `detectPathTraversal detects dot dot percent-encoded slash`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/%2e%2e%5c"))
    }

    @Test
    fun `detectPathTraversal detects dot dot at end of path`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/.."))
    }

    @Test
    fun `detectPathTraversal detects percent-encoded dot dot at end of path`() {
        assertTrue(PathAnalyzer.detectPathTraversal("/api/%2e%2e"))
    }

    @Test
    fun `detectPathTraversal returns false for normal api path`() {
        assertFalse(PathAnalyzer.detectPathTraversal("/api/v1/users"))
    }

    @Test
    fun `detectPathTraversal returns false for root path`() {
        assertFalse(PathAnalyzer.detectPathTraversal("/"))
    }

    @Test
    fun `detectPathTraversal returns false for empty string`() {
        assertFalse(PathAnalyzer.detectPathTraversal(""))
    }

    @Test
    fun `detectPathTraversal returns false for path with single dot`() {
        assertFalse(PathAnalyzer.detectPathTraversal("/api/./resource"))
    }

    @Test
    fun `detectPathTraversal returns false for path with dots in filenames`() {
        assertFalse(PathAnalyzer.detectPathTraversal("/api/file.name.txt"))
    }

    @Test
    fun `detectDoubleEncoding detects double-encoded slash`() {
        assertTrue(PathAnalyzer.detectDoubleEncoding("/api/%252f/resource"))
    }

    @Test
    fun `detectDoubleEncoding detects double-encoded space`() {
        assertTrue(PathAnalyzer.detectDoubleEncoding("/api/%2520/resource"))
    }

    @Test
    fun `detectDoubleEncoding detects double-encoded uppercase hex`() {
        assertTrue(PathAnalyzer.detectDoubleEncoding("/api/%253A/resource"))
    }

    @Test
    fun `detectDoubleEncoding returns false for normal path`() {
        assertFalse(PathAnalyzer.detectDoubleEncoding("/api/v1/users"))
    }

    @Test
    fun `detectDoubleEncoding returns false for single-encoded path`() {
        assertFalse(PathAnalyzer.detectDoubleEncoding("/api/%20/resource"))
    }

    @Test
    fun `detectDoubleEncoding returns false for empty string`() {
        assertFalse(PathAnalyzer.detectDoubleEncoding(""))
    }

    @Test
    fun `detectDoubleEncoding returns false for path with percent not followed by 25`() {
        assertFalse(PathAnalyzer.detectDoubleEncoding("/api/%2F/resource"))
    }

    @Test
    fun `maxSegmentEntropy returns zero for empty path`() {
        assertEquals(0.0, "".maxSegmentEntropy())
    }

    @Test
    fun `maxSegmentEntropy returns zero for root path`() {
        assertEquals(0.0, "/".maxSegmentEntropy())
    }

    @Test
    fun `maxSegmentEntropy returns low entropy for simple segments`() {
        val entropy = "/api/users".maxSegmentEntropy()
        assertTrue(entropy < 3.0, "Expected low entropy for simple segments, got $entropy")
    }

    @Test
    fun `maxSegmentEntropy returns higher entropy for random-looking segment`() {
        val entropy = "/api/a1b2c3d4e5f6g7h8i9j0k1l2m3".maxSegmentEntropy()
        assertTrue(entropy > 3.0, "Expected higher entropy for random segment, got $entropy")
    }

    @Test
    fun `maxSegmentEntropy ignores query string`() {
        val withQuery = "/api?x=a1b2c3d4e5f6g7h8i9j0k1l2m3".maxSegmentEntropy()
        val withoutQuery = "/api".maxSegmentEntropy()
        assertEquals(withoutQuery, withQuery)
    }

    @Test
    fun `maxSegmentEntropy ignores fragment`() {
        val withFragment = "/api#a1b2c3d4e5f6g7h8i9j0k1l2m3".maxSegmentEntropy()
        val withoutFragment = "/api".maxSegmentEntropy()
        assertEquals(withoutFragment, withFragment)
    }

    @Test
    fun `maxSegmentEntropy picks segment with highest entropy`() {
        val entropy = "/api/a1b2c3d4e5f6g7h8i9j0k1l2m3n4".maxSegmentEntropy()
        val simpleEntropy = "/api".maxSegmentEntropy()
        assertTrue(entropy > simpleEntropy, "Max segment entropy should reflect the high-entropy segment")
    }

    @Test
    fun `maxSegmentEntropy returns zero entropy for single repeated character segment`() {
        val entropy = "/aaaaaaa".maxSegmentEntropy()
        assertEquals(0.0, entropy)
    }
}
