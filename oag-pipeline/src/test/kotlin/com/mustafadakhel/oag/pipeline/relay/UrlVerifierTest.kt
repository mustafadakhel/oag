package com.mustafadakhel.oag.pipeline.relay

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class UrlVerifierTest {

    @Test
    fun `extractUrls extracts http and https URLs`() {
        val text = "Visit https://example.com/path and http://other.org/page for details."
        val urls = extractUrls(text)
        assertEquals(2, urls.size)
        assertTrue("https://example.com/path" in urls)
        assertTrue("http://other.org/page" in urls)
    }

    @Test
    fun `extractUrls trims trailing punctuation`() {
        val text = "See https://example.com/path."
        val urls = extractUrls(text)
        assertEquals(1, urls.size)
        assertEquals("https://example.com/path", urls[0])
    }

    @Test
    fun `extractUrls deduplicates`() {
        val text = "https://example.com/a and https://example.com/a again"
        val urls = extractUrls(text)
        assertEquals(1, urls.size)
    }

    @Test
    fun `extractUrls filters short URLs`() {
        val text = "https://x.xx is too short"
        val urls = extractUrls(text)
        assertTrue(urls.isEmpty())
    }

    @Test
    fun `extractUrls limits count`() {
        val text = (1..30).joinToString(" ") { "https://example.com/page$it" }
        val urls = extractUrls(text)
        assertEquals(20, urls.size)
    }

    @Test
    fun `extractUrls handles URLs in markdown`() {
        val text = "Check [link](https://example.com/docs) for info"
        val urls = extractUrls(text)
        assertEquals(1, urls.size)
        assertEquals("https://example.com/docs", urls[0])
    }

    @Test
    fun `extractUrls handles URLs with query params`() {
        val text = "Visit https://example.com/search?q=test&page=1 for results"
        val urls = extractUrls(text)
        assertEquals(1, urls.size)
        assertTrue(urls[0].contains("q=test"))
    }

    @Test
    fun `SSRF prevention - private IPs rejected by SafeOutboundClient`() {
        val client = com.mustafadakhel.oag.SafeOutboundClient()
        val verifier = UrlVerifier(client)
        val results = verifier.verify(listOf("http://127.0.0.1/admin"))
        assertEquals(1, results.size)
        assertEquals(UrlStatus.BLOCKED, results[0].status)
    }

    @Test
    fun `allowlist skips verification for listed domains`() {
        val client = com.mustafadakhel.oag.SafeOutboundClient()
        val verifier = UrlVerifier(client, allowlist = setOf("example.com"))
        val results = verifier.verify(listOf("https://example.com/page"))
        assertTrue(results.isEmpty(), "Allowlisted domain should be skipped")
    }

    @Test
    fun `NXDOMAIN returns unreachable`() {
        val client = com.mustafadakhel.oag.SafeOutboundClient()
        val verifier = UrlVerifier(client)
        val results = verifier.verify(listOf("https://this-domain-does-not-exist-oag-test.invalid/path"))
        assertEquals(1, results.size)
        assertEquals(UrlStatus.UNREACHABLE, results[0].status)
    }
}
