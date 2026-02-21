package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.http.isIpLiteralHost
import com.mustafadakhel.oag.http.parseAbsoluteTarget
import com.mustafadakhel.oag.http.parseAuthorityTarget

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class TargetParserTest {
    @Test
    fun `parse absolute-form with query`() {
        val target = parseAbsoluteTarget("https://api.example.com/v1/models?x=1")
        assertEquals("https", target.scheme)
        assertEquals("api.example.com", target.host)
        assertEquals(443, target.port)
        assertEquals("/v1/models?x=1", target.path)
    }

    @Test
    fun `parse authority-form ipv6`() {
        val target = parseAuthorityTarget("[::1]:443")
        assertEquals("https", target.scheme)
        assertEquals("::1", target.host)
        assertEquals(443, target.port)
    }

    @Test
    fun `parse authority-form rejects bracketed non ipv6 host`() {
        assertFailsWith<IllegalArgumentException> {
            parseAuthorityTarget("[api.example.com]:443")
        }
    }

    @Test
    fun `parse authority-form rejects ipv6 zone identifier`() {
        assertFailsWith<IllegalArgumentException> {
            parseAuthorityTarget("[fe80::1%eth0]:443")
        }
    }

    @Test
    fun `parse authority-form rejects userinfo`() {
        assertFailsWith<IllegalArgumentException> {
            parseAuthorityTarget("user@api.example.com:443")
        }
    }

    @Test
    fun `parse authority-form rejects host with path`() {
        assertFailsWith<IllegalArgumentException> {
            parseAuthorityTarget("api.example.com/path:443")
        }
    }

    @Test
    fun `parse authority-form rejects host with query`() {
        assertFailsWith<IllegalArgumentException> {
            parseAuthorityTarget("api.example.com?x=1:443")
        }
    }

    @Test
    fun `ip literal detection handles ipv4 and ipv6`() {
        assertTrue(isIpLiteralHost("127.0.0.1"))
        assertTrue(isIpLiteralHost("::1"))
        assertFalse(isIpLiteralHost("api.example.com"))
    }

    @Test
    fun `parse absolute-form rejects unsupported scheme`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("ftp://api.example.com/resource")
        }
    }

    @Test
    fun `parse absolute-form rejects invalid port`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://api.example.com:0/v1/models")
        }
    }

    @Test
    fun `parse absolute-form rejects userinfo`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://user:pass@api.example.com/v1/models")
        }
    }

    @Test
    fun `parse absolute-form rejects fragment`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://api.example.com/v1/models#fragment")
        }
    }

    @Test
    fun `parse absolute-form rejects ipv6 zone identifier`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://[fe80::1%25eth0]/v1/models")
        }
    }

    @Test
    fun `parse absolute-form rejects whitespace in path`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://api.example.com/v1/ bad")
        }
    }

    @Test
    fun `parse absolute-form rejects backslash in path`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://api.example.com/v1\\bad")
        }
    }

    @Test
    fun `parse absolute-form rejects host starting with dot`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://.example.com/v1/models")
        }
    }

    @Test
    fun `parse absolute-form rejects host with consecutive dots`() {
        assertFailsWith<IllegalArgumentException> {
            parseAbsoluteTarget("https://api..example.com/v1/models")
        }
    }

    @Test
    fun `parse absolute-form allows trailing dot in host`() {
        val target = parseAbsoluteTarget("https://api.example.com./v1/models")
        assertEquals("api.example.com.", target.host)
    }
}
