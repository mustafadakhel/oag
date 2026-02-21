package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.proxy.http.parseHttpRequest

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

import java.io.ByteArrayInputStream

class HttpParserTest {
    

    @Test
    fun `parse accepts request line with repeated whitespace`() {
        val raw = """
            GET   http://api.example.com/v1/models   HTTP/1.1
            Host: ignored
            
            
        """.trimIndent().replace("\n", "\r\n")

        val parsed = parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))

        assertEquals("GET", parsed.method)
        assertEquals("http://api.example.com/v1/models", parsed.target)
        assertEquals("HTTP/1.1", parsed.version)
    }

    @Test
    fun `parse rejects malformed request line with fewer than 3 parts`() {
        val raw = """
            GET /v1/models
            Host: ignored
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects request line with extra trailing tokens`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1 extra
            Host: ignored
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects unsupported http version`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/2
            Host: ignored
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects invalid http method token`() {
        val raw = """
            GE T http://api.example.com/v1/models HTTP/1.1
            Host: ignored
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects request line that exceeds limit`() {
        val longTarget = "/" + "a".repeat(9000)
        val raw = "GET $longTarget HTTP/1.1\r\nHost: ignored\r\n\r\n"

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects requests with too many header lines`() {
        val headers = buildString {
            repeat(300) { index ->
                append("X-$index: value\r\n")
            }
        }
        val raw = "GET http://api.example.com/v1/models HTTP/1.1\r\n$headers\r\n"

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects malformed header line`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            BrokenHeaderLine
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects header line with leading whitespace`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
             Host: api.example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects blank header name`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
             : value
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects invalid header name token`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            X Header: value
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects header value with control character`() {
        val raw = "GET http://api.example.com/v1/models HTTP/1.1\r\nHost: api.example.com\r\nX-Test: ok\u0001bad\r\n\r\n"

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects header value with DEL character`() {
        val raw = "GET http://api.example.com/v1/models HTTP/1.1\r\nHost: api.example.com\r\nX-Test: ok\u007Fbad\r\n\r\n"

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse accepts header value with obs-text characters`() {
        val raw = "GET http://api.example.com/v1/models HTTP/1.1\r\nHost: api.example.com\r\nX-Test: caf\u00E9\r\n\r\n"

        val request = parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.ISO_8859_1)))
        assertEquals("caf\u00E9", request.headers["x-test"])
    }

    @Test
    fun `parse rejects duplicate content length header`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Content-Length: 4
            Content-Length: 4
            
            body
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects duplicate transfer encoding header`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Transfer-Encoding: chunked
            Transfer-Encoding: chunked
            
            0
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects duplicate host header`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Host: api.example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects host header with whitespace`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects host header with userinfo`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: user@api.example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects host header starting with dot`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: .example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects host header with consecutive dots`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api..example.com
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects host header with invalid port`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com:99999
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse accepts host header with valid port`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com:8443
            
            
        """.trimIndent().replace("\n", "\r\n")

        val parsed = parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        assertEquals("api.example.com:8443", parsed.headers["host"])
    }

    @Test
    fun `parse rejects host header with extra colon`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com:443:1
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects unbracketed ipv6 host header`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            Host: 2001:db8::1
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects http11 request without host header`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.1
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse allows http10 request without host header`() {
        val raw = """
            GET http://api.example.com/v1/models HTTP/1.0
            
            
        """.trimIndent().replace("\n", "\r\n")

        val parsed = parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        assertEquals("HTTP/1.0", parsed.version)
    }

    @Test
    fun `parse rejects conflicting content length and transfer encoding`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Content-Length: 4
            Transfer-Encoding: chunked
            
            body
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects negative content length`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Content-Length: -1
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects non numeric content length`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Content-Length: abc
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }

    @Test
    fun `parse rejects content length that overflows long`() {
        val raw = """
            POST http://api.example.com/v1/models HTTP/1.1
            Host: api.example.com
            Content-Length: 999999999999999999999999999999
            
            
        """.trimIndent().replace("\n", "\r\n")

        assertFailsWith<IllegalArgumentException> {
            parseHttpRequest(ByteArrayInputStream(raw.toByteArray(Charsets.US_ASCII)))
        }
    }
}
