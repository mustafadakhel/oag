package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyRequest
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ScopeMatchingTest {

    private fun request(
        host: String = "api.example.com",
        method: String = "POST",
        path: String = "/v1/chat",
        scheme: String = "https",
        port: Int = 443
    ) = PolicyRequest(scheme = scheme, host = host, port = port, method = method, path = path)

    @Test
    fun `null fields match all requests`() {
        assertTrue(scopeMatchesRequest(null, null, null, null, request()))
    }

    @Test
    fun `single host matches exact host`() {
        assertTrue(scopeMatchesRequest(listOf("api.example.com"), null, null, null, request()))
    }

    @Test
    fun `single host does not match different host`() {
        assertFalse(scopeMatchesRequest(listOf("other.com"), null, null, null, request()))
    }

    @Test
    fun `multiple hosts match if any matches`() {
        assertTrue(scopeMatchesRequest(listOf("other.com", "api.example.com"), null, null, null, request()))
    }

    @Test
    fun `wildcard host matches subdomain`() {
        assertTrue(scopeMatchesRequest(listOf("*.example.com"), null, null, null, request()))
    }

    @Test
    fun `method matching is case insensitive`() {
        assertTrue(scopeMatchesRequest(null, listOf("post"), null, null, request()))
        assertTrue(scopeMatchesRequest(null, listOf("POST"), null, null, request()))
    }

    @Test
    fun `method mismatch denies`() {
        assertFalse(scopeMatchesRequest(null, listOf("GET"), null, null, request()))
    }

    @Test
    fun `path glob matching`() {
        assertTrue(scopeMatchesRequest(null, null, listOf("/v1/*"), null, request()))
        assertFalse(scopeMatchesRequest(null, null, listOf("/v2/*"), null, request()))
    }

    @Test
    fun `exact path matching`() {
        assertTrue(scopeMatchesRequest(null, null, listOf("/v1/chat"), null, request()))
    }

    @Test
    fun `CIDR range matches IP literal host`() {
        val ipRequest = request(host = "10.0.0.5")
        assertTrue(scopeMatchesRequest(null, null, null, listOf("10.0.0.0/8"), ipRequest))
    }

    @Test
    fun `CIDR range does not match hostname`() {
        assertFalse(scopeMatchesRequest(null, null, null, listOf("10.0.0.0/8"), request()))
    }

    @Test
    fun `all fields must match together`() {
        assertTrue(scopeMatchesRequest(
            listOf("api.example.com"), listOf("POST"), listOf("/v1/*"), null,
            request()
        ))
        assertFalse(scopeMatchesRequest(
            listOf("api.example.com"), listOf("GET"), listOf("/v1/*"), null,
            request()
        ))
    }

    @Test
    fun `empty host list matches all`() {
        assertTrue(scopeMatchesRequest(emptyList(), null, null, null, request()))
    }
}
