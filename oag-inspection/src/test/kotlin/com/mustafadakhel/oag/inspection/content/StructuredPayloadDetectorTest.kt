package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.policy.core.DetectedProtocol
import com.mustafadakhel.oag.policy.core.GraphQlOperationType

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class StructuredPayloadDetectorTest {

    @Test
    fun `detects JSON-RPC request with explicit jsonrpc field`() {
        val body = """{"jsonrpc":"2.0","method":"tools/call","id":"1"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNotNull(result)
        assertEquals(DetectedProtocol.JSON_RPC, result.protocol)
        assertEquals("tools/call", result.method)
        assertEquals("1", result.id)
    }

    @Test
    fun `returns null when method and id present without jsonrpc field`() {
        val body = """{"method":"tools/list","id":"42"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNull(result)
    }

    @Test
    fun `detects GraphQL query`() {
        val body = """{"query":"query { users { id name } }"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNotNull(result)
        assertEquals(DetectedProtocol.GRAPHQL, result.protocol)
        assertEquals(GraphQlOperationType.QUERY, result.operationType)
    }

    @Test
    fun `detects GraphQL mutation with operationName`() {
        val body = """{"query":"mutation { createUser(name: \"Alice\") { id } }","operationName":"CreateUser"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNotNull(result)
        assertEquals(DetectedProtocol.GRAPHQL, result.protocol)
        assertEquals(GraphQlOperationType.MUTATION, result.operationType)
        assertEquals("CreateUser", result.operationName)
    }

    @Test
    fun `detects GraphQL subscription`() {
        val body = """{"query":"subscription { messageAdded { content } }"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNotNull(result)
        assertEquals(DetectedProtocol.GRAPHQL, result.protocol)
        assertEquals(GraphQlOperationType.SUBSCRIPTION, result.operationType)
    }

    @Test
    fun `returns null for non-JSON body`() {
        val body = "Hello, this is plain text"
        val result = detectStructuredPayload(body, "text/plain")

        assertNull(result)
    }

    @Test
    fun `returns null for invalid JSON`() {
        val body = """{not valid json"""
        val result = detectStructuredPayload(body, "application/json")

        assertNull(result)
    }

    @Test
    fun `returns null for JSON object without RPC or GraphQL fields`() {
        val body = """{"name":"Alice","age":30}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNull(result)
    }

    @Test
    fun `detects payload when contentType contains json`() {
        val body = """{"jsonrpc":"2.0","method":"ping","id":"5"}"""
        val result = detectStructuredPayload(body, "application/vnd.api+json; charset=utf-8")

        assertNotNull(result)
        assertEquals(DetectedProtocol.JSON_RPC, result.protocol)
        assertEquals("ping", result.method)
    }

    @Test
    fun `detects payload from body starting with brace even without json content type`() {
        val body = """{"query":"query { viewer { login } }"}"""
        val result = detectStructuredPayload(body, "text/plain")

        assertNotNull(result)
        assertEquals(DetectedProtocol.GRAPHQL, result.protocol)
        assertEquals(GraphQlOperationType.QUERY, result.operationType)
    }

    @Test
    fun `returns null when contentType is null and body is not JSON`() {
        val body = "just some text"
        val result = detectStructuredPayload(body, null)

        assertNull(result)
    }

    @Test
    fun `GraphQL shorthand query starting with brace detected as query`() {
        val body = """{"query":"{ users { id } }"}"""
        val result = detectStructuredPayload(body, "application/json")

        assertNotNull(result)
        assertEquals(DetectedProtocol.GRAPHQL, result.protocol)
        assertEquals(GraphQlOperationType.QUERY, result.operationType)
    }
}
