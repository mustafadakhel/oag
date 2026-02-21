package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.http.HttpRequest
import com.mustafadakhel.oag.http.ParsedTarget
import com.mustafadakhel.oag.pipeline.HostResolver
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.NetworkConfig
import com.mustafadakhel.oag.policy.core.PolicyAction
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import kotlinx.coroutines.test.runTest

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.net.InetAddress
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DryRunResponseRelayTest {

    private val tempFiles = mutableListOf<Path>()

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private fun policyService(): PolicyService {
        val path = writePolicy("version: 1\ndefaults:\n  action: allow\n")
        return PolicyService(path)
    }

    private val hostResolver = HostResolver { listOf(InetAddress.getLoopbackAddress()) }
    private val target = ParsedTarget(scheme = "https", host = "api.example.com", port = 443, path = "/api")
    private val request = HttpRequest(method = "GET", target = "https://api.example.com/api", version = "HTTP/1.1", headers = mapOf("host" to "api.example.com"))

    private fun buildUpstreamResponse(body: String): ByteArray {
        val response = "HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\n\r\n$body"
        return response.toByteArray(Charsets.US_ASCII)
    }

    @Test
    fun `dry-run relays response body even when inspection chain denies`() = runTest {
        val responseBody = """{"unexpected":"data"}"""
        val relayer = ResponseRelayer(
            policyService = policyService(),
            hostResolver = hostResolver,
            networkConfig = NetworkConfig(),
            dryRun = true
        )
        val rule = PolicyRule(
            id = "test",
            host = "api.example.com",
            responseBodyMatch = PolicyBodyMatch(contains = listOf("expected_token"))
        )
        val clientOutput = ByteArrayOutputStream()
        val upstreamIn = ByteArrayInputStream(buildUpstreamResponse(responseBody))

        val result = relayer.relay(
            upstreamIn = upstreamIn,
            clientOutput = clientOutput,
            request = request,
            requestTarget = target,
            matchedRule = rule
        )

        // Body was relayed to client despite inspection chain denying
        val clientResponse = clientOutput.toString(Charsets.US_ASCII)
        assertTrue(clientResponse.contains("200 OK"), "Response should be 200 in dry-run, got: $clientResponse")
        assertTrue(clientResponse.contains(responseBody), "Body should be relayed in dry-run")

        // Decision override recorded for audit
        val override = result.decisionOverride
        assertNotNull(override, "decisionOverride should be set")
        assertEquals(PolicyAction.DENY, override.action)
        assertEquals(ReasonCode.RESPONSE_INJECTION_DETECTED, override.reasonCode)

        // Bytes were relayed (not zero)
        assertTrue(result.bytesIn > 0, "bytesIn should be > 0 in dry-run")
    }

    @Test
    fun `non-dry-run writes 403 when inspection chain denies`() = runTest {
        val responseBody = """{"unexpected":"data"}"""
        val relayer = ResponseRelayer(
            policyService = policyService(),
            hostResolver = hostResolver,
            networkConfig = NetworkConfig(),
            dryRun = false
        )
        val rule = PolicyRule(
            id = "test",
            host = "api.example.com",
            responseBodyMatch = PolicyBodyMatch(contains = listOf("expected_token"))
        )
        val clientOutput = ByteArrayOutputStream()
        val upstreamIn = ByteArrayInputStream(buildUpstreamResponse(responseBody))

        val result = relayer.relay(
            upstreamIn = upstreamIn,
            clientOutput = clientOutput,
            request = request,
            requestTarget = target,
            matchedRule = rule
        )

        // 403 written to client
        val clientResponse = clientOutput.toString(Charsets.US_ASCII)
        assertTrue(clientResponse.contains("403"), "Response should be 403, got: $clientResponse")

        // Decision override set
        assertNotNull(result.decisionOverride)
        assertEquals(PolicyAction.DENY, result.decisionOverride!!.action)

        // No body relayed
        assertEquals(0L, result.bytesIn)
        assertEquals(HttpStatus.FORBIDDEN.code, result.statusCode)
    }
}
