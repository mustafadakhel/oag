package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.enforcement.SessionRequestTracker
import com.mustafadakhel.oag.pipeline.ChainHeadKey
import com.mustafadakhel.oag.pipeline.buildTestContext
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.nio.file.Files
import java.nio.file.Path

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ChainHeadWiringTest {

    private val tempFiles = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempFiles.forEach { runCatching { Files.deleteIfExists(it) } }
    }

    private fun writePolicy(content: String): Path =
        Files.createTempFile("policy", ".yaml").also {
            tempFiles.add(it)
            Files.writeString(it, content)
        }

    private fun policyService(): PolicyService {
        val path = writePolicy(
            "version: 1\n" +
            "defaults:\n" +
            "  action: allow\n" +
            "  content_inspection:\n" +
            "    enable_builtin_patterns: true\n" +
            "allow:\n" +
            "  - id: rule_1\n" +
            "    host: \"*.example.com\"\n"
        )
        return PolicyService(path)
    }

    @Test
    fun `chain head populated in context outputs after content inspection`() {
        val tracker = SessionRequestTracker()
        val ctx = buildTestContext(bodyText = "hello world", sessionId = "s1")
        checkContentInspectionPhase(ctx, policyService(), tracker)
        val chainHead = ctx.outputs.getOrNull(ChainHeadKey)
        assertNotNull(chainHead, "chain head should be set in context outputs")
        assertEquals(64, chainHead.value.length, "chain head should be full SHA-256 hex")
    }

    @Test
    fun `chain head not populated without session id`() {
        val tracker = SessionRequestTracker()
        val ctx = buildTestContext(bodyText = "hello world", sessionId = null)
        checkContentInspectionPhase(ctx, policyService(), tracker)
        assertNull(ctx.outputs.getOrNull(ChainHeadKey))
    }

    @Test
    fun `chain head not populated without session tracker`() {
        val ctx = buildTestContext(bodyText = "hello world", sessionId = "s1")
        checkContentInspectionPhase(ctx, policyService(), sessionRequestTracker = null)
        assertNull(ctx.outputs.getOrNull(ChainHeadKey))
    }

    @Test
    fun `chain head changes across sequential requests`() {
        val tracker = SessionRequestTracker()
        val service = policyService()

        val ctx1 = buildTestContext(bodyText = "first request", sessionId = "s1")
        checkContentInspectionPhase(ctx1, service, tracker)
        val head1 = ctx1.outputs.getOrNull(ChainHeadKey)?.value

        val ctx2 = buildTestContext(bodyText = "second request", sessionId = "s1")
        checkContentInspectionPhase(ctx2, service, tracker)
        val head2 = ctx2.outputs.getOrNull(ChainHeadKey)?.value

        assertNotNull(head1)
        assertNotNull(head2)
        assertTrue(head1 != head2, "chain head should change with different body content")
    }

    @Test
    fun `chain head deterministic for same body sequence`() {
        val service = policyService()

        val tracker1 = SessionRequestTracker()
        val ctx1a = buildTestContext(bodyText = "body A", sessionId = "s1")
        checkContentInspectionPhase(ctx1a, service, tracker1)
        val ctx1b = buildTestContext(bodyText = "body B", sessionId = "s1")
        checkContentInspectionPhase(ctx1b, service, tracker1)

        val tracker2 = SessionRequestTracker()
        val ctx2a = buildTestContext(bodyText = "body A", sessionId = "s1")
        checkContentInspectionPhase(ctx2a, service, tracker2)
        val ctx2b = buildTestContext(bodyText = "body B", sessionId = "s1")
        checkContentInspectionPhase(ctx2b, service, tracker2)

        assertEquals(
            ctx1b.outputs.getOrNull(ChainHeadKey)?.value,
            ctx2b.outputs.getOrNull(ChainHeadKey)?.value,
            "same body sequence should produce same chain head"
        )
    }
}
