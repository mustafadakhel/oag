package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.PipelineStage
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PipelineSkipValidationTest {

    private fun stubPhase(
        name: String,
        stage: PipelineStage = PipelineStage.POLICY,
        skipWhenPolicyDenied: Boolean = false,
        producesKeys: Set<PhaseKey<*>> = emptySet()
    ) = object : Phase {
        override val name = name
        override val stage = stage
        override val skipWhenPolicyDenied = skipWhenPolicyDenied
        override val producesKeys = producesKeys
        override suspend fun execute(context: RequestPipelineContext) {}
    }

    @Test
    fun `pipeline with skipWhenPolicyDenied after policy eval succeeds`() {
        val policyPhase = stubPhase("policy_eval", producesKeys = setOf(PolicyEvalKey))
        val rateLimit = stubPhase("rate_limit", skipWhenPolicyDenied = true)
        Pipeline("test", listOf(policyPhase, rateLimit))
    }

    @Test
    fun `pipeline with skipWhenPolicyDenied before policy eval fails`() {
        val rateLimit = stubPhase("rate_limit", skipWhenPolicyDenied = true)
        val policyPhase = stubPhase("policy_eval", producesKeys = setOf(PolicyEvalKey))
        val error = assertFailsWith<IllegalArgumentException> {
            Pipeline("test", listOf(rateLimit, policyPhase))
        }
        assertTrue(error.message!!.contains("rate_limit"))
        assertTrue(error.message!!.contains("skipWhenPolicyDenied"))
    }

    @Test
    fun `pipeline with skipWhenPolicyDenied but no policy eval phase fails`() {
        val rateLimit = stubPhase("rate_limit", skipWhenPolicyDenied = true)
        assertFailsWith<IllegalArgumentException> {
            Pipeline("test", listOf(rateLimit))
        }
    }

    @Test
    fun `pipeline without skipWhenPolicyDenied phases needs no policy eval`() {
        val phase = stubPhase("some_phase")
        Pipeline("test", listOf(phase))
    }

    @Test
    fun `pipeline with multiple skipWhenPolicyDenied phases all after policy eval succeeds`() {
        val policyPhase = stubPhase("policy_eval", producesKeys = setOf(PolicyEvalKey))
        val rate = stubPhase("rate_limit", skipWhenPolicyDenied = true)
        val agent = stubPhase("agent_profile", skipWhenPolicyDenied = true)
        Pipeline("test", listOf(policyPhase, rate, agent))
    }

    @Test
    fun `pipeline across stages with skipWhenPolicyDenied in later stage succeeds`() {
        val target = stubPhase("target", stage = PipelineStage.TARGET)
        val policyPhase = stubPhase("policy_eval", stage = PipelineStage.POLICY, producesKeys = setOf(PolicyEvalKey))
        val inspect = stubPhase("inspect", stage = PipelineStage.INSPECT, skipWhenPolicyDenied = true)
        Pipeline("test", listOf(target, policyPhase, inspect))
    }
}
