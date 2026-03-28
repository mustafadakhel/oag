package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LogprobAnalyzerTest {

    @Test
    fun `extractLogprobs parses OpenAI format`() {
        val json = """{"choices":[{"logprobs":{"content":[{"token":"Hello","logprob":-0.5},{"token":" world","logprob":-1.2}]}}]}"""
        val logprobs = LogprobAnalyzer.extractLogprobs(json)
        assertEquals(2, logprobs.size)
        assertEquals(-0.5, logprobs[0], 0.001)
        assertEquals(-1.2, logprobs[1], 0.001)
    }

    @Test
    fun `extractLogprobs handles scientific notation`() {
        val json = """{"logprob": -1.5e-2}"""
        val logprobs = LogprobAnalyzer.extractLogprobs(json)
        assertEquals(1, logprobs.size)
        assertEquals(-0.015, logprobs[0], 0.001)
    }

    @Test
    fun `extractLogprobs returns empty for no logprobs`() {
        val json = """{"choices":[{"message":{"content":"Hello"}}]}"""
        val logprobs = LogprobAnalyzer.extractLogprobs(json)
        assertTrue(logprobs.isEmpty())
    }

    @Test
    fun `analyze returns null when no logprobs present`() {
        val result = LogprobAnalyzer.analyze("""{"content": "no logprobs here"}""")
        assertNull(result)
    }

    @Test
    fun `analyze computes mean and min`() {
        val json = """{"logprob": -1.0} {"logprob": -3.0} {"logprob": -2.0}"""
        val result = LogprobAnalyzer.analyze(json)
        assertNotNull(result)
        assertEquals(-2.0, result.meanLogprob, 0.001)
        assertEquals(-3.0, result.minLogprob, 0.001)
        assertEquals(3, result.tokenCount)
    }

    @Test
    fun `mapToScore returns 0 for perfect confidence`() {
        assertEquals(0.0, LogprobAnalyzer.mapToScore(0.0), 0.001)
    }

    @Test
    fun `mapToScore increases for lower logprobs`() {
        val scoreLow = LogprobAnalyzer.mapToScore(-1.0)
        val scoreMid = LogprobAnalyzer.mapToScore(-3.0)
        val scoreHigh = LogprobAnalyzer.mapToScore(-5.0)
        assertTrue(scoreLow < scoreMid)
        assertTrue(scoreMid < scoreHigh)
        assertTrue(scoreHigh <= 1.0)
    }

    @Test
    fun `mapToScore stays in range`() {
        assertTrue(LogprobAnalyzer.mapToScore(-100.0) <= 1.0)
        assertTrue(LogprobAnalyzer.mapToScore(-100.0) >= 0.0)
        assertTrue(LogprobAnalyzer.mapToScore(1.0) == 0.0)
    }

    @Test
    fun `step skips logprob analysis when not present in response`() {
        val step = HallucinationCheckStep(
            PolicyHallucinationCheck(enabled = true, logprobAnalysis = true)
        )
        val ctx = BufferedInspectionContext(
            statusCode = 200, contentType = "application/json",
            matchedRule = null, onError = {}
        )
        step.inspect("""{"content": "no logprobs"}""", ctx)
        assertTrue(ctx.accumulator.hallucinationSignals?.none { it.name == "logprob_analysis" } == true)
    }

    @Test
    fun `step produces logprob signal when logprobs present`() {
        val step = HallucinationCheckStep(
            PolicyHallucinationCheck(enabled = true, logprobAnalysis = true)
        )
        val ctx = BufferedInspectionContext(
            statusCode = 200, contentType = "application/json",
            matchedRule = null, onError = {}
        )
        val body = """{"choices":[{"logprobs":{"content":[{"token":"x","logprob":-2.0},{"token":"y","logprob":-3.0}]}}]}"""
        step.inspect(body, ctx)
        val signal = ctx.accumulator.hallucinationSignals?.find { it.name == "logprob_analysis" }
        assertNotNull(signal)
        assertTrue(signal.score > 0.0)
    }

    @Test
    fun `different provider formats extract logprobs`() {
        // Anthropic-style (hypothetical future format)
        val anthropic = """{"logprob": -0.8, "logprob": -1.5}"""
        val logprobs = LogprobAnalyzer.extractLogprobs(anthropic)
        assertEquals(2, logprobs.size)
    }
}
