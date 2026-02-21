package com.mustafadakhel.oag.pipeline.inspection

import com.mustafadakhel.oag.inspection.injection.ClassificationResult
import com.mustafadakhel.oag.inspection.injection.InjectionClassifier
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyInjectionScoring
import com.mustafadakhel.oag.policy.core.InjectionScoringMode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ContentInspectorMlTest {

    private val scoringConfig = PolicyInjectionScoring(
        mode = InjectionScoringMode.SCORE,
        denyThreshold = 0.9
    )

    @Test
    fun `ml classifier score is used when provided`() {
        val mlClassifier = InjectionClassifier { _ ->
            ClassificationResult(score = 0.95, signals = listOf("ml:test"), source = "test-ml")
        }
        val inspection = PolicyContentInspection(enableBuiltinPatterns = true)

        val result = checkContentInspectionScored("hello world", inspection, scoringConfig, mlClassifier)

        assertTrue(result.injectionScore!! >= 0.95)
        assertTrue(result.injectionSignals?.any { it == "ml:test" } == true)
        assertNotNull(result.decision)
    }

    @Test
    fun `ml classifier null falls back to heuristic only`() {
        val inspection = PolicyContentInspection(enableBuiltinPatterns = true)

        val result = checkContentInspectionScored("hello world", inspection, scoringConfig, null)

        assertNotNull(result.injectionScore)
        assertTrue(result.injectionScore!! < 0.9)
    }

    @Test
    fun `ml classifier failure is handled gracefully`() {
        val failingClassifier = InjectionClassifier { _ ->
            throw RuntimeException("model load failed")
        }
        val inspection = PolicyContentInspection(enableBuiltinPatterns = true)

        val result = checkContentInspectionScored("hello world", inspection, scoringConfig, failingClassifier)

        assertNotNull(result.injectionScore)
    }
}
