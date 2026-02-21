package com.mustafadakhel.oag.inspection.injection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CombinedInjectionClassifierTest {

    private fun stubClassifier(score: Double, signals: List<String>, source: String) =
        object : InjectionClassifier {
            override fun classify(content: String) = ClassificationResult(score, signals, source)
        }

    private fun failingClassifier() = object : InjectionClassifier {
        override fun classify(content: String): ClassificationResult = throw RuntimeException("ML error")
    }

    @Test
    fun `returns heuristic result when ml is null`() {
        val heuristic = stubClassifier(0.5, listOf("delimiter_injection:chatml_start"), "heuristic")
        val combined = CombinedInjectionClassifier(heuristic, ml = null)
        val result = combined.classify("test")
        assertEquals(0.5, result.score, 0.001)
        assertEquals("heuristic", result.source)
        assertEquals(listOf("delimiter_injection:chatml_start"), result.signals)
    }

    @Test
    fun `combines scores via max when ml is higher`() {
        val heuristic = stubClassifier(0.3, listOf("h:sig"), "heuristic")
        val ml = stubClassifier(0.9, listOf("ml_onnx:score=0.9000"), "ml_onnx")
        val combined = CombinedInjectionClassifier(heuristic, ml)
        val result = combined.classify("test")
        assertEquals(0.9, result.score, 0.001)
        assertEquals("combined", result.source)
        assertEquals(listOf("h:sig", "ml_onnx:score=0.9000"), result.signals)
    }

    @Test
    fun `combines scores via max when heuristic is higher`() {
        val heuristic = stubClassifier(2.5, listOf("h:sig"), "heuristic")
        val ml = stubClassifier(0.4, listOf("ml:sig"), "ml_onnx")
        val combined = CombinedInjectionClassifier(heuristic, ml)
        val result = combined.classify("test")
        assertEquals(2.5, result.score, 0.001)
        assertEquals("combined", result.source)
    }

    @Test
    fun `ALWAYS mode runs ML regardless of heuristic score`() {
        val heuristic = stubClassifier(0.0, emptyList(), "heuristic")
        val ml = stubClassifier(0.7, listOf("ml:detected"), "ml_onnx")
        val combined = CombinedInjectionClassifier(heuristic, ml, mlTriggerMode = MlTriggerMode.ALWAYS)
        val result = combined.classify("test")
        assertEquals(0.7, result.score, 0.001)
        assertEquals("combined", result.source)
        assertEquals(listOf("ml:detected"), result.signals)
    }

    @Test
    fun `UNCERTAIN_ONLY triggers ML when score in range`() {
        val heuristic = stubClassifier(0.5, listOf("h:sig"), "heuristic")
        val ml = stubClassifier(0.9, listOf("ml:sig"), "ml_onnx")
        val combined = CombinedInjectionClassifier(
            heuristic, ml,
            mlTriggerMode = MlTriggerMode.UNCERTAIN_ONLY,
            uncertainLow = 0.3,
            uncertainHigh = 0.8
        )
        val result = combined.classify("test")
        assertEquals(0.9, result.score, 0.001)
        assertEquals("combined", result.source)
    }

    @Test
    fun `UNCERTAIN_ONLY skips ML when score below range`() {
        val heuristic = stubClassifier(0.1, listOf("h:sig"), "heuristic")
        val ml = stubClassifier(0.9, listOf("ml:sig"), "ml_onnx")
        val combined = CombinedInjectionClassifier(
            heuristic, ml,
            mlTriggerMode = MlTriggerMode.UNCERTAIN_ONLY,
            uncertainLow = 0.3,
            uncertainHigh = 0.8
        )
        val result = combined.classify("test")
        assertEquals(0.1, result.score, 0.001)
        assertEquals("heuristic", result.source)
    }

    @Test
    fun `UNCERTAIN_ONLY skips ML when score above range`() {
        val heuristic = stubClassifier(2.0, listOf("h:sig"), "heuristic")
        val ml = stubClassifier(0.9, listOf("ml:sig"), "ml_onnx")
        val combined = CombinedInjectionClassifier(
            heuristic, ml,
            mlTriggerMode = MlTriggerMode.UNCERTAIN_ONLY,
            uncertainLow = 0.3,
            uncertainHigh = 0.8
        )
        val result = combined.classify("test")
        assertEquals(2.0, result.score, 0.001)
        assertEquals("heuristic", result.source)
    }

    @Test
    fun `UNCERTAIN_ONLY triggers at exact boundary low`() {
        val heuristic = stubClassifier(0.3, emptyList(), "heuristic")
        val ml = stubClassifier(0.8, listOf("ml:sig"), "ml_onnx")
        val combined = CombinedInjectionClassifier(
            heuristic, ml,
            mlTriggerMode = MlTriggerMode.UNCERTAIN_ONLY,
            uncertainLow = 0.3,
            uncertainHigh = 0.8
        )
        val result = combined.classify("test")
        assertEquals("combined", result.source)
    }

    @Test
    fun `UNCERTAIN_ONLY triggers at exact boundary high`() {
        val heuristic = stubClassifier(0.8, emptyList(), "heuristic")
        val ml = stubClassifier(0.1, emptyList(), "ml_onnx")
        val combined = CombinedInjectionClassifier(
            heuristic, ml,
            mlTriggerMode = MlTriggerMode.UNCERTAIN_ONLY,
            uncertainLow = 0.3,
            uncertainHigh = 0.8
        )
        val result = combined.classify("test")
        assertEquals("combined", result.source)
    }

    @Test
    fun `ml failure falls back to heuristic result`() {
        val heuristic = stubClassifier(0.5, listOf("h:sig"), "heuristic")
        val ml = failingClassifier()
        val combined = CombinedInjectionClassifier(heuristic, ml)
        val result = combined.classify("test")
        assertEquals(0.5, result.score, 0.001)
        assertEquals("heuristic", result.source)
    }

    @Test
    fun `merges all signals from both classifiers`() {
        val heuristic = stubClassifier(1.0, listOf("a:1", "b:2"), "heuristic")
        val ml = stubClassifier(0.8, listOf("ml:x", "ml:y"), "ml_onnx")
        val combined = CombinedInjectionClassifier(heuristic, ml)
        val result = combined.classify("test")
        assertEquals(listOf("a:1", "b:2", "ml:x", "ml:y"), result.signals)
    }

    @Test
    fun `source is combined when both run`() {
        val heuristic = stubClassifier(0.0, emptyList(), "heuristic")
        val ml = stubClassifier(0.0, emptyList(), "ml_onnx")
        val combined = CombinedInjectionClassifier(heuristic, ml)
        val result = combined.classify("test")
        assertEquals("combined", result.source)
    }

    @Test
    fun `close calls close on AutoCloseable classifiers`() {
        var heuristicClosed = false
        var mlClosed = false
        val heuristic = object : InjectionClassifier, AutoCloseable {
            override fun classify(content: String) = ClassificationResult(0.0, emptyList(), "h")
            override fun close() { heuristicClosed = true }
        }
        val ml = object : InjectionClassifier, AutoCloseable {
            override fun classify(content: String) = ClassificationResult(0.0, emptyList(), "ml")
            override fun close() { mlClosed = true }
        }
        val combined = CombinedInjectionClassifier(heuristic, ml)
        combined.close()
        assertTrue(heuristicClosed)
        assertTrue(mlClosed)
    }
}
