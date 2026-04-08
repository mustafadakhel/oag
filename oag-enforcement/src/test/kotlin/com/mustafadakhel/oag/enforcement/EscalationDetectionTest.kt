package com.mustafadakhel.oag.enforcement

import com.mustafadakhel.oag.EscalationPattern

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class EscalationDetectionTest {

    private fun turns(vararg scores: Double) =
        scores.mapIndexed { i, s -> ScoredTurn(turnIndex = i.toLong() + 1, score = s) }

    private val sustainedConfig = EscalationConfig(
        enabled = true,
        windowSize = 3,
        denyPatterns = setOf(EscalationPattern.SUSTAINED_ELEVATION)
    )

    private val crescendoConfig = EscalationConfig(
        enabled = true,
        windowSize = 3,
        denyPatterns = setOf(EscalationPattern.CRESCENDO)
    )

    private val bothConfig = EscalationConfig(
        enabled = true,
        windowSize = 3,
        denyPatterns = setOf(EscalationPattern.SUSTAINED_ELEVATION, EscalationPattern.CRESCENDO)
    )

    @Test
    fun `sustained elevation detected when all scores above threshold`() {
        val result = detectEscalationPatterns(turns(0.5, 0.6, 0.7), sustainedConfig)
        assertTrue(result.detected)
        assertEquals(EscalationPattern.SUSTAINED_ELEVATION, result.pattern)
    }

    @Test
    fun `sustained elevation not detected when some scores below threshold`() {
        val result = detectEscalationPatterns(turns(0.1, 0.6, 0.7), sustainedConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `crescendo detected when scores strictly increase`() {
        val result = detectEscalationPatterns(turns(0.3, 0.5, 0.7), crescendoConfig)
        assertTrue(result.detected)
        assertEquals(EscalationPattern.CRESCENDO, result.pattern)
    }

    @Test
    fun `crescendo not detected when scores flat`() {
        val result = detectEscalationPatterns(turns(0.5, 0.5, 0.5), crescendoConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `crescendo not detected when scores decrease`() {
        val result = detectEscalationPatterns(turns(0.7, 0.5, 0.3), crescendoConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `not detected when disabled`() {
        val config = EscalationConfig(enabled = false, windowSize = 3, denyPatterns = setOf(EscalationPattern.CRESCENDO))
        val result = detectEscalationPatterns(turns(0.3, 0.5, 0.7), config)
        assertFalse(result.detected)
    }

    @Test
    fun `not detected when window too small`() {
        val result = detectEscalationPatterns(turns(0.5, 0.7), sustainedConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `pattern orchestration checks all deny patterns`() {
        val result = detectEscalationPatterns(turns(0.3, 0.5, 0.7), bothConfig)
        assertTrue(result.detected)
    }

    @Test
    fun `window uses last N turns only`() {
        val config = EscalationConfig(enabled = true, windowSize = 3, denyPatterns = setOf(EscalationPattern.CRESCENDO))
        val result = detectEscalationPatterns(turns(0.9, 0.1, 0.3, 0.5, 0.7), config)
        assertTrue(result.detected)
        assertEquals(3, result.windowScores.size)
    }

    @Test
    fun `result contains window scores and size`() {
        val result = detectEscalationPatterns(turns(0.4, 0.5, 0.6), sustainedConfig)
        assertEquals(3, result.windowScores.size)
        assertEquals(3, result.windowSize)
    }

    @Test
    fun `no pattern when no denyPatterns configured`() {
        val config = EscalationConfig(enabled = true, windowSize = 3, denyPatterns = emptySet())
        val result = detectEscalationPatterns(turns(0.3, 0.5, 0.7), config)
        assertFalse(result.detected)
        assertNull(result.pattern)
    }

    // --- SAW_TOOTH_PROBING ---

    private fun turnsAt(vararg pairs: Pair<Long, Double>) =
        pairs.map { (idx, score) -> ScoredTurn(turnIndex = idx, score = score) }

    private val sawToothConfig = EscalationConfig(
        enabled = true,
        windowSize = 3,
        denyPatterns = setOf(EscalationPattern.SAW_TOOTH_PROBING)
    )

    private val periodicConfig = EscalationConfig(
        enabled = true,
        windowSize = 7,
        denyPatterns = setOf(EscalationPattern.PERIODIC_TESTING)
    )

    @Test
    fun `saw tooth detected with high-low-high pattern`() {
        val result = detectEscalationPatterns(turns(0.5, 0.1, 0.5), sawToothConfig)
        assertTrue(result.detected)
        assertEquals(EscalationPattern.SAW_TOOTH_PROBING, result.pattern)
    }

    @Test
    fun `saw tooth detected with longer oscillation`() {
        val config = sawToothConfig.copy(windowSize = 5)
        val result = detectEscalationPatterns(turns(0.5, 0.1, 0.5, 0.1, 0.5), config)
        assertTrue(result.detected)
        assertEquals(EscalationPattern.SAW_TOOTH_PROBING, result.pattern)
    }

    @Test
    fun `saw tooth not detected when all high`() {
        val result = detectEscalationPatterns(turns(0.5, 0.6, 0.7), sawToothConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `saw tooth not detected when all low`() {
        val result = detectEscalationPatterns(turns(0.1, 0.2, 0.1), sawToothConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `saw tooth not detected with only one above threshold`() {
        val result = detectEscalationPatterns(turns(0.5, 0.1, 0.1), sawToothConfig)
        assertFalse(result.detected)
    }

    @Test
    fun `saw tooth not detected with fewer than 3 scores`() {
        val config = sawToothConfig.copy(windowSize = 2)
        val result = detectEscalationPatterns(turns(0.5, 0.1), config)
        assertFalse(result.detected)
    }

    @Test
    fun `saw tooth not detected when scores are exactly at threshold`() {
        val result = detectEscalationPatterns(turns(0.3, 0.1, 0.3), sawToothConfig)
        assertFalse(result.detected)
    }

    // --- PERIODIC_TESTING ---

    @Test
    fun `periodic testing detected at regular intervals`() {
        val result = detectEscalationPatterns(
            turnsAt(1L to 0.5, 2L to 0.1, 3L to 0.1, 4L to 0.5, 5L to 0.1, 6L to 0.1, 7L to 0.5),
            periodicConfig
        )
        assertTrue(result.detected)
        assertEquals(EscalationPattern.PERIODIC_TESTING, result.pattern)
    }

    @Test
    fun `periodic testing not detected with irregular intervals`() {
        val config = periodicConfig.copy(windowSize = 3)
        val result = detectEscalationPatterns(
            turnsAt(1L to 0.5, 5L to 0.5, 6L to 0.5),
            config
        )
        assertFalse(result.detected)
    }

    @Test
    fun `periodic testing not detected with fewer than 3 high turns`() {
        val config = periodicConfig.copy(windowSize = 3)
        val result = detectEscalationPatterns(
            turnsAt(1L to 0.5, 4L to 0.5, 5L to 0.1),
            config
        )
        assertFalse(result.detected)
    }

    @Test
    fun `periodic testing not detected when interval is 1`() {
        val config = periodicConfig.copy(windowSize = 3)
        val result = detectEscalationPatterns(
            turnsAt(1L to 0.5, 2L to 0.5, 3L to 0.5),
            config
        )
        assertFalse(result.detected)
    }

    @Test
    fun `periodic testing detected at minimum interval boundary`() {
        // Mean interval exactly 2.0 (= MIN_PERIODIC_INTERVAL) should fire
        val config = periodicConfig.copy(windowSize = 5)
        val result = detectEscalationPatterns(
            turnsAt(1L to 0.5, 2L to 0.1, 3L to 0.5, 4L to 0.1, 5L to 0.5),
            config
        )
        assertTrue(result.detected)
        assertEquals(EscalationPattern.PERIODIC_TESTING, result.pattern)
    }
}
