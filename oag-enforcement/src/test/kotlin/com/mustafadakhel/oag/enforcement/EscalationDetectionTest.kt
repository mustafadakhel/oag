/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
}
