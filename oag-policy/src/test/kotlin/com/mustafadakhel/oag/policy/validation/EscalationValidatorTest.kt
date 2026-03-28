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

package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyEscalation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class EscalationValidatorTest {

    private fun validate(config: PolicyEscalation) = config.validate("test")

    @Test
    fun `window size below 3 fails`() {
        val errors = validate(PolicyEscalation(windowSize = 2))
        assertTrue(errors.any { "window_size" in it.path && "at least 3" in it.message })
    }

    @Test
    fun `window size above 100 fails`() {
        val errors = validate(PolicyEscalation(windowSize = 101))
        assertTrue(errors.any { "window_size" in it.path && "100" in it.message })
    }

    @Test
    fun `window size 5 passes`() {
        val errors = validate(PolicyEscalation(windowSize = 5))
        assertTrue(errors.none { "window_size" in it.path })
    }

    @Test
    fun `unknown pattern fails`() {
        val errors = validate(PolicyEscalation(denyPatterns = listOf("unknown_pattern")))
        assertTrue(errors.any { "deny_patterns[0]" in it.path && "Unknown" in it.message })
    }

    @Test
    fun `valid pattern sustained_elevation passes`() {
        val errors = validate(PolicyEscalation(denyPatterns = listOf("sustained_elevation")))
        assertTrue(errors.none { "deny_patterns" in it.path })
    }

    @Test
    fun `valid pattern crescendo passes`() {
        val errors = validate(PolicyEscalation(denyPatterns = listOf("crescendo")))
        assertTrue(errors.none { "deny_patterns" in it.path })
    }

    @Test
    fun `valid config produces no errors`() {
        val errors = validate(PolicyEscalation(
            enabled = true,
            windowSize = 5,
            denyPatterns = listOf("sustained_elevation", "crescendo")
        ))
        assertEquals(emptyList(), errors)
    }
}
