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

package com.mustafadakhel.oag.pipeline.relay

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ImpossibleClaimMatcherTest {

    @Test
    fun `loadDefault loads built-in patterns`() {
        val matcher = ImpossibleClaimMatcher.loadDefault()
        val matches = matcher.match("Python 4.0 is now available")
        assertTrue(matches.isNotEmpty())
        assertEquals("versions", matches.first().category)
    }

    @Test
    fun `contains pattern matches substring`() {
        val yaml = """
            test:
              contains:
                - "nonexistent thing"
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val matches = matcher.match("The nonexistent thing was found")
        assertEquals(1, matches.size)
        assertEquals("test", matches[0].category)
        assertEquals("nonexistent thing", matches[0].pattern)
    }

    @Test
    fun `regex pattern matches anchored pattern`() {
        val yaml = """
            test:
              regex:
                - "Python 3\\.1[5-9]\\."
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val matches = matcher.match("Use Python 3.17.2 for best results")
        assertEquals(1, matches.size)
        assertEquals("test", matches[0].category)
    }

    @Test
    fun `no match returns empty list`() {
        val yaml = """
            test:
              contains:
                - "nonexistent thing"
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val matches = matcher.match("Everything is normal here")
        assertTrue(matches.isEmpty())
    }

    @Test
    fun `multiple categories matched`() {
        val yaml = """
            versions:
              contains:
                - "Python 4."
            models:
              contains:
                - "GPT-6"
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val matches = matcher.match("Python 4.0 works with GPT-6")
        assertEquals(2, matches.size)
        val categories = matches.map { it.category }.toSet()
        assertTrue("versions" in categories)
        assertTrue("models" in categories)
    }

    @Test
    fun `hypothetical context does not affect matching`() {
        val matcher = ImpossibleClaimMatcher.loadDefault()
        val matches = matcher.match("If Python 4.0 existed, it would be great")
        assertTrue(matches.isNotEmpty(), "Pattern matching is substring-based, not context-aware")
    }

    @Test
    fun `custom file loading works`() {
        val yaml = """
            custom:
              contains:
                - "custom pattern one"
                - "custom pattern two"
              regex:
                - "custom-\\d+"
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        assertEquals(1, matcher.match("found custom pattern one here").size)
        assertEquals(1, matcher.match("found custom pattern two here").size)
        assertEquals(1, matcher.match("id: custom-42").size)
        assertTrue(matcher.match("nothing here").isEmpty())
    }

    @Test
    fun `parseClaimsYaml handles all categories`() {
        val yaml = """
            cat1:
              contains:
                - "a"
                - "b"
              regex:
                - "c\\d+"
            cat2:
              contains:
                - "d"
        """.trimIndent()
        val result = parseClaimsYaml(yaml)
        assertEquals(2, result.size)
        assertEquals(listOf("a", "b"), result["cat1"]?.contains)
        assertEquals(listOf("c\\d+"), result["cat1"]?.regex)
        assertEquals(listOf("d"), result["cat2"]?.contains)
        assertTrue(result["cat2"]?.regex?.isEmpty() == true)
    }

    @Test
    fun `step with claim matcher produces signals`() {
        val yaml = """
            versions:
              contains:
                - "Python 4."
        """.trimIndent()
        val matcher = ImpossibleClaimMatcher.load(yaml)
        val step = HallucinationCheckStep(
            com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck(enabled = true),
            claimMatcher = matcher
        )
        val ctx = BufferedInspectionContext(
            statusCode = 200, contentType = "application/json",
            matchedRule = null, onError = {}
        )
        step.inspect("Python 4.1 is out", ctx)
        assertNotNull(ctx.accumulator.hallucinationScore)
        assertTrue(ctx.accumulator.hallucinationSignals?.isNotEmpty() == true)
        assertEquals(
            HallucinationCheckStep.SIGNAL_IMPOSSIBLE_CLAIMS,
            ctx.accumulator.hallucinationSignals?.first()?.name
        )
    }
}
