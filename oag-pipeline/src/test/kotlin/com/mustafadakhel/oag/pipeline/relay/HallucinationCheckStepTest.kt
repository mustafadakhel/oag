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

import com.mustafadakhel.oag.policy.core.HallucinationMode
import com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class HallucinationCheckStepTest {

    private fun context() = BufferedInspectionContext(
        statusCode = 200,
        contentType = "application/json",
        matchedRule = null,
        onError = {}
    )

    @Test
    fun `step returns Continue with unmodified body`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        val outcome = step.inspect("response body", ctx)
        assertIs<StepOutcome.Continue>(outcome)
        assertEquals("response body", outcome.bodyText)
    }

    @Test
    fun `step writes default observe mode to accumulator`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        step.inspect("body", ctx)
        assertEquals("observe", ctx.accumulator.hallucinationMode)
    }

    @Test
    fun `step writes explicit enforce mode to accumulator`() {
        val step = HallucinationCheckStep(
            PolicyHallucinationCheck(enabled = true, mode = HallucinationMode.ENFORCE)
        )
        val ctx = context()
        step.inspect("body", ctx)
        assertEquals("enforce", ctx.accumulator.hallucinationMode)
    }

    @Test
    fun `step writes empty signals to accumulator`() {
        val step = HallucinationCheckStep(PolicyHallucinationCheck(enabled = true))
        val ctx = context()
        step.inspect("body", ctx)
        assertNotNull(ctx.accumulator.hallucinationSignals)
        assertEquals(emptyList(), ctx.accumulator.hallucinationSignals)
        assertNull(ctx.accumulator.hallucinationScore)
    }
}
