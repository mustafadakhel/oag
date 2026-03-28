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

import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.policy.core.HallucinationMode
import com.mustafadakhel.oag.policy.core.PolicyHallucinationCheck

internal class HallucinationCheckStep(
    private val config: PolicyHallucinationCheck
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        val mode = config.mode ?: HallucinationMode.OBSERVE
        context.accumulator.hallucinationMode = mode.label()
        context.accumulator.hallucinationScore = null
        context.accumulator.hallucinationSignals = emptyList()
        return StepOutcome.Continue(bodyText)
    }
}
