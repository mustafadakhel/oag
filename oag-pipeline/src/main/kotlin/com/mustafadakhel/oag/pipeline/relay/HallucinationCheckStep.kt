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
    private val config: PolicyHallucinationCheck,
    private val claimMatcher: ImpossibleClaimMatcher? = null,
    private val urlVerifier: UrlVerifier? = null,
    private val packageVerifier: PackageVerifier? = null
) : ResponseInspectionStep {

    override fun inspect(bodyText: String, context: BufferedInspectionContext): StepOutcome {
        val mode = config.mode ?: HallucinationMode.OBSERVE
        val signals = mutableListOf<HallucinationSignalResult>()

        if (config.impossibleClaims != false && claimMatcher != null) {
            val matches = claimMatcher.match(bodyText)
            if (matches.isNotEmpty()) {
                val score = (matches.size.coerceAtMost(MAX_CLAIM_MATCHES).toDouble() / MAX_CLAIM_MATCHES)
                    .coerceAtMost(1.0)
                val details = matches.take(MAX_CLAIM_DETAILS)
                    .joinToString("; ") { "${it.category}: ${it.pattern}" }
                signals.add(HallucinationSignalResult(
                    name = SIGNAL_IMPOSSIBLE_CLAIMS,
                    score = score,
                    details = details
                ))
            }
        }

        if (config.urlVerification == true && urlVerifier != null) {
            val results = urlVerifier.extractAndVerify(bodyText)
            val deadUrls = results.filter { it.status == UrlStatus.NOT_FOUND || it.status == UrlStatus.UNREACHABLE }
            if (deadUrls.isNotEmpty()) {
                val score = (deadUrls.size.toDouble() / results.size.coerceAtLeast(1)).coerceAtMost(1.0)
                val details = deadUrls.take(MAX_URL_DETAILS)
                    .joinToString("; ") { "${it.url} (${it.status.name.lowercase()})" }
                signals.add(HallucinationSignalResult(
                    name = SIGNAL_URL_VERIFICATION,
                    score = score,
                    details = details
                ))
            }
        }

        if (config.packageVerification == true && packageVerifier != null) {
            val results = packageVerifier.extractAndVerify(bodyText)
            val notFound = results.filter { it.status == PackageStatus.NOT_FOUND }
            if (notFound.isNotEmpty()) {
                val score = (notFound.size.toDouble() / results.size.coerceAtLeast(1)).coerceAtMost(1.0)
                val details = notFound.take(MAX_PACKAGE_DETAILS)
                    .joinToString("; ") { "${it.registry}:${it.packageName}" }
                signals.add(HallucinationSignalResult(
                    name = SIGNAL_PACKAGE_VERIFICATION,
                    score = score,
                    details = details
                ))
            }
        }

        context.accumulator.hallucinationMode = mode.label()
        context.accumulator.hallucinationSignals = signals
        context.accumulator.hallucinationScore = if (signals.isNotEmpty()) {
            signals.maxOf { it.score }
        } else null
        return StepOutcome.Continue(bodyText)
    }

    companion object {
        internal const val SIGNAL_IMPOSSIBLE_CLAIMS = "impossible_claims"
        internal const val SIGNAL_URL_VERIFICATION = "url_verification"
        internal const val SIGNAL_PACKAGE_VERIFICATION = "package_verification"
        private const val MAX_CLAIM_MATCHES = 5
        private const val MAX_CLAIM_DETAILS = 10
        private const val MAX_URL_DETAILS = 10
        private const val MAX_PACKAGE_DETAILS = 10
    }
}
