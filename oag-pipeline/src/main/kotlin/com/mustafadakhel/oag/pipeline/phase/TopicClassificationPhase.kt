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

package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.PipelineStage
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.pipeline.AuditEnrichable
import com.mustafadakhel.oag.pipeline.GatePhase
import com.mustafadakhel.oag.pipeline.HttpStatus
import com.mustafadakhel.oag.pipeline.PhaseKey
import com.mustafadakhel.oag.pipeline.PhaseOutcome
import com.mustafadakhel.oag.pipeline.RequestPipelineContext
import com.mustafadakhel.oag.pipeline.TopicClassificationException
import com.mustafadakhel.oag.pipeline.TopicClassificationRequest
import com.mustafadakhel.oag.pipeline.TopicClassifierClient
import com.mustafadakhel.oag.pipeline.extractUserTurnText
import com.mustafadakhel.oag.policy.core.PolicyDecision
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.PolicyTopicClassification
import com.mustafadakhel.oag.policy.core.ReasonCode
import com.mustafadakhel.oag.policy.lifecycle.PolicyService

import java.util.Locale

enum class TopicClassificationAction {
    DENIED,
    ALLOWED,
    ERROR_DENY,
    ERROR_ALLOW
}

data class TopicClassificationResult(
    val action: TopicClassificationAction,
    val topic: String? = null,
    val confidence: Double? = null,
    val endpointLatencyMs: Long? = null,
    val error: String? = null
)

class TopicClassificationPhase(
    private val policyService: PolicyService,
    private val topicClassifierClient: TopicClassifierClient,
    private val circuitBreakerRegistry: CircuitBreakerCheck? = null
) : GatePhase, AuditEnrichable {

    companion object : PhaseKey<TopicClassificationResult>

    override val stage = PipelineStage.INSPECT
    override val name = "topic_classification"
    override val skipWhenPolicyDenied = true

    override fun evaluate(context: RequestPipelineContext): PhaseOutcome<Unit> {
        val config = resolveTopicClassification(context.matchedRule, policyService.current.defaults)
            ?: return PhaseOutcome.Continue(Unit)

        val result = classify(context, config)
        context.outputs.put(TopicClassificationPhase, result)

        return when (result.action) {
            TopicClassificationAction.DENIED, TopicClassificationAction.ERROR_DENY ->
                PhaseOutcome.Deny(
                    decision = PolicyDecision(
                        action = com.mustafadakhel.oag.policy.core.PolicyAction.DENY,
                        ruleId = context.matchedRule?.id,
                        reasonCode = ReasonCode.TOPIC_DENIED
                    ),
                    statusCode = HttpStatus.FORBIDDEN
                )
            TopicClassificationAction.ALLOWED, TopicClassificationAction.ERROR_ALLOW ->
                PhaseOutcome.Continue(Unit)
        }
    }

    override fun enrichAudit(context: RequestPipelineContext) {
        val config = resolveTopicClassification(context.matchedRule, policyService.current.defaults)
            ?: return
        val result = classify(context, config)
        context.outputs.put(TopicClassificationPhase, result)
    }

    private fun classify(context: RequestPipelineContext, config: PolicyTopicClassification): TopicClassificationResult {
        val bodyText = context.bufferedBodyText ?: return TopicClassificationResult(
            action = TopicClassificationAction.ALLOWED
        )
        val userText = extractUserTurnText(bodyText) ?: bodyText
        val truncated = config.maxTextBytes?.let { userText.take(it) } ?: userText

        val topics = config.deniedTopics ?: config.allowedTopics ?: return TopicClassificationResult(
            action = TopicClassificationAction.ALLOWED
        )

        if (circuitBreakerRegistry != null) {
            val endpointUrl = config.endpointUrl ?: return TopicClassificationResult(action = TopicClassificationAction.ALLOWED)
            if (!circuitBreakerRegistry.allowRequest(endpointUrl)) {
                return routeError(config, "circuit breaker open for $endpointUrl")
            }
        }

        val startMs = System.currentTimeMillis()
        return try {
            val response = topicClassifierClient.classify(TopicClassificationRequest(truncated, topics))
            val latency = System.currentTimeMillis() - startMs
            circuitBreakerRegistry?.recordSuccess(config.endpointUrl ?: "")

            val threshold = config.confidenceThreshold ?: DEFAULT_CONFIDENCE_THRESHOLD
            val action = evaluateTopicMatch(config, response.topic, response.confidence, threshold)
            TopicClassificationResult(
                action = action,
                topic = response.topic,
                confidence = response.confidence,
                endpointLatencyMs = latency
            )
        } catch (e: TopicClassificationException) {
            val latency = System.currentTimeMillis() - startMs
            circuitBreakerRegistry?.recordFailure(config.endpointUrl ?: "")
            routeError(config, e.message ?: "classification failed").copy(endpointLatencyMs = latency)
        }
    }

    private fun evaluateTopicMatch(
        config: PolicyTopicClassification,
        topic: String?,
        confidence: Double,
        threshold: Double
    ): TopicClassificationAction {
        if (topic == null || confidence < threshold) return TopicClassificationAction.ALLOWED

        val normalizedTopic = topic.lowercase(Locale.ROOT)
        val denied = config.deniedTopics
        val allowed = config.allowedTopics
        return if (denied != null) {
            if (denied.any { it.lowercase(Locale.ROOT) == normalizedTopic }) {
                TopicClassificationAction.DENIED
            } else {
                TopicClassificationAction.ALLOWED
            }
        } else if (allowed != null) {
            if (allowed.any { it.lowercase(Locale.ROOT) == normalizedTopic }) {
                TopicClassificationAction.ALLOWED
            } else {
                TopicClassificationAction.DENIED
            }
        } else {
            TopicClassificationAction.ALLOWED
        }
    }

    private fun routeError(config: PolicyTopicClassification, error: String): TopicClassificationResult {
        val action = if (config.onError == "allow") {
            TopicClassificationAction.ERROR_ALLOW
        } else {
            TopicClassificationAction.ERROR_DENY
        }
        return TopicClassificationResult(action = action, error = error)
    }
}

fun interface CircuitBreakerCheck {
    fun allowRequest(key: String): Boolean
    fun recordSuccess(key: String) {}
    fun recordFailure(key: String) {}
}

private fun resolveTopicClassification(rule: PolicyRule?, defaults: PolicyDefaults?): PolicyTopicClassification? {
    if (rule?.skipTopicClassification == true) return null
    val config = rule?.topicClassification ?: defaults?.topicClassification ?: return null
    return if (config.enabled == true) config else null
}

private const val DEFAULT_CONFIDENCE_THRESHOLD = 0.5
