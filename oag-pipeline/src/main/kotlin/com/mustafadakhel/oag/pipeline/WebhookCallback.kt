package com.mustafadakhel.oag.pipeline

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

fun interface WebhookCallback {
    fun send(eventType: String, data: Map<String, JsonElement>)
}

fun webhookData(vararg pairs: Pair<String, Any?>): Map<String, JsonElement> =
    pairs.associate { (k, v) -> k to v.toWebhookElement() }

private fun Any?.toWebhookElement(): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is List<*> -> JsonArray(map { it.toWebhookElement() })
    else -> JsonPrimitive(toString())
}
