package com.mustafadakhel.oag.pipeline

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

private const val MAX_REVERSE_ITERATIONS = 100

private val lenientJson = Json { ignoreUnknownKeys = true; isLenient = true }

fun extractUserTurnText(bodyText: String): String? {
    val root = runCatching { lenientJson.parseToJsonElement(bodyText) }.getOrNull()
    if (root !is JsonObject) return null
    val messages = root["messages"]
    if (messages !is JsonArray || messages.isEmpty()) return null

    val startIndex = maxOf(0, messages.size - MAX_REVERSE_ITERATIONS)
    for (i in messages.lastIndex downTo startIndex) {
        val element = messages[i]
        if (element !is JsonObject) continue
        val role = (element["role"] as? JsonPrimitive)?.contentOrNull ?: continue
        if (role != "user") continue
        return extractContent(element)
    }

    return null
}

private fun extractContent(message: JsonObject): String? {
    val content = message["content"] ?: return null
    return when (content) {
        is JsonPrimitive -> content.contentOrNull
        is JsonArray -> extractMultimodalContent(content)
        else -> null
    }
}

private fun extractMultimodalContent(parts: JsonArray): String? {
    val textParts = parts.mapNotNull { part ->
        if (part !is JsonObject) return@mapNotNull null
        val type = (part["type"] as? JsonPrimitive)?.contentOrNull
        if (type == "text") {
            (part["text"] as? JsonPrimitive)?.contentOrNull
        } else null
    }
    return textParts.joinToString("\n").ifBlank { null }
}
