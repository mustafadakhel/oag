package com.mustafadakhel.oag

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

/**
 * Extracts a value from a [JsonElement] using an RFC 6901 JSON Pointer.
 *
 * @param pointer RFC 6901 pointer (e.g., "/choices/0/message/content")
 * @return the element at the pointer path, or null if any segment is missing
 */
fun extractJsonPointer(root: JsonElement, pointer: String): JsonElement? {
    if (pointer.isEmpty()) return root
    if (!pointer.startsWith("/")) return null

    val segments = pointer.removePrefix("/").split("/").map { unescapeSegment(it) }
    var current: JsonElement = root
    for (segment in segments) {
        current = when (current) {
            is JsonObject -> current[segment] ?: return null
            is JsonArray -> {
                val index = segment.toIntOrNull() ?: return null
                if (index < 0 || index >= current.size) return null
                current[index]
            }
            else -> return null
        }
    }
    return current
}

/**
 * Validates that a string is a well-formed RFC 6901 JSON Pointer.
 *
 * @return null if valid, or an error message describing the problem
 */
fun validateJsonPointer(pointer: String): String? {
    if (pointer.isEmpty()) return null
    if (!pointer.startsWith("/")) return "JSON Pointer must start with '/'"
    if (pointer.length > MAX_POINTER_LENGTH) return "JSON Pointer exceeds max length of $MAX_POINTER_LENGTH"
    val segments = pointer.removePrefix("/").split("/")
    if (segments.size > MAX_POINTER_DEPTH) return "JSON Pointer exceeds max depth of $MAX_POINTER_DEPTH"
    return null
}

private fun unescapeSegment(segment: String): String =
    segment.replace("~1", "/").replace("~0", "~")

private const val MAX_POINTER_LENGTH = 512
private const val MAX_POINTER_DEPTH = 20
