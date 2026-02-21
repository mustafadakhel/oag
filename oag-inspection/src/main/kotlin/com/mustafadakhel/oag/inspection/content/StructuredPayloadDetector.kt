package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.policy.core.DetectedProtocol
import com.mustafadakhel.oag.policy.core.GraphQlOperationType
import com.mustafadakhel.oag.policy.core.StructuredPayload
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.util.Locale

private val payloadJson = Json { ignoreUnknownKeys = true }

private const val MAX_PAYLOAD_DETECT_BYTES = 1024 * 1024 // 1 MB

fun detectStructuredPayload(body: String, contentType: String?): StructuredPayload? {
    if (body.length > MAX_PAYLOAD_DETECT_BYTES) return null

    val isJson = contentType?.lowercase(Locale.ROOT)?.contains("json") == true ||
        body.trimStart().startsWith("{")
    if (!isJson) return null

    val obj: JsonObject = try {
        payloadJson.parseToJsonElement(body).jsonObject
    } catch (_: Exception) {
        return null
    }

    if ("jsonrpc" in obj) {
        val method = obj["method"]?.jsonPrimitive?.contentOrNull
        val id = obj["id"]?.jsonPrimitive?.contentOrNull
        if (method != null) {
            return StructuredPayload(
                protocol = DetectedProtocol.JSON_RPC,
                method = method,
                id = id
            )
        }
    }

    if ("query" in obj || "operationName" in obj) {
        val operationName = obj["operationName"]?.jsonPrimitive?.contentOrNull
        val query = obj["query"]?.jsonPrimitive?.contentOrNull
        val operationType = query?.let { detectGraphQlOperationType(it) }
        return StructuredPayload(
            protocol = DetectedProtocol.GRAPHQL,
            operationName = operationName,
            operationType = operationType
        )
    }

    return null
}

private val GRAPHQL_OP_BOUNDARY = Regex("""^(mutation|subscription|query)[\s({]""")

private fun detectGraphQlOperationType(query: String): GraphQlOperationType? {
    val trimmed = query.trimStart()
    if (trimmed.startsWith("{")) return GraphQlOperationType.QUERY
    val match = GRAPHQL_OP_BOUNDARY.find(trimmed) ?: return null
    return GraphQlOperationType.fromLabel(match.groupValues[1])
}
