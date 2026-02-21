package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.label
import java.util.Locale

enum class DetectedProtocol(val protocolId: String) {
    JSON_RPC("jsonrpc"),
    GRAPHQL("graphql"),
    UNKNOWN("unknown");

    companion object {
        private val byId = entries.associateBy { it.protocolId }
        fun fromProtocolId(id: String): DetectedProtocol? = byId[id.lowercase(Locale.ROOT)]
        val validProtocolIds: Set<String> = entries.filter { it != UNKNOWN }.map { it.protocolId }.toSet()
    }
}

enum class GraphQlOperationType {
    QUERY, MUTATION, SUBSCRIPTION;

    companion object {
        private val BY_LABEL = entries.associateBy { it.label() }
        fun fromLabel(value: String): GraphQlOperationType? = BY_LABEL[value]
    }
}

data class StructuredPayload(
    val protocol: DetectedProtocol,
    val method: String? = null,
    val operationName: String? = null,
    val operationType: GraphQlOperationType? = null,
    val id: String? = null
)
