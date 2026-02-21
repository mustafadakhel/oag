package com.mustafadakhel.oag.inspection

object EvidenceKey {
    const val PATTERN = "pattern"
    const val CATEGORY = "category"
    const val MAX_ENTROPY = "max_entropy"
    const val THRESHOLD = "threshold"
    const val HOST = "host"
    const val ENTROPY = "entropy"
    const val REASON = "reason"
    const val LENGTH = "length"
    const val MAX = "max"
    const val PATH = "path"
    const val CONTAINS = "contains"
    const val PATTERNS = "patterns"
    const val PROTOCOL = "protocol"
    const val METHOD = "method"
    const val ID = "id"
    const val OPERATION_NAME = "operation_name"
    const val OPERATION_TYPE = "operation_type"
    const val SOURCE = "source"
    const val SCORE = "score"
    const val SIGNALS = "signals"
}

sealed interface FindingLocation {
    val label: String

    data object Body : FindingLocation { override val label = "body" }
    data object Dns : FindingLocation { override val label = "dns" }
    data object UrlQuery : FindingLocation { override val label = "url.query" }
    data object UrlPath : FindingLocation { override val label = "url.path" }
    data object RedirectHost : FindingLocation { override val label = "redirect.host" }
    data object WebSocket : FindingLocation { override val label = "websocket" }
    data object StreamingResponse : FindingLocation { override val label = "streaming_response" }
}

enum class RecommendedAction {
    DENY,
    REDACT,
    LOG
}
