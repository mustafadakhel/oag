package com.mustafadakhel.oag.inspection

sealed interface InspectableArtifact

data class TextBody(val text: String) : InspectableArtifact

data class HeaderEntry(val name: String, val value: String)

data class Headers(val entries: List<HeaderEntry>) : InspectableArtifact

data class Url(
    val scheme: String,
    val host: String,
    val port: Int,
    val path: String,
    val query: String?
) : InspectableArtifact

data class DnsLabel(val label: String) : InspectableArtifact

data class ResponseTextBody(val text: String, val statusCode: Int, val contentType: String?) : InspectableArtifact

data class WsFrame(val text: String, val isText: Boolean) : InspectableArtifact

data class StreamingResponseBody(
    val accumulatedText: String,
    val statusCode: Int,
    val contentType: String?,
    val truncated: Boolean
) : InspectableArtifact
