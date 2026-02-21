package com.mustafadakhel.oag.app.commands

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

internal val cliJson = Json {
    encodeDefaults = true
    explicitNulls = false
}

@Serializable
internal data class MainErrorJson(
    val ok: Boolean = false,
    @SerialName("error_code") val errorCode: String,
    val error: String?
)

@Serializable
internal data class RequestSummary(
    val scheme: String,
    val host: String,
    val port: Int,
    val method: String,
    val path: String
)
