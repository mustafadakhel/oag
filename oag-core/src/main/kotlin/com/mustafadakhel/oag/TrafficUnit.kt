package com.mustafadakhel.oag

sealed interface TrafficUnit {

    data class ConnectRequest(
        val host: String,
        val port: Int
    ) : TrafficUnit

    data class HttpRequest(
        val method: String,
        val host: String,
        val port: Int,
        val path: String,
        val scheme: String,
        val headers: Map<String, String>
    ) : TrafficUnit

    data class WsFrame(
        val text: String,
        val isText: Boolean
    ) : TrafficUnit
}
