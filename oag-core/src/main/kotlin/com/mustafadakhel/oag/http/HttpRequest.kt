package com.mustafadakhel.oag.http

data class HttpRequest(
    val method: String,
    val target: String,
    val version: String,
    val headers: Map<String, String>
)
