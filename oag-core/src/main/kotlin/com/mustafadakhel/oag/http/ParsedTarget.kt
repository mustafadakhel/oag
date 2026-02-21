package com.mustafadakhel.oag.http

data class ParsedTarget(
    val scheme: String,
    val host: String,
    val port: Int,
    val path: String
)
