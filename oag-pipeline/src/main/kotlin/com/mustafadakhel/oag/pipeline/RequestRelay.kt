package com.mustafadakhel.oag.pipeline

fun interface RequestRelay {
    suspend fun relay(context: RequestPipelineContext)
}
