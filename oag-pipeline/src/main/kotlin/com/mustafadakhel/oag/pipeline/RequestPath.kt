package com.mustafadakhel.oag.pipeline

fun interface RequestPath {
    suspend fun process(context: RequestPipelineContext)
}
