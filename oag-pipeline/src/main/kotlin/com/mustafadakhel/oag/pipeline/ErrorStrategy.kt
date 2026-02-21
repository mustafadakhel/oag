package com.mustafadakhel.oag.pipeline

fun interface ErrorStrategy {
    fun handle(context: RequestPipelineContext, exception: OagRequestException)
}
