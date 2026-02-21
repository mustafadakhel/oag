package com.mustafadakhel.oag.pipeline

fun interface RequestExceptionHandler {
    fun handle(context: RequestPipelineContext, exception: OagRequestException)
}
