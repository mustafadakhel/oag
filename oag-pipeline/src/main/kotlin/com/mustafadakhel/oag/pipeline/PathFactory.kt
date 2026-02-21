package com.mustafadakhel.oag.pipeline

fun buildPipelinePath(
    pipeline: Pipeline,
    relay: RequestRelay
): RequestPath = RequestPath { context ->
    pipeline.run(context)
    relay.relay(context)
}

fun buildScopedPath(
    delegate: RequestPath,
    exceptionHandler: RequestExceptionHandler
): RequestPath = RequestPath { context ->
    try {
        delegate.process(context)
    } catch (e: OagRequestException) {
        exceptionHandler.handle(context, e)
    } finally {
        context.requestSpan?.end()
    }
}
