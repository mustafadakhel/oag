package com.mustafadakhel.oag.proxy.relay

import com.mustafadakhel.oag.pipeline.RequestPipelineContext

internal fun interface MitmTrafficHandler {
    suspend fun run(connectContext: RequestPipelineContext, tunnel: MitmSslTunnel)
}
