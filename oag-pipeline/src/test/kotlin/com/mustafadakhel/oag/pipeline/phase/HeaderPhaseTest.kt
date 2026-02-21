package com.mustafadakhel.oag.pipeline.phase

import com.mustafadakhel.oag.pipeline.HeaderState
import com.mustafadakhel.oag.pipeline.RequestIdKey
import com.mustafadakhel.oag.pipeline.buildTestContext
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HeaderPhaseTest {

    @Test
    fun `prepareHeaders populates HeaderState`() {
        val context = buildTestContext()
        prepareHeaders(context)

        val headers = context.outputs.getOrNull(HeaderState)
        assertNotNull(headers)
        assertTrue(headers.containsKey("host"))
    }

    @Test
    fun `injectRequestIdPhase adds request id to headers`() {
        val context = buildTestContext()
        prepareHeaders(context)
        injectRequestIdPhase(context)

        val requestId = context.outputs.getOrNull(RequestIdKey)
        assertNotNull(requestId)
        assertTrue(requestId.value.isNotEmpty())
    }
}
