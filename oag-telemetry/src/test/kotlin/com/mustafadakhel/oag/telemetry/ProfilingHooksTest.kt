package com.mustafadakhel.oag.telemetry

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProfilingHooksTest {

    /** Spin until at least [minNs] nanoseconds have elapsed. */
    private fun busyWait(minNs: Long = 500_000) {
        val start = System.nanoTime()
        @Suppress("ControlFlowWithEmptyBody")
        while (System.nanoTime() - start < minNs) { }
    }

    @Test
    fun `measure captures phase duration`() {
        val profiler = RequestProfiler()
        val result = profiler.measure(RequestProfiler.PHASE_POLICY_EVALUATION) {
            busyWait()
            42
        }

        assertEquals(42, result)
        val timings = profiler.finish()
        assertTrue(timings.policyEvaluationNs > 0)
    }

    @Test
    fun `finish records total time`() {
        val profiler = RequestProfiler()
        busyWait()
        val timings = profiler.finish()

        assertTrue(timings.totalNs > 0)
    }

    @Test
    fun `unmeasured phases default to zero`() {
        val profiler = RequestProfiler()
        val timings = profiler.finish()

        assertEquals(0, timings.policyEvaluationNs)
        assertEquals(0, timings.dnsResolutionNs)
        assertEquals(0, timings.upstreamConnectNs)
        assertEquals(0, timings.requestRelayNs)
        assertEquals(0, timings.responseRelayNs)
        assertEquals(0, timings.secretMaterializationNs)
    }

    @Test
    fun `multiple phases are measured independently`() {
        val profiler = RequestProfiler()

        profiler.measure(RequestProfiler.PHASE_POLICY_EVALUATION) { busyWait() }
        profiler.measure(RequestProfiler.PHASE_DNS_RESOLUTION) { busyWait() }
        profiler.measure(RequestProfiler.PHASE_UPSTREAM_CONNECT) { busyWait() }

        val timings = profiler.finish()
        assertTrue(timings.policyEvaluationNs > 0)
        assertTrue(timings.dnsResolutionNs > 0)
        assertTrue(timings.upstreamConnectNs > 0)
        assertTrue(timings.totalNs >= timings.policyEvaluationNs + timings.dnsResolutionNs + timings.upstreamConnectNs)
    }
}
