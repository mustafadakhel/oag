package com.mustafadakhel.oag.telemetry

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class MetricsSchemaTest {
    @Test
    fun `metric names follow oag prefix convention`() {
        listOf(
            OagMetrics.METRIC_REQUESTS_TOTAL,
            OagMetrics.METRIC_RATE_LIMITED_TOTAL,
            OagMetrics.METRIC_REQUEST_DURATION_MS,
            OagMetrics.METRIC_ACTIVE_CONNECTIONS
        ).forEach { name ->
            assertTrue(name.startsWith("oag_"), "metric name must start with oag_: $name")
            assertTrue(name.matches(Regex("^[a-z0-9_]+$")), "metric name must be snake_case: $name")
        }
    }

    @Test
    fun `request label keys are stable`() {
        assertEquals(
            listOf("action", "reason_code", "rule_id", "tags"),
            OagMetrics.LABEL_KEYS_REQUESTS
        )
    }

    @Test
    fun `duration bucket boundaries are sorted and positive`() {
        val buckets = OagMetrics.DURATION_BUCKET_BOUNDARIES
        assertTrue(buckets.isNotEmpty())
        assertTrue(buckets.all { it > 0 })
        assertEquals(buckets.sorted().toLongArray().toList(), buckets.toList())
    }

    @Test
    fun `prometheus output contains all metric names`() {
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "allowed_by_rule", "r1")
        metrics.recordDuration(10)

        val text = metrics.toPrometheusText()
        assertContains(text, OagMetrics.METRIC_REQUESTS_TOTAL)
        assertContains(text, OagMetrics.METRIC_RATE_LIMITED_TOTAL)
        assertContains(text, OagMetrics.METRIC_REQUEST_DURATION_MS)
        assertContains(text, OagMetrics.METRIC_ACTIVE_CONNECTIONS)
    }

    @Test
    fun `prometheus output uses correct TYPE annotations`() {
        val text = OagMetrics().toPrometheusText()
        assertContains(text, "# TYPE ${OagMetrics.METRIC_REQUESTS_TOTAL} counter")
        assertContains(text, "# TYPE ${OagMetrics.METRIC_RATE_LIMITED_TOTAL} counter")
        assertContains(text, "# TYPE ${OagMetrics.METRIC_REQUEST_DURATION_MS} histogram")
        assertContains(text, "# TYPE ${OagMetrics.METRIC_ACTIVE_CONNECTIONS} gauge")
    }

    @Test
    fun `duration unit is milliseconds in metric name`() {
        assertTrue(OagMetrics.METRIC_REQUEST_DURATION_MS.endsWith("_ms"))
    }
}
