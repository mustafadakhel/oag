package com.mustafadakhel.oag.telemetry

import kotlin.test.Test
import kotlin.test.assertContains

class OagMetricsTest {
    @Test
    fun `records request counter by labels`() {
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "allowed_by_rule", "rule1")
        metrics.recordRequest("allow", "allowed_by_rule", "rule1")
        metrics.recordRequest("deny", "denied_by_rule", "rule2")

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_requests_total{action="allow",reason_code="allowed_by_rule",rule_id="rule1",tags=""} 2""")
        assertContains(text, """oag_requests_total{action="deny",reason_code="denied_by_rule",rule_id="rule2",tags=""} 1""")
    }

    @Test
    fun `records rate limited counter`() {
        val metrics = OagMetrics()
        metrics.recordRateLimited()
        metrics.recordRateLimited()

        val text = metrics.toPrometheusText()
        assertContains(text, "oag_rate_limited_total 2")
    }

    @Test
    fun `records duration histogram`() {
        val metrics = OagMetrics()
        metrics.recordDuration(15)
        metrics.recordDuration(150)

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_request_duration_ms_bucket{le="25"} 1""")
        assertContains(text, """oag_request_duration_ms_bucket{le="250"} 2""")
        assertContains(text, """oag_request_duration_ms_bucket{le="+Inf"} 2""")
        assertContains(text, "oag_request_duration_ms_sum 165")
        assertContains(text, "oag_request_duration_ms_count 2")
    }

    @Test
    fun `tracks active connections`() {
        val metrics = OagMetrics()
        metrics.incrementActiveConnections()
        metrics.incrementActiveConnections()
        metrics.decrementActiveConnections()

        val text = metrics.toPrometheusText()
        assertContains(text, "oag_active_connections 1")
    }

    @Test
    fun `null rule id recorded as empty string`() {
        val metrics = OagMetrics()
        metrics.recordRequest("deny", "no_match_default_deny", null)

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_requests_total{action="deny",reason_code="no_match_default_deny",rule_id="",tags=""} 1""")
    }

    @Test
    fun `custom reason code is used in metrics`() {
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "approved_by_team", "custom_rule")

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_requests_total{action="allow",reason_code="approved_by_team",rule_id="custom_rule",tags=""} 1""")
    }

    @Test
    fun `prometheus text includes type and help annotations`() {
        val metrics = OagMetrics()
        val text = metrics.toPrometheusText()

        assertContains(text, "# TYPE oag_requests_total counter")
        assertContains(text, "# HELP oag_requests_total")
        assertContains(text, "# TYPE oag_rate_limited_total counter")
        assertContains(text, "# TYPE oag_request_duration_ms histogram")
        assertContains(text, "# TYPE oag_active_connections gauge")
    }

    @Test
    fun `histogram buckets are cumulative`() {
        val metrics = OagMetrics()
        metrics.recordDuration(3)
        metrics.recordDuration(8)
        metrics.recordDuration(30)

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_request_duration_ms_bucket{le="5"} 1""")
        assertContains(text, """oag_request_duration_ms_bucket{le="10"} 2""")
        assertContains(text, """oag_request_duration_ms_bucket{le="50"} 3""")
        assertContains(text, """oag_request_duration_ms_bucket{le="+Inf"} 3""")
    }

    @Test
    fun `tags label appears in metrics when provided`() {
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "allowed_by_rule", "rule1", listOf("billing", "api"))

        val text = metrics.toPrometheusText()
        assertContains(text, """oag_requests_total{action="allow",reason_code="allowed_by_rule",rule_id="rule1",tags="api,billing"} 1""")
    }

    @Test
    fun `tags label is empty when tags are null`() {
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "allowed_by_rule", "rule1", null)

        val text = metrics.toPrometheusText()
        assertContains(text, """tags=""} 1""")
    }
}
