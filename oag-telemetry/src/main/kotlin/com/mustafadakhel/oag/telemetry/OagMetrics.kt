package com.mustafadakhel.oag.telemetry

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder

class OagMetrics {
    private val requestsTotal = ConcurrentHashMap<String, LongAdder>()
    private val rateLimitedTotal = LongAdder()
    private val dryRunOverrideTotal = LongAdder()
    private val durationBuckets = ConcurrentHashMap<String, LongAdder>()
    private val durationSum = LongAdder()
    private val durationCount = LongAdder()
    private val phaseDurationBuckets = ConcurrentHashMap<String, LongAdder>()
    private val phaseDurationSum = ConcurrentHashMap<String, LongAdder>()
    private val phaseDurationCount = ConcurrentHashMap<String, LongAdder>()
    private val activeConnections = AtomicLong(0)
    private val poolHits = LongAdder()
    private val poolMisses = LongAdder()
    private val poolEvictions = LongAdder()
    private val auditDroppedTotal = LongAdder()

    fun recordRequest(action: String, reasonCode: String, ruleId: String?, tags: List<String>? = null) {
        val tagLabel = tags?.sorted()?.joinToString(",").orEmpty()
        val key = labelKey(action, reasonCode, ruleId.orEmpty(), tagLabel)
        requestsTotal.computeIfAbsent(key) { LongAdder() }.increment()
    }

    fun recordRateLimited() {
        rateLimitedTotal.increment()
    }

    fun recordDryRunOverride() {
        dryRunOverrideTotal.increment()
    }

    fun recordPhaseDuration(phase: String, durationMs: Double) {
        val ms = durationMs.toLong()
        phaseDurationCount.computeIfAbsent(phase) { LongAdder() }.increment()
        phaseDurationSum.computeIfAbsent(phase) { LongAdder() }.add(ms)
        for (bucket in PHASE_BUCKET_BOUNDARIES) {
            if (ms <= bucket) {
                phaseDurationBuckets.computeIfAbsent("$phase$LABEL_SEPARATOR$bucket") { LongAdder() }.increment()
            }
        }
    }

    fun recordDuration(durationMs: Long) {
        durationCount.increment()
        durationSum.add(durationMs)
        for (bucket in DURATION_BUCKET_BOUNDARIES) {
            if (durationMs <= bucket) {
                durationBuckets.computeIfAbsent(bucket.toString()) { LongAdder() }.increment()
            }
        }
    }

    fun incrementActiveConnections() {
        activeConnections.incrementAndGet()
    }

    fun decrementActiveConnections() {
        activeConnections.decrementAndGet()
    }

    fun recordPoolHit() {
        poolHits.increment()
    }

    fun recordPoolMiss() {
        poolMisses.increment()
    }

    fun recordPoolEviction() {
        poolEvictions.increment()
    }

    fun recordAuditDropped() {
        auditDroppedTotal.increment()
    }

    fun auditStats(): Map<String, Long> = buildMap<String, Long> {
        requestsTotal.forEach { (key, count) ->
            val action = key.split(LABEL_SEPARATOR, limit = 4)[0]
            this[action] = (this[action] ?: 0L) + count.sum()
        }
        this[STAT_RATE_LIMITED] = rateLimitedTotal.sum()
        this[STAT_DRY_RUN_OVERRIDE] = dryRunOverrideTotal.sum()
    }.toSortedMap()
    fun toPrometheusText(): String = buildString {
        appendCounter(METRIC_REQUESTS_TOTAL, "Total requests by action, reason code, rule, and tags.") {
            requestsTotal.toSortedMap().forEach { (key, count) ->
                val parts = key.split(LABEL_SEPARATOR, limit = 4)
                val (action, reason, rule) = parts
                val tags = parts.getOrElse(3) { "" }
                appendLine("$METRIC_REQUESTS_TOTAL{$LABEL_ACTION=\"${escapeLabel(action)}\",$LABEL_REASON_CODE=\"${escapeLabel(reason)}\",$LABEL_RULE_ID=\"${escapeLabel(rule)}\",$LABEL_TAGS=\"${escapeLabel(tags)}\"} ${count.sum()}")
            }
        }
        appendCounter(METRIC_RATE_LIMITED_TOTAL, "Total requests denied by rate limiting.", rateLimitedTotal.sum())
        appendCounter(METRIC_DRY_RUN_OVERRIDE_TOTAL, "Total DENY decisions overridden by dry-run mode.", dryRunOverrideTotal.sum())

        appendHistogram(METRIC_PHASE_DURATION_MS, "Per-phase request latency histogram in milliseconds.") {
            phaseDurationCount.keys.sorted().forEach { phase ->
                for (bucket in PHASE_BUCKET_BOUNDARIES) {
                    val count = phaseDurationBuckets["$phase$LABEL_SEPARATOR$bucket"]?.sum() ?: 0
                    appendLine("${METRIC_PHASE_DURATION_MS}_bucket{$LABEL_PHASE=\"${escapeLabel(phase)}\",le=\"$bucket\"} $count")
                }
                appendLine("${METRIC_PHASE_DURATION_MS}_bucket{$LABEL_PHASE=\"${escapeLabel(phase)}\",le=\"+Inf\"} ${phaseDurationCount[phase]?.sum() ?: 0}")
                appendLine("${METRIC_PHASE_DURATION_MS}_sum{$LABEL_PHASE=\"${escapeLabel(phase)}\"} ${phaseDurationSum[phase]?.sum() ?: 0}")
                appendLine("${METRIC_PHASE_DURATION_MS}_count{$LABEL_PHASE=\"${escapeLabel(phase)}\"} ${phaseDurationCount[phase]?.sum() ?: 0}")
            }
        }

        appendHistogram(METRIC_REQUEST_DURATION_MS, "Request duration histogram in milliseconds.") {
            for (bucket in DURATION_BUCKET_BOUNDARIES) {
                appendLine("${METRIC_REQUEST_DURATION_MS}_bucket{le=\"$bucket\"} ${durationBuckets[bucket.toString()]?.sum() ?: 0}")
            }
            appendLine("${METRIC_REQUEST_DURATION_MS}_bucket{le=\"+Inf\"} ${durationCount.sum()}")
            appendLine("${METRIC_REQUEST_DURATION_MS}_sum ${durationSum.sum()}")
            appendLine("${METRIC_REQUEST_DURATION_MS}_count ${durationCount.sum()}")
        }

        appendGauge(METRIC_ACTIVE_CONNECTIONS, "Current active proxy connections.", activeConnections.get())
        appendCounter(METRIC_POOL_HITS, "Connection pool hits.", poolHits.sum())
        appendCounter(METRIC_POOL_MISSES, "Connection pool misses.", poolMisses.sum())
        appendCounter(METRIC_POOL_EVICTIONS, "Connection pool evictions.", poolEvictions.sum())
        appendCounter(METRIC_AUDIT_DROPPED, "Audit events dropped due to full queue.", auditDroppedTotal.sum())
    }

    private fun StringBuilder.appendCounter(name: String, help: String, value: Long) {
        appendLine("# HELP $name $help")
        appendLine("# TYPE $name counter")
        appendLine("$name $value")
    }

    private fun StringBuilder.appendCounter(name: String, help: String, body: StringBuilder.() -> Unit) {
        appendLine("# HELP $name $help")
        appendLine("# TYPE $name counter")
        body()
    }

    private fun StringBuilder.appendGauge(name: String, help: String, value: Long) {
        appendLine("# HELP $name $help")
        appendLine("# TYPE $name gauge")
        appendLine("$name $value")
    }

    private fun StringBuilder.appendHistogram(name: String, help: String, body: StringBuilder.() -> Unit) {
        appendLine("# HELP $name $help")
        appendLine("# TYPE $name histogram")
        body()
    }

    companion object {
        const val METRIC_REQUESTS_TOTAL = "oag_requests_total"
        const val METRIC_RATE_LIMITED_TOTAL = "oag_rate_limited_total"
        const val METRIC_DRY_RUN_OVERRIDE_TOTAL = "oag_dry_run_override_total"
        const val METRIC_PHASE_DURATION_MS = "oag_phase_duration_ms"
        const val METRIC_REQUEST_DURATION_MS = "oag_request_duration_ms"
        const val METRIC_ACTIVE_CONNECTIONS = "oag_active_connections"
        const val METRIC_POOL_HITS = "oag_pool_hits_total"
        const val METRIC_POOL_MISSES = "oag_pool_misses_total"
        const val METRIC_POOL_EVICTIONS = "oag_pool_evictions_total"
        const val METRIC_AUDIT_DROPPED = "oag_audit_dropped_total"

        const val LABEL_ACTION = "action"
        const val LABEL_REASON_CODE = "reason_code"
        const val LABEL_RULE_ID = "rule_id"
        const val LABEL_TAGS = "tags"
        const val LABEL_PHASE = "phase"

        val LABEL_KEYS_REQUESTS = listOf(LABEL_ACTION, LABEL_REASON_CODE, LABEL_RULE_ID, LABEL_TAGS)
        val PHASE_BUCKET_BOUNDARIES = listOf(1L, 2L, 5L, 10L, 25L, 50L, 100L, 250L, 500L, 1000L)
        val DURATION_BUCKET_BOUNDARIES = listOf(5L, 10L, 25L, 50L, 100L, 250L, 500L, 1000L, 5000L, 30000L)

        const val STAT_RATE_LIMITED = "rate_limited"
        const val STAT_DRY_RUN_OVERRIDE = "dry_run_override"

        // U+001F UNIT SEPARATOR — cannot appear in metric label values, safe as a key delimiter
        private const val LABEL_SEPARATOR = "\u001F"

        private fun labelKey(action: String, reasonCode: String, ruleId: String, tags: String = ""): String =
            "$action$LABEL_SEPARATOR$reasonCode$LABEL_SEPARATOR$ruleId$LABEL_SEPARATOR$tags"

        // Backslash must come first to avoid double-escaping subsequent replacements
        internal fun escapeLabel(value: String): String = value
            .replace("\\", "\\\\")
            .replace("\"", "\\\"")
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
    }
}
