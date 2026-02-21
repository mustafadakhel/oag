package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.TaskSnapshot
import com.mustafadakhel.oag.enforcement.EnforcementAction
import com.mustafadakhel.oag.proxy.admin.AdminAccessCallback
import com.mustafadakhel.oag.proxy.admin.AdminServer
import com.mustafadakhel.oag.proxy.admin.AdminServerDeps
import com.mustafadakhel.oag.proxy.admin.PolicyInfo
import com.mustafadakhel.oag.enforcement.PoolStats
import com.mustafadakhel.oag.telemetry.OagMetrics

import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runTest

import java.net.HttpURLConnection
import java.net.ServerSocket
import java.net.URI

class AdminServerTest {

    private data class HttpResponse(val statusCode: Int, val body: String)
    private data class AccessLogEntry(val endpoint: String, val sourceIp: String, val action: EnforcementAction)

    private fun httpGet(port: Int, path: String): HttpResponse {
        val url = URI("http://127.0.0.1:$port$path").toURL()
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "GET"
        conn.connectTimeout = 3000
        conn.readTimeout = 3000
        val code = conn.responseCode
        val body = if (code in 200..299) {
            conn.inputStream.bufferedReader().readText()
        } else {
            conn.errorStream?.bufferedReader()?.readText() ?: ""
        }
        conn.disconnect()
        return HttpResponse(code, body)
    }

    private fun buildDeps(
        metrics: OagMetrics = OagMetrics(),
        oagVersion: String = "0.1.0-test",
        policyHashProvider: () -> String = { "testhash" },
        drainingProvider: () -> Boolean = { false },
        reloadCallback: (() -> ReloadCallbackResult)? = null,
        policyInfoProvider: (() -> PolicyInfo)? = null,
        poolStatsProvider: (() -> PoolStats?)? = null,
        taskSnapshotProvider: (() -> List<TaskSnapshot>)? = null
    ) = AdminServerDeps(
        metrics = metrics,
        oagVersion = oagVersion,
        policyHashProvider = policyHashProvider,
        drainingProvider = drainingProvider,
        reloadCallback = reloadCallback,
        policyInfoProvider = policyInfoProvider,
        poolStatsProvider = poolStatsProvider,
        taskSnapshotProvider = taskSnapshotProvider
    )

    @Test
    fun `healthz returns 200 with status ok`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "abc123" })
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/healthz")
            assertEquals(200, code)
            assertContains(body, "\"status\":\"ok\"")
            assertContains(body, "\"version\":\"0.1.0-test\"")
            assertContains(body, "\"policy_hash\":\"abc123\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `metrics returns 200 with prometheus text`() = runTest {
        val port = findFreePort()
        val metrics = OagMetrics()
        metrics.recordRateLimited()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(metrics = metrics)
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/metrics")
            assertEquals(200, code)
            assertContains(body, "oag_rate_limited_total 1")
            assertContains(body, "oag_active_connections")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `unknown path returns 404`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps()
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, _) = httpGet(port, "/unknown")
            assertEquals(404, code)
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `stop closes the server`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps()
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        srv.stop()
        val failed = runCatching { httpGet(port, "/healthz") }.isFailure
        assertTrue(failed)
    }

    @Test
    fun `healthz returns 503 with status draining when draining`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "abc123" }, drainingProvider = { true })
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/healthz")
            assertEquals(503, code)
            assertContains(body, "\"status\":\"draining\"")
            assertContains(body, "\"version\":\"0.1.0-test\"")
            assertContains(body, "\"policy_hash\":\"abc123\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `healthz transitions from 200 to 503 when draining starts`() = runTest {
        val port = findFreePort()
        var draining = false
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash1" }, drainingProvider = { draining })
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code1, body1) = httpGet(port, "/healthz")
            assertEquals(200, code1)
            assertContains(body1, "\"status\":\"ok\"")

            draining = true
            val (code2, body2) = httpGet(port, "/healthz")
            assertEquals(503, code2)
            assertContains(body2, "\"status\":\"draining\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `reload endpoint returns 200 on success`() = runTest {
        val port = findFreePort()
        var reloadCalled = false
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(
                policyHashProvider = { "newhash" },
                reloadCallback = {
                    reloadCalled = true
                    ReloadCallbackResult(success = true, changed = true, newHash = "newhash")
                }
            )
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpPost(port, "/admin/reload")
            assertEquals(200, code)
            assertContains(body, "\"ok\":true")
            assertContains(body, "\"changed\":true")
            assertContains(body, "\"policy_hash\":\"newhash\"")
            assertTrue(reloadCalled)
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `reload endpoint returns 500 on failure`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(
                policyHashProvider = { "hash" },
                reloadCallback = {
                    ReloadCallbackResult(success = false, changed = false, errorMessage = "bad policy")
                }
            )
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpPost(port, "/admin/reload")
            assertEquals(500, code)
            assertContains(body, "\"ok\":false")
            assertContains(body, "bad policy")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `reload endpoint returns 405 for GET`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(
                policyHashProvider = { "hash" },
                reloadCallback = {
                    ReloadCallbackResult(success = true, changed = false, newHash = "hash")
                }
            )
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/reload")
            assertEquals(405, code)
            assertContains(body, "method not allowed")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `reload endpoint returns 501 when no callback configured`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps()
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpPost(port, "/admin/reload")
            assertEquals(501, code)
            assertContains(body, "reload not configured")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `pool stats returns disabled when no provider`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps()
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/pool")
            assertEquals(200, code)
            assertContains(body, "\"enabled\":false")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `pool stats returns stats when provider configured`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(
                policyHashProvider = { "hash" },
                poolStatsProvider = { PoolStats(hits = 10, misses = 3, evictions = 1, currentIdle = 5) }
            )
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/pool")
            assertEquals(200, code)
            assertContains(body, "\"enabled\":true")
            assertContains(body, "\"idle\":5")
            assertContains(body, "\"hits\":10")
            assertContains(body, "\"misses\":3")
            assertContains(body, "\"evictions\":1")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `policy info returns hash and rule counts`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(
                policyHashProvider = { "abc123" },
                policyInfoProvider = {
                    PolicyInfo(
                        hash = "abc123",
                        allowRuleCount = 3,
                        denyRuleCount = 1,
                        loadedAt = "2026-01-01T00:00:00Z"
                    )
                }
            )
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/policy")
            assertEquals(200, code)
            assertContains(body, "\"policy_hash\":\"abc123\"")
            assertContains(body, "\"allow_rule_count\":3")
            assertContains(body, "\"deny_rule_count\":1")
            assertContains(body, "\"loaded_at\":\"2026-01-01T00:00:00Z\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `audit stats returns decision counts`() = runTest {
        val port = findFreePort()
        val metrics = OagMetrics()
        metrics.recordRequest("allow", "allowed_by_rule", "r1")
        metrics.recordRequest("deny", "no_match_default_deny", null)
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(metrics = metrics, policyHashProvider = { "hash" })
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/audit")
            assertEquals(200, code)
            assertContains(body, "\"ok\":true")
            assertContains(body, "\"allow\":1")
            assertContains(body, "\"deny\":1")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `admin allowed ips blocks non-allowed source`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash" }),
            allowedIps = listOf("10.0.0.1")
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/healthz")
            assertEquals(403, code)
            assertContains(body, "\"ok\":false")
            assertContains(body, "forbidden")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `admin allowed ips allows matching source`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash" }),
            allowedIps = listOf("127.0.0.1")
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/healthz")
            assertEquals(200, code)
            assertContains(body, "\"status\":\"ok\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `admin allowed ips with cidr allows range`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash" }),
            allowedIps = listOf("127.0.0.0/8")
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/healthz")
            assertEquals(200, code)
            assertContains(body, "\"status\":\"ok\"")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `admin access callback is invoked with source ip`() = runTest {
        val port = findFreePort()
        val accessLog = mutableListOf<AccessLogEntry>()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash" }),
            adminAccessCallback = AdminAccessCallback { endpoint, sourceIp, action ->
                accessLog.add(AccessLogEntry(endpoint, sourceIp, action))
            }
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            httpGet(port, "/healthz")
            assertEquals(1, accessLog.size)
            assertEquals("/healthz", accessLog[0].endpoint)
            assertEquals("127.0.0.1", accessLog[0].sourceIp)
            assertIs<EnforcementAction.Allow>(accessLog[0].action)
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `admin access callback records denied access with enforcement action`() = runTest {
        val port = findFreePort()
        val accessLog = mutableListOf<AccessLogEntry>()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(policyHashProvider = { "hash" }),
            adminAccessCallback = AdminAccessCallback { endpoint, sourceIp, action ->
                accessLog.add(AccessLogEntry(endpoint, sourceIp, action))
            },
            allowedIps = listOf("10.0.0.1")
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, _) = httpGet(port, "/healthz")
            assertEquals(403, code)
            assertEquals(1, accessLog.size)
            assertEquals("/healthz", accessLog[0].endpoint)
            assertEquals("127.0.0.1", accessLog[0].sourceIp)
            val deny = assertIs<EnforcementAction.Deny>(accessLog[0].action)
            assertEquals("forbidden", deny.reason)
            assertEquals(403, deny.statusCode)
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `tasks endpoint returns empty array when no provider`() = runTest {
        val port = findFreePort()
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps()
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/tasks")
            assertEquals(200, code)
            assertContains(body, "\"ok\":true")
            assertContains(body, "\"tasks\":[]")
        } finally {
            srv.stop()
        }
    }

    @Test
    fun `tasks endpoint returns task snapshots`() = runTest {
        val port = findFreePort()
        val snapshots = listOf(
            TaskSnapshot(
                name = "integrity_checker",
                running = true,
                successCount = 42,
                errorCount = 1,
                lastSuccessMs = 1700000000000L,
                lastErrorMs = 1699999000000L,
                lastError = "check failed"
            ),
            TaskSnapshot(
                name = "pool_evictor",
                running = true,
                successCount = 100,
                errorCount = 0,
                lastSuccessMs = 1700000001000L,
                lastErrorMs = null,
                lastError = null
            )
        )
        val srv = AdminServer(
            listenHost = "127.0.0.1",
            listenPort = port,
            deps = buildDeps(taskSnapshotProvider = { snapshots })
        )
        backgroundScope.launch(Dispatchers.IO) { srv.start() }
        awaitServerReady(port)
        try {
            val (code, body) = httpGet(port, "/admin/tasks")
            assertEquals(200, code)
            assertContains(body, "\"ok\":true")
            assertContains(body, "\"name\":\"integrity_checker\"")
            assertContains(body, "\"running\":true")
            assertContains(body, "\"success_count\":42")
            assertContains(body, "\"error_count\":1")
            assertContains(body, "\"last_error\":\"check failed\"")
            assertContains(body, "\"name\":\"pool_evictor\"")
            assertContains(body, "\"success_count\":100")
        } finally {
            srv.stop()
        }
    }

    private fun httpPost(port: Int, path: String): HttpResponse {
        val url = URI("http://127.0.0.1:$port$path").toURL()
        val conn = url.openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.connectTimeout = 3000
        conn.readTimeout = 3000
        conn.doOutput = true
        conn.outputStream.write(ByteArray(0))
        conn.outputStream.flush()
        val code = conn.responseCode
        val body = if (code in 200..299) {
            conn.inputStream.bufferedReader().readText()
        } else {
            conn.errorStream?.bufferedReader()?.readText() ?: ""
        }
        conn.disconnect()
        return HttpResponse(code, body)
    }

    private fun findFreePort(): Int {
        val socket = ServerSocket(0)
        val port = socket.localPort
        socket.close()
        return port
    }
}
