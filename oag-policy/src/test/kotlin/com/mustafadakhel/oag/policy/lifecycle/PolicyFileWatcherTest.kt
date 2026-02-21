package com.mustafadakhel.oag.policy.lifecycle

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class PolicyFileWatcherTest {

    private val tempDirs = mutableListOf<Path>()

    @AfterTest
    fun tearDown() {
        tempDirs.forEach { dir ->
            runCatching {
                Files.walk(dir).sorted(Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
        tempDirs.clear()
    }

    private fun tempDir(prefix: String): Path =
        Files.createTempDirectory(prefix).also { tempDirs.add(it) }

    private val minimalPolicy = """
        version: 1
        defaults:
          action: deny
        allow:
          - id: test
            host: api.example.com
            methods: [GET]
            paths: [/v1/*]
    """.trimIndent()

    private val updatedPolicy = """
        version: 1
        defaults:
          action: deny
        allow:
          - id: updated
            host: api.updated.com
            methods: [POST]
            paths: [/v2/*]
    """.trimIndent()

    @Test
    fun `watcher detects policy file modification`() = runTest {
        val dir = tempDir("watcher-test")
        val policyFile = dir.resolve("policy.yaml")
        Files.writeString(policyFile, minimalPolicy)

        val service = PolicyService(policyFile)
        val latch = CountDownLatch(1)
        var reloadResult: PolicyService.ReloadResult? = null

        val watcher = PolicyFileWatcher(
            policyPath = policyFile,
            debounceMs = 100,
            onReload = { result ->
                reloadResult = result
                latch.countDown()
            },
            onError = { throw it },
            policyService = service
        )

        watcher.start(backgroundScope)
        try {
            delay(200)
            Files.writeString(policyFile, updatedPolicy)
            assertTrue(latch.await(10, TimeUnit.SECONDS), "Expected reload callback")
            assertTrue(reloadResult!!.changed)
        } finally {
            watcher.close()
        }
    }

    @Test
    fun `watcher debounces rapid changes`() = runTest {
        val dir = tempDir("watcher-debounce")
        val policyFile = dir.resolve("policy.yaml")
        Files.writeString(policyFile, minimalPolicy)

        val service = PolicyService(policyFile)
        var reloadCount = 0
        val latch = CountDownLatch(1)

        val watcher = PolicyFileWatcher(
            policyPath = policyFile,
            debounceMs = 500,
            onReload = { reloadCount++; latch.countDown() },
            onError = { throw it },
            policyService = service
        )

        watcher.start(backgroundScope)
        try {
            delay(200)
            // Rapid writes — debounce should collapse these
            Files.writeString(policyFile, updatedPolicy)
            delay(50)
            Files.writeString(policyFile, updatedPolicy)
            delay(50)
            Files.writeString(policyFile, updatedPolicy)

            latch.await(10, TimeUnit.SECONDS)
            delay(1000)
            // Should have at most 1-2 reloads due to debounce
            assertTrue(reloadCount <= 2, "Expected debounced reload count, got $reloadCount")
        } finally {
            watcher.close()
        }
    }

    @Test
    fun `watcher calls onError for invalid policy`() = runTest {
        val dir = tempDir("watcher-error")
        val policyFile = dir.resolve("policy.yaml")
        Files.writeString(policyFile, minimalPolicy)

        val service = PolicyService(policyFile)
        val errorLatch = CountDownLatch(1)
        var caughtError: Exception? = null

        val watcher = PolicyFileWatcher(
            policyPath = policyFile,
            debounceMs = 100,
            onReload = {},
            onError = { e -> caughtError = e; errorLatch.countDown() },
            policyService = service
        )

        watcher.start(backgroundScope)
        try {
            delay(200)
            Files.writeString(policyFile, "invalid: yaml: [broken")
            assertTrue(errorLatch.await(10, TimeUnit.SECONDS), "Expected error callback")
            assertTrue(caughtError != null)
        } finally {
            watcher.close()
        }
    }

    @Test
    fun `watcher ignores unrelated file changes`() = runTest {
        val dir = tempDir("watcher-unrelated")
        val policyFile = dir.resolve("policy.yaml")
        Files.writeString(policyFile, minimalPolicy)

        val service = PolicyService(policyFile)
        var reloadCount = 0

        val watcher = PolicyFileWatcher(
            policyPath = policyFile,
            debounceMs = 100,
            onReload = { reloadCount++ },
            onError = { throw it },
            policyService = service
        )

        watcher.start(backgroundScope)
        try {
            delay(200)
            Files.writeString(dir.resolve("other.txt"), "unrelated")
            delay(1000)
            assertEquals(0, reloadCount)
        } finally {
            watcher.close()
        }
    }

    @Test
    fun `close stops the watcher`() = runTest {
        val dir = tempDir("watcher-close")
        val policyFile = dir.resolve("policy.yaml")
        Files.writeString(policyFile, minimalPolicy)

        val service = PolicyService(policyFile)
        val watcher = PolicyFileWatcher(
            policyPath = policyFile,
            debounceMs = 100,
            onReload = {},
            onError = {},
            policyService = service
        )

        watcher.start(backgroundScope)
        watcher.close()

        // Should not throw or hang
        delay(200)
    }
}
