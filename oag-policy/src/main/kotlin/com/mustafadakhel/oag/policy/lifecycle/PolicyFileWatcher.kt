package com.mustafadakhel.oag.policy.lifecycle

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

import java.nio.file.ClosedWatchServiceException
import java.nio.file.FileSystems
import java.nio.file.Path
import java.nio.file.StandardWatchEventKinds
import java.nio.file.WatchKey
import java.time.Clock

class PolicyFileWatcher(
    private val policyPath: Path,
    private val debounceMs: Long = DEFAULT_DEBOUNCE_MS,
    private val onReload: (PolicyService.ReloadResult) -> Unit,
    private val onError: (Exception) -> Unit,
    private val policyService: PolicyService,
    private val clock: Clock = Clock.systemUTC()
) : AutoCloseable {

    private val watchService = FileSystems.getDefault().newWatchService()
    @Volatile private var watchJob: Job? = null

    fun start(scope: CoroutineScope) {
        val dir = requireNotNull(policyPath.toAbsolutePath().parent) {
            "policy path has no parent directory"
        }
        val fileName = policyPath.fileName.toString()

        dir.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE)

        watchJob = scope.launch(Dispatchers.IO) {
            watchLoop(fileName)
        }
    }

    private fun CoroutineScope.watchLoop(fileName: String) {
        var lastReloadMs = 0L

        while (isActive) {
            val key: WatchKey = try {
                watchService.take()
            } catch (_: InterruptedException) {
                break
            } catch (_: ClosedWatchServiceException) {
                break
            }

            var policyChanged = false
            for (event in key.pollEvents()) {
                if (event.kind() == StandardWatchEventKinds.OVERFLOW) {
                    policyChanged = true
                    continue
                }
                val context = event.context()
                if (context is Path && context.toString() == fileName) {
                    policyChanged = true
                }
            }

            key.reset()

            if (policyChanged && isActive) {
                val now = clock.millis()
                if (now - lastReloadMs < debounceMs) continue
                lastReloadMs = now

                try {
                    val result = policyService.reload()
                    onReload(result)
                } catch (e: Exception) {
                    onError(e)
                }
            }
        }
    }

    override fun close() {
        watchJob?.cancel()
        try {
            watchService.close()
        } catch (e: Exception) {
            onError(e)
        }
    }

    companion object {
        const val DEFAULT_DEBOUNCE_MS = 500L
    }
}
