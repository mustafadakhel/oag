package com.mustafadakhel.oag.audit

import com.mustafadakhel.oag.LOG_PREFIX
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.Json

import java.io.Closeable
import java.io.OutputStream
import java.time.Instant

class AuditLogger(
    private val outputStream: OutputStream,
    private val externalSink: AuditExternalSink? = null,
    private val closeOutputStream: Boolean = true,
    private val onError: (String) -> Unit = System.err::println,
    private val onDrop: () -> Unit = {},
    queueCapacity: Int = 0
) : Closeable {
    private val lock = Any()
    private val json = Json {
        encodeDefaults = true
        explicitNulls = true
    }

    private val channel: Channel<AuditLogEvent>? =
        queueCapacity.takeIf { it > 0 }?.let { Channel(it) }

    private val writerScope: CoroutineScope? = channel?.let {
        CoroutineScope(SupervisorJob() + Dispatchers.IO)
    }

    private val writerJob: Job? = channel?.let { ch ->
        requireNotNull(writerScope).launch {
            for (event in ch) {
                processEvent(event)
            }
        }
    }

    fun logEvent(event: AuditLogEvent) {
        val stamped = event.withTimestamp(Instant.now().toString())
        if (channel != null) {
            if (channel.trySend(stamped).isFailure) {
                onError("${LOG_PREFIX}audit queue full, dropping event")
                onDrop()
            }
        } else {
            processEvent(stamped)
        }
    }

    fun log(event: AuditEvent) = logEvent(event)
    fun logToolEvent(event: AuditToolEvent) = logEvent(event)
    fun logStartupEvent(event: AuditStartupEvent) = logEvent(event)
    fun logPolicyReloadEvent(event: AuditPolicyReloadEvent) = logEvent(event)
    fun logCircuitBreakerEvent(event: AuditCircuitBreakerEvent) = logEvent(event)
    fun logAdminAccessEvent(event: AuditAdminAccessEvent) = logEvent(event)
    fun logPolicyFetchEvent(event: AuditPolicyFetchEvent) = logEvent(event)
    fun logIntegrityCheckEvent(event: AuditIntegrityCheckEvent) = logEvent(event)

    override fun close() {
        channel?.close()
        writerJob?.let { job ->
            runBlocking {
                withTimeoutOrNull(DRAIN_TIMEOUT_MS) { job.join() }
                    ?: onError("${LOG_PREFIX}audit writer coroutine did not stop within ${DRAIN_TIMEOUT_MS}ms")
            }
        }
        writerScope?.let { scope ->
            scope.coroutineContext[Job]?.cancel()
        }
        synchronized(lock) {
            outputStream.flush()
            if (closeOutputStream) {
                outputStream.close()
            }
        }
        runCatching { externalSink?.close() }.onFailure { error ->
            onError("${LOG_PREFIX}external sink close failed: ${error.message}")
        }
    }

    private fun processEvent(stamped: AuditLogEvent) {
        synchronized(lock) {
            writeJsonLine(stamped)
        }
        dispatchToSink(stamped)
    }

    private fun dispatchToSink(stamped: AuditLogEvent) {
        externalSink?.let { sink ->
            runCatching { sink.log(stamped) }.onFailure { error ->
                onError("${LOG_PREFIX}otel export failed: ${error.message}")
            }
        }
    }

    private fun writeJsonLine(event: AuditLogEvent) {
        runCatching {
            val line = when (event) {
                is AuditEvent -> json.encodeToString(AuditEvent.serializer(), event)
                is AuditToolEvent -> json.encodeToString(AuditToolEvent.serializer(), event)
                is AuditStartupEvent -> json.encodeToString(AuditStartupEvent.serializer(), event)
                is AuditPolicyReloadEvent -> json.encodeToString(AuditPolicyReloadEvent.serializer(), event)
                is AuditCircuitBreakerEvent -> json.encodeToString(AuditCircuitBreakerEvent.serializer(), event)
                is AuditAdminAccessEvent -> json.encodeToString(AuditAdminAccessEvent.serializer(), event)
                is AuditPolicyFetchEvent -> json.encodeToString(AuditPolicyFetchEvent.serializer(), event)
                is AuditIntegrityCheckEvent -> json.encodeToString(AuditIntegrityCheckEvent.serializer(), event)
            }
            outputStream.write((line + "\n").toByteArray(Charsets.UTF_8))
            outputStream.flush()
        }.onFailure { error ->
            onError("${LOG_PREFIX}audit write failed: ${error.message}")
        }
    }

    companion object {
        private const val DRAIN_TIMEOUT_MS = 5_000L
    }
}
