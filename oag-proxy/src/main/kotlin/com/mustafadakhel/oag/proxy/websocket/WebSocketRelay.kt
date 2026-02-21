package com.mustafadakhel.oag.proxy.websocket

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.audit.AuditWebSocketSession
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import com.mustafadakhel.oag.policy.core.PolicyContentInspection
import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.proxy.ProxyDefaults

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.util.concurrent.atomic.AtomicLong

private const val WS_POLICY_VIOLATION_CODE = 4403

data class WebSocketRelayResult(
    val session: AuditWebSocketSession,
    val detectedPatterns: List<String>,
    val dataClassificationMatches: List<String>
)

internal suspend fun relayWebSocketSession(
    clientInput: InputStream,
    clientOutput: OutputStream,
    serverInput: InputStream,
    serverOutput: OutputStream,
    contentInspection: PolicyContentInspection?,
    dataClassification: PolicyDataClassification?,
    readTimeoutMs: Int,
    detectorRegistry: DetectorRegistry = DetectorRegistry.empty(),
    inspectionContext: InspectionContext? = null,
    wsSessionTimeoutMs: Long = ProxyDefaults.WS_SESSION_TIMEOUT_MS,
    onError: (String) -> Unit = { System.err.println("${LOG_PREFIX}$it") }
): WebSocketRelayResult = coroutineScope {
    val clientFrames = AtomicLong(0L)
    val serverFrames = AtomicLong(0L)
    val inspectionEnabled = contentInspection?.scanWebSocketFrames != false
    val inspector = WebSocketInspector(
        if (inspectionEnabled) contentInspection else null,
        if (inspectionEnabled) dataClassification else null,
        detectorRegistry = detectorRegistry,
        inspectionContext = inspectionContext
    )

    val clientToServer = launch(Dispatchers.IO) {
        relayFrames(clientInput, serverOutput, clientFrames, inspector, WsDirection.CLIENT_TO_SERVER)
    }

    val serverToClient = launch(Dispatchers.IO) {
        relayFrames(serverInput, clientOutput, serverFrames, inspector, WsDirection.SERVER_TO_CLIENT)
    }

    val sessionTimeout = maxOf(wsSessionTimeoutMs, readTimeoutMs.toLong())
    withTimeoutOrNull(sessionTimeout) {
        // When either direction completes (DENY, close frame, or disconnect),
        // cancel the other to prevent orphaned relay coroutines.
        // Structured concurrency: scope waits for both launches to finish.
        launch {
            clientToServer.join()
            serverToClient.cancel()
        }
        launch {
            serverToClient.join()
            clientToServer.cancel()
        }
    }
    clientToServer.cancel()
    serverToClient.cancel()
    val closeFrame = WebSocketFrame.buildCloseFrame()
    runCatching { writeWebSocketFrame(serverOutput, closeFrame) }.onFailure { e ->
        onError("websocket close frame to server failed: ${e.message}")
    }
    runCatching { writeWebSocketFrame(clientOutput, closeFrame) }.onFailure { e ->
        onError("websocket close frame to client failed: ${e.message}")
    }

    val detectedList = inspector.detectedPatterns.toList()
    val dataClassList = inspector.dataClassificationMatches.toList()
    val totalFrames = clientFrames.get() + serverFrames.get()
    val session = AuditWebSocketSession(
        frameCount = totalFrames,
        clientFrames = clientFrames.get(),
        serverFrames = serverFrames.get(),
        detectedPatterns = detectedList.ifEmpty { null },
        dataClassificationMatches = dataClassList.ifEmpty { null }
    )
    WebSocketRelayResult(
        session = session,
        detectedPatterns = detectedList,
        dataClassificationMatches = dataClassList
    )
}

private suspend fun relayFrames(
    input: InputStream,
    output: OutputStream,
    frameCounter: AtomicLong,
    inspector: WebSocketInspector,
    direction: WsDirection
) {
    try {
        while (currentCoroutineContext().isActive) {
            val frame = readWebSocketFrame(input) ?: break
            frameCounter.incrementAndGet()
            val inspectionResult = inspector.inspectFrame(frame, direction)
            if (inspectionResult == WebSocketInspector.FrameInspectionResult.DENY) {
                val closeFrame = WebSocketFrame.buildCloseFrame(code = WS_POLICY_VIOLATION_CODE)
                runCatching { writeWebSocketFrame(output, closeFrame) }
                break
            }
            writeWebSocketFrame(output, frame)
            if (frame.isClose) break
        }
    } catch (_: IOException) {
        // Stream closed — expected on disconnect
    } catch (_: IllegalArgumentException) {
        // Malformed frame — close relay
    }
}
