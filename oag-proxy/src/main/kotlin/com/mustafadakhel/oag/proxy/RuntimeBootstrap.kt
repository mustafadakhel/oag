package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.audit.AuditLogger
import com.mustafadakhel.oag.audit.AuditStartupConfig
import com.mustafadakhel.oag.audit.AuditStartupEvent
import com.mustafadakhel.oag.label
import com.mustafadakhel.oag.proxy.lifecycle.computeConfigFingerprint
import com.mustafadakhel.oag.telemetry.DebugLogger

import java.lang.reflect.Proxy

internal fun buildStartupEvent(config: ProxyConfig, policyHash: String): AuditStartupEvent {
    val fingerprint = computeConfigFingerprint(config)
    return AuditStartupEvent(
        oagVersion = config.oagVersion,
        policyHash = policyHash,
        agentId = config.identity.agentId,
        sessionId = config.identity.sessionId,
        configFingerprint = fingerprint,
        config = AuditStartupConfig(
            policyPath = config.policy.path,
            policyPublicKeyPath = config.policy.publicKeyPath,
            policyRequireSignature = config.policy.requireSignature,
            logPath = config.log.path,
            listenHost = config.listenHost,
            listenPort = config.listenPort,
            maxThreads = config.maxThreads,
            secretEnvPrefix = config.secret.envPrefix,
            secretProvider = config.secret.provider.label(),
            secretFileDir = config.secret.fileDir,
            dryRun = config.dryRun,
            blockIpLiterals = config.network.blockIpLiterals,
            enforceRedirectPolicy = config.network.enforceRedirectPolicy,
            blockPrivateResolvedIps = config.network.blockPrivateResolvedIps,
            connectTimeoutMs = config.network.connectTimeoutMs,
            readTimeoutMs = config.network.readTimeoutMs,
            otelExporter = config.otelConfig.exporter.label(),
            otelEndpoint = config.otelConfig.endpoint,
            otelHeadersKeys = config.otelConfig.headers.keys.sorted(),
            otelTimeoutMs = config.otelConfig.takeIf { it.enabled }?.timeoutMs,
            otelServiceName = config.otelConfig.takeIf { it.enabled }?.serviceName
        )
    )
}

internal fun logStartupInfo(
    config: ProxyConfig,
    debugLogger: DebugLogger,
    auditLogger: AuditLogger,
    policyHash: String,
    hasTlsInspect: Boolean,
    hasMtls: Boolean
) {
    debugLogger.log("starting oag ${config.oagVersion} on ${config.listenHost}:${config.listenPort}")
    if (hasTlsInspect) debugLogger.log("tls interception enabled")
    if (hasMtls) debugLogger.log("mtls client authentication enabled")
    debugLogger.log("policy loaded hash=$policyHash")
    auditLogger.logStartupEvent(buildStartupEvent(config, policyHash))
}

internal fun installSignalHandler(
    signalName: String,
    onError: (String) -> Unit = System.err::println,
    handler: () -> Unit
) {
    try {
        val signalClass = Class.forName("sun.misc.Signal")
        val signalHandlerClass = Class.forName("sun.misc.SignalHandler")
        val signalConstructor = signalClass.getConstructor(String::class.java)
        val handleMethod = signalClass.getMethod("handle", signalClass, signalHandlerClass)
        val signal = signalConstructor.newInstance(signalName)
        val proxyHandler = Proxy.newProxyInstance(
            signalHandlerClass.classLoader,
            arrayOf(signalHandlerClass)
        ) { _, _, _ ->
            runCatching { handler() }.onFailure { e ->
                onError("${LOG_PREFIX}signal handler ($signalName) failed: ${e.message}")
            }
            null
        }
        handleMethod.invoke(null, signal, proxyHandler)
    } catch (_: ClassNotFoundException) {
        // sun.misc.Signal not available on this JVM — signal handling not supported
    } catch (_: IllegalArgumentException) {
        // Signal not available on this platform (e.g., HUP on Windows)
    } catch (e: java.lang.reflect.InvocationTargetException) {
        if (e.cause is IllegalArgumentException) {
            // Signal not available on this platform (wrapped by reflection invoke)
        } else {
            onError("${LOG_PREFIX}signal handler ($signalName) installation failed: ${e.cause?.message}")
        }
    } catch (e: Exception) {
        onError("${LOG_PREFIX}signal handler ($signalName) installation failed: ${e.message}")
    }
}

