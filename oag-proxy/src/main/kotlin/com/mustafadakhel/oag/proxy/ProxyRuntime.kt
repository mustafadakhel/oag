package com.mustafadakhel.oag.proxy

import com.mustafadakhel.oag.BackgroundTaskRegistry
import com.mustafadakhel.oag.proxy.admin.AdminServer
import com.mustafadakhel.oag.proxy.lifecycle.IntegrityChecker
import com.mustafadakhel.oag.proxy.lifecycle.ShutdownResources
import com.mustafadakhel.oag.proxy.lifecycle.buildPolicyWatcher
import com.mustafadakhel.oag.proxy.lifecycle.buildReloadCallback
import com.mustafadakhel.oag.proxy.lifecycle.closeAll
import com.mustafadakhel.oag.proxy.lifecycle.installShutdownHook
import com.mustafadakhel.oag.proxy.lifecycle.launchAdminServer
import com.mustafadakhel.oag.proxy.lifecycle.launchIntegrityChecker
import com.mustafadakhel.oag.proxy.lifecycle.launchPoolEvictor
import com.mustafadakhel.oag.proxy.lifecycle.TASK_POLICY_WATCHER
import com.mustafadakhel.oag.proxy.lifecycle.launchPolicyFetcher

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.supervisorScope

import java.io.Closeable

internal class ProxyRuntime(private val config: ProxyConfig) : Closeable {
    private var shutdownResources: ShutdownResources? = null

    fun start() {
        validateProxyConfig(config)
        val components = buildComponents(config)

        val taskRegistry = BackgroundTaskRegistry()

        logStartupInfo(config, components.debugLogger, components.auditLogger, components.policyService.currentHash, config.tls.inspect, components.sslServerSocketFactory != null)

        val policyWatcher = if (config.policy.watch) {
            buildPolicyWatcher(config, components.debugLogger, components.auditLogger, components.policyService, components.rateLimiterRegistry).also {
                components.debugLogger.log("policy file watcher started")
            }
        } else {
            null
        }

        val server = ProxyServer(
            listenHost = config.listenHost,
            listenPort = config.listenPort,
            handler = components.handler,
            config = components.handlerConfig,
            maxThreads = config.maxThreads,
            sslServerSocketFactory = components.sslServerSocketFactory
        )

        lateinit var integrityCheckerRef: () -> IntegrityChecker?
        var adminServer: AdminServer? = null

        val reloadCallback = buildReloadCallback(
            config, components.debugLogger, components.auditLogger, components.webhookCallback,
            components.policyService, components.rateLimiterRegistry
        ) { integrityCheckerRef() }

        installSignalHandler("HUP") {
            reloadCallback(ReloadTrigger.SIGNAL)
        }

        runBlocking {
            supervisorScope {
                if (components.connectionPool != null) {
                    launchPoolEvictor(this, taskRegistry, config, components.connectionPool, components.debugLogger, components.oagMetrics)
                }

                if (policyWatcher != null) {
                    val watcherHandle = taskRegistry.register(TASK_POLICY_WATCHER)
                    watcherHandle.running = true
                    policyWatcher.start(this)
                }

                if (config.policy.url != null) {
                    launchPolicyFetcher(this, taskRegistry, config, components.debugLogger, components.auditLogger, reloadCallback)
                }

                if (config.admin.port != null) {
                    adminServer = launchAdminServer(
                        this, config, components.debugLogger, components.auditLogger, components.webhookCallback,
                        server, components.policyService, components.oagMetrics, components.connectionPool, reloadCallback,
                        taskRegistry,
                        pluginProviderCount = components.detectorRegistry.providers.size
                    )
                }

                val integrityChecker = if (config.integrityCheckIntervalS > 0) {
                    launchIntegrityChecker(
                        this, taskRegistry, config, components.debugLogger, components.auditLogger, components.webhookCallback, components.policyService
                    )
                } else null
                integrityCheckerRef = { integrityChecker }

                shutdownResources = ShutdownResources(
                    components = components,
                    adminServer = adminServer,
                    policyWatcher = policyWatcher
                )

                installShutdownHook(server, config.drainTimeoutMs, components.debugLogger, this)
                server.start()
            }
        }
    }

    override fun close() {
        shutdownResources?.closeAll()
    }
}

fun runProxy(config: ProxyConfig) {
    ProxyRuntime(config).use { it.start() }
}
