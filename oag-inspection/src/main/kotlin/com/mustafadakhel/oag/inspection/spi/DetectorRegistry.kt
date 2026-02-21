package com.mustafadakhel.oag.inspection.spi

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.InspectableArtifact

class DetectorRegistry private constructor(
    val providers: List<DetectorProvider>,
    private val registrations: List<DetectorRegistration<*>>
) : AutoCloseable {

    @Suppress("UNCHECKED_CAST")
    fun <T : InspectableArtifact> detectorsFor(artifactType: Class<T>): List<Detector<T>> =
        registrations
            .filter { it.artifactType == artifactType }
            .map { it.detector as Detector<T> }

    @Suppress("UNCHECKED_CAST")
    fun <T : InspectableArtifact> registrationsFor(artifactType: Class<T>): List<DetectorRegistration<T>> =
        registrations
            .filter { it.artifactType == artifactType }
            .map { it as DetectorRegistration<T> }

    fun allRegistrations(): List<DetectorRegistration<*>> = registrations

    override fun close() = close {}

    fun close(onError: (String) -> Unit) {
        providers.forEach { provider ->
            runCatching { provider.close() }
                .onFailure { e -> onError("Failed to close detector provider '${provider.id}': ${e.message}") }
        }
    }

    companion object {
        fun loadFromClassNames(
            classNames: List<String>,
            classLoader: ClassLoader = Thread.currentThread().contextClassLoader,
            onError: (String) -> Unit = {}
        ): DetectorRegistry {
            if (classNames.isEmpty()) return empty()

            val providers = classNames.mapNotNull { className ->
                runCatching {
                    val clazz = Class.forName(className, true, classLoader)
                    clazz.getDeclaredConstructor().newInstance() as DetectorProvider
                }.onFailure { e ->
                    onError("Failed to load detector provider '$className': ${e.message}")
                }.getOrNull()
            }.sortedBy { it.priority }

            val registrations = providers.flatMap { provider ->
                runCatching { provider.detectors() }
                    .onFailure { e -> onError("Failed to load detectors from provider '${provider.id}': ${e.message}") }
                    .getOrDefault(emptyList())
            }

            return DetectorRegistry(providers, registrations)
        }

        fun fromProviders(providers: List<DetectorProvider>): DetectorRegistry {
            val sorted = providers.sortedBy { it.priority }
            val registrations = sorted.flatMap { it.detectors() }
            return DetectorRegistry(sorted, registrations)
        }

        fun empty() = DetectorRegistry(emptyList(), emptyList())
    }
}
