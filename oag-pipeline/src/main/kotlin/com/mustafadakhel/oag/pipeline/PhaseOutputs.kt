package com.mustafadakhel.oag.pipeline

interface PhaseKey<T : Any>

class PhaseOutputs {
    private val map = mutableMapOf<PhaseKey<*>, Any>()

    fun <T : Any> put(key: PhaseKey<T>, value: T) {
        map[key] = value
    }

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> getOrNull(key: PhaseKey<T>): T? = map[key] as? T

    @Suppress("UNCHECKED_CAST")
    fun <T : Any> get(key: PhaseKey<T>): T =
        map[key] as? T ?: error("Phase output not set for ${key::class.simpleName}")

    operator fun contains(key: PhaseKey<*>): Boolean = key in map
}
