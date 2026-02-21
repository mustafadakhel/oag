package com.mustafadakhel.oag.inspection.spi

interface DetectorProvider {
    val id: String
    val description: String
    val priority: Int get() = DEFAULT_PRIORITY
    fun detectors(): List<DetectorRegistration<*>>
    fun close() {}

    companion object {
        const val DEFAULT_PRIORITY = 100
    }
}
