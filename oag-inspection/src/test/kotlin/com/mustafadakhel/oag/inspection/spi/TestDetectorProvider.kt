package com.mustafadakhel.oag.inspection.spi

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.TextBody

class TestDetectorProvider : DetectorProvider {
    override val id = "test-provider"
    override val description = "Test provider for loadFromClassNames"

    override fun detectors(): List<DetectorRegistration<*>> = listOf(
        DetectorRegistration(
            artifactType = TextBody::class.java,
            detector = Detector { _, _ -> emptyList() },
            findingTypes = setOf(FindingType.CUSTOM),
            id = "test-detector"
        )
    )
}
