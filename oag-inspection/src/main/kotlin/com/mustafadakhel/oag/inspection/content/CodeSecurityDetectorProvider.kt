package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.ResponseTextBody
import com.mustafadakhel.oag.inspection.spi.DetectorProvider
import com.mustafadakhel.oag.inspection.spi.DetectorRegistration

class CodeSecurityDetectorProvider : DetectorProvider {
    override val id = "oag-code-security"
    override val description = "Detects common vulnerability patterns in LLM-generated code"

    override fun detectors(): List<DetectorRegistration<*>> = listOf(
        DetectorRegistration(
            artifactType = ResponseTextBody::class.java,
            detector = CodeSecurityDetector(),
            findingTypes = setOf(FindingType.CODE_VULNERABILITY),
            id = "code-security"
        )
    )
}
