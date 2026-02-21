package com.mustafadakhel.oag.inspection.spi

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.InspectableArtifact

data class DetectorRegistration<T : InspectableArtifact>(
    val artifactType: Class<T>,
    val detector: Detector<T>,
    val findingTypes: Set<FindingType>,
    val id: String
)
