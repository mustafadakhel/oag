package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class PolicySchemaValidation(
    val schema: String? = null,
    @SerialName("on_fail") val onFail: String? = null,
    @SerialName("extract_path") val extractPath: String? = null,
    @SerialName("parse_extracted_json") val parseExtractedJson: Boolean? = null
)
