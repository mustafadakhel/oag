package com.mustafadakhel.oag.policy.core

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

enum class PolicyAction {
    ALLOW,
    DENY
}

@Serializable
data class PolicyDocument(
    val version: Int? = null,
    val includes: List<String>? = null,
    val defaults: PolicyDefaults? = null,
    val allow: List<PolicyRule>? = null,
    val deny: List<PolicyRule>? = null,
    @SerialName("secret_scopes") val secretScopes: List<SecretScope>? = null,
    @SerialName("agent_profiles") val agentProfiles: List<PolicyAgentProfile>? = null
)
