package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicyDocument

internal fun validateAgentProfiles(policy: PolicyDocument): List<ValidationError> = buildList {
    val profiles = policy.agentProfiles ?: return@buildList
    val allRuleIds = (policy.allow.orEmpty() + policy.deny.orEmpty()).mapNotNull { it.id?.trim() }.toSet()
    val seenIds = mutableSetOf<String>()

    profiles.forEachIndexed { index, profile ->
        val base = "agent_profiles[$index]"
        when {
            profile.id.isBlank() ->
                add(ValidationError("$base.id", ValidationMessage.MUST_NOT_BE_BLANK))
            profile.id.any(Char::isWhitespace) ->
                add(ValidationError("$base.id", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
            !seenIds.add(profile.id) ->
                add(ValidationError("$base.id", "Duplicate agent profile id '${profile.id}'"))
        }
        if (profile.allowedRules != null && profile.deniedRules != null) {
            add(ValidationError(base, "Cannot set both allowed_rules and denied_rules"))
        }
        if (profile.maxRequestsPerMinute != null && profile.maxRequestsPerMinute <= 0) {
            add(ValidationError("$base.max_requests_per_minute", ValidationMessage.MUST_BE_POSITIVE))
        }
        addAll(validateMaxBodyBytes(profile.maxBodyBytes, base))
        profile.allowedRules?.forEachIndexed { ruleIndex, ruleId ->
            if (ruleId.isBlank()) {
                add(ValidationError("$base.allowed_rules[$ruleIndex]", ValidationMessage.MUST_NOT_BE_BLANK))
            } else if (ruleId.trim() !in allRuleIds) {
                add(ValidationError("$base.allowed_rules[$ruleIndex]", "References unknown rule id '$ruleId'"))
            }
        }
        profile.deniedRules?.forEachIndexed { ruleIndex, ruleId ->
            if (ruleId.isBlank()) {
                add(ValidationError("$base.denied_rules[$ruleIndex]", ValidationMessage.MUST_NOT_BE_BLANK))
            } else if (ruleId.trim() !in allRuleIds) {
                add(ValidationError("$base.denied_rules[$ruleIndex]", "References unknown rule id '$ruleId'"))
            }
        }
        profile.tags?.forEachIndexed { tagIndex, tag ->
            if (tag.isBlank()) {
                add(ValidationError("$base.tags[$tagIndex]", ValidationMessage.MUST_NOT_BE_BLANK))
            } else if (tag.any(Char::isWhitespace)) {
                add(ValidationError("$base.tags[$tagIndex]", ValidationMessage.MUST_NOT_CONTAIN_WHITESPACE))
            }
        }
    }
}
