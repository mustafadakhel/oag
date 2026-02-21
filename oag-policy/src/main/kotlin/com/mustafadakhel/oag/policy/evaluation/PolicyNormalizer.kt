package com.mustafadakhel.oag.policy.evaluation

import com.mustafadakhel.oag.policy.core.PolicyDataClassification
import com.mustafadakhel.oag.policy.core.PolicyDefaults
import com.mustafadakhel.oag.policy.core.PolicyDocument
import com.mustafadakhel.oag.policy.core.PolicyRule
import com.mustafadakhel.oag.policy.core.SecretScope
import com.mustafadakhel.oag.policy.evaluation.dimension.matchDimensions

import java.util.Locale

fun PolicyDocument.normalize(): PolicyDocument =
    copy(
        defaults = defaults?.normalize(),
        allow = allow?.map { it.normalize() },
        deny = deny?.map { it.normalize() },
        secretScopes = secretScopes?.map { it.normalize() }
    )

private fun PolicyDefaults.normalize(): PolicyDefaults =
    copy(dataClassification = dataClassification?.normalize())

private fun PolicyDataClassification.normalize(): PolicyDataClassification =
    copy(categories = categories?.map { it.lowercase(Locale.ROOT) })

private fun PolicyRule.normalize(): PolicyRule {
    val dimensionNormalized = matchDimensions.fold(this) { rule, dim -> dim.normalize(rule) }
    return dimensionNormalized.copy(
        id = id?.trim(),
        secrets = secrets?.mapNotNull { it.trim().ifEmpty { null } },
        reasonCode = reasonCode?.trim(),
        dataClassification = dataClassification?.normalize(),
        webhookEvents = webhookEvents
            ?.mapNotNull { it.trim().lowercase(Locale.ROOT).ifEmpty { null } }
            ?.distinct()
    )
}

private fun SecretScope.normalize(): SecretScope =
    copy(
        id = id?.trim(),
        hosts = normalizeHosts(hosts),
        methods = normalizeMethods(methods),
        paths = normalizePaths(paths),
        ipRanges = normalizeIpRanges(ipRanges)
    )
