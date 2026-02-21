package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.label

enum class SensitiveDataCategory {
    FINANCIAL,
    CREDENTIALS,
    PII;

    companion object {
        val validLabels: Set<String> = entries.map { it.label() }.toSet()
    }
}
