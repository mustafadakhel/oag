package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.label

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ReasonCodeContractTest {
    @Test
    fun `reason codes are unique and snake_case`() {
        val codes = ReasonCode.entries.map { it.label() }
        assertEquals(codes.size, codes.toSet().size, "reason codes must be unique")
        codes.forEach { code ->
            assertTrue(code.matches(Regex("^[a-z0-9_]+$")), "reason code must be snake_case: $code")
        }
    }
}
