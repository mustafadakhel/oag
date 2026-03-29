package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicySchemaValidation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SchemaValidationValidatorTest {

    private fun validate(config: PolicySchemaValidation) = config.validate("test")

    @Test
    fun `blank schema fails`() {
        val errors = validate(PolicySchemaValidation(schema = ""))
        assertTrue(errors.any { "schema" in it.path && "Must be set" in it.message })
    }

    @Test
    fun `null schema fails`() {
        val errors = validate(PolicySchemaValidation())
        assertTrue(errors.any { "schema" in it.path })
    }

    @Test
    fun `valid schema passes`() {
        val errors = validate(PolicySchemaValidation(schema = """{"type":"object"}"""))
        assertTrue(errors.none { "schema" in it.path })
    }

    @Test
    fun `onFail block passes`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", onFail = "block"))
        assertTrue(errors.none { "on_fail" in it.path })
    }

    @Test
    fun `onFail pass passes`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", onFail = "pass"))
        assertTrue(errors.none { "on_fail" in it.path })
    }

    @Test
    fun `onFail invalid value fails`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", onFail = "ignore"))
        assertTrue(errors.any { "on_fail" in it.path })
    }

    @Test
    fun `valid extractPath passes`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", extractPath = "/choices/0/message/content"))
        assertTrue(errors.none { "extract_path" in it.path })
    }

    @Test
    fun `extractPath without leading slash fails`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", extractPath = "choices/0"))
        assertTrue(errors.any { "extract_path" in it.path })
    }

    @Test
    fun `extractPath too long fails`() {
        val errors = validate(PolicySchemaValidation(schema = "{}", extractPath = "/" + "a".repeat(600)))
        assertTrue(errors.any { "extract_path" in it.path })
    }

    @Test
    fun `fully valid config produces no errors`() {
        val errors = validate(PolicySchemaValidation(
            schema = """{"type":"object","properties":{"name":{"type":"string"}}}""",
            onFail = "block",
            extractPath = "/choices/0/message/content",
            parseExtractedJson = true
        ))
        assertEquals(emptyList(), errors)
    }
}
