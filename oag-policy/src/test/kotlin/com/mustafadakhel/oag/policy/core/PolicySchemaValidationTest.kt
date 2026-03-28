package com.mustafadakhel.oag.policy.core

import com.mustafadakhel.oag.policy.distribution.policyYaml

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PolicySchemaValidationTest {

    @Test
    fun `YAML round-trip preserves all fields`() {
        val original = PolicySchemaValidation(
            schema = """{"type":"object"}""",
            onFail = "block",
            extractPath = "/choices/0/message/content",
            parseExtractedJson = true
        )
        val yaml = policyYaml.encodeToString(PolicySchemaValidation.serializer(), original)
        val decoded = policyYaml.decodeFromString(PolicySchemaValidation.serializer(), yaml)
        assertEquals(original, decoded)
    }

    @Test
    fun `YAML deserialization with minimal fields`() {
        val yaml = """
            schema: '{"type":"string"}'
        """.trimIndent()
        val result = policyYaml.decodeFromString(PolicySchemaValidation.serializer(), yaml)
        assertEquals("""{"type":"string"}""", result.schema)
        assertNull(result.onFail)
        assertNull(result.extractPath)
        assertNull(result.parseExtractedJson)
    }

    @Test
    fun `defaults are all null`() {
        val config = PolicySchemaValidation()
        assertNull(config.schema)
        assertNull(config.onFail)
        assertNull(config.extractPath)
        assertNull(config.parseExtractedJson)
    }

    @Test
    fun `YAML serialization uses snake_case field names`() {
        val config = PolicySchemaValidation(onFail = "pass", extractPath = "/a", parseExtractedJson = false)
        val yaml = policyYaml.encodeToString(PolicySchemaValidation.serializer(), config)
        assertTrue("on_fail" in yaml)
        assertTrue("extract_path" in yaml)
        assertTrue("parse_extracted_json" in yaml)
    }
}
