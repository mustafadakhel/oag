package com.mustafadakhel.oag.inspection.content

import com.mustafadakhel.oag.inspection.EvidenceKey
import com.mustafadakhel.oag.FindingType
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.ResponseTextBody
import com.mustafadakhel.oag.inspection.spi.DetectorRegistry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CodeSecurityDetectorProviderTest {

    private val provider = CodeSecurityDetectorProvider()

    @Test
    fun `provider loads via DetectorRegistry`() {
        val registry = DetectorRegistry.fromProviders(listOf(provider))

        assertEquals(1, registry.providers.size)
        assertEquals("oag-code-security", registry.providers[0].id)
    }

    @Test
    fun `registry returns detector for ResponseTextBody`() {
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val detectors = registry.detectorsFor(ResponseTextBody::class.java)

        assertEquals(1, detectors.size)
    }

    @Test
    fun `registration finding types contains CODE_VULNERABILITY`() {
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val registrations = registry.registrationsFor(ResponseTextBody::class.java)

        assertTrue(registrations.all { FindingType.CODE_VULNERABILITY in it.findingTypes })
    }

    @Test
    fun `end-to-end detection through provider`() {
        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val detectors = registry.detectorsFor(ResponseTextBody::class.java)
        val input = ResponseTextBody(
            text = "```python\nos.system(\"rm -rf /\")\n```",
            statusCode = 200,
            contentType = "text/plain"
        )

        val findings = detectors.flatMap { it.inspect(input, InspectionContext()) }

        assertTrue(findings.isNotEmpty())
        assertEquals(FindingType.CODE_VULNERABILITY, findings[0].type)
        assertEquals("cmd_os_system", findings[0].evidence[EvidenceKey.PATTERN])
    }
}
