package com.mustafadakhel.oag.inspection.spi

import com.mustafadakhel.oag.inspection.Detector
import com.mustafadakhel.oag.inspection.Finding
import com.mustafadakhel.oag.inspection.FindingLocation
import com.mustafadakhel.oag.inspection.FindingSeverity
import com.mustafadakhel.oag.inspection.FindingType
import com.mustafadakhel.oag.inspection.RecommendedAction
import com.mustafadakhel.oag.inspection.InspectionContext
import com.mustafadakhel.oag.inspection.TextBody
import com.mustafadakhel.oag.inspection.Url

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DetectorRegistryTest {

    @Test
    fun `fromProviders aggregates detectors from multiple providers`() {
        val provider1 = testProvider("p1", listOf(textDetectorRegistration("d1")))
        val provider2 = testProvider("p2", listOf(textDetectorRegistration("d2")))

        val registry = DetectorRegistry.fromProviders(listOf(provider1, provider2))

        assertEquals(2, registry.allRegistrations().size)
        assertEquals(2, registry.detectorsFor(TextBody::class.java).size)
    }

    @Test
    fun `detectorsFor filters by artifact type`() {
        val textReg = textDetectorRegistration("text-det")
        val urlReg = DetectorRegistration(
            artifactType = Url::class.java,
            detector = Detector { _, _ -> emptyList() },
            findingTypes = setOf(FindingType.CUSTOM),
            id = "url-det"
        )
        val provider = testProvider("mixed", listOf(textReg, urlReg))

        val registry = DetectorRegistry.fromProviders(listOf(provider))

        assertEquals(1, registry.detectorsFor(TextBody::class.java).size)
        assertEquals(1, registry.detectorsFor(Url::class.java).size)
    }

    @Test
    fun `providers sorted by priority`() {
        val low = testProvider("low", emptyList(), priority = 200)
        val high = testProvider("high", emptyList(), priority = 10)
        val default = testProvider("default", emptyList())

        val registry = DetectorRegistry.fromProviders(listOf(low, default, high))

        assertEquals(listOf("high", "default", "low"), registry.providers.map { it.id })
    }

    @Test
    fun `close calls close on all providers`() {
        var closed1 = false
        var closed2 = false
        val p1 = object : DetectorProvider {
            override val id = "p1"
            override val description = "test"
            override fun detectors() = emptyList<DetectorRegistration<*>>()
            override fun close() { closed1 = true }
        }
        val p2 = object : DetectorProvider {
            override val id = "p2"
            override val description = "test"
            override fun detectors() = emptyList<DetectorRegistration<*>>()
            override fun close() { closed2 = true }
        }

        val registry = DetectorRegistry.fromProviders(listOf(p1, p2))
        registry.close()

        assertTrue(closed1)
        assertTrue(closed2)
    }

    @Test
    fun `close continues when provider throws`() {
        var closed2 = false
        val p1 = object : DetectorProvider {
            override val id = "p1"
            override val description = "test"
            override fun detectors() = emptyList<DetectorRegistration<*>>()
            override fun close() { throw RuntimeException("boom") }
        }
        val p2 = object : DetectorProvider {
            override val id = "p2"
            override val description = "test"
            override fun detectors() = emptyList<DetectorRegistration<*>>()
            override fun close() { closed2 = true }
        }

        val registry = DetectorRegistry.fromProviders(listOf(p1, p2))
        registry.close()

        assertTrue(closed2)
    }

    @Test
    fun `loadFromClassNames instantiates provider by class name`() {
        val registry = DetectorRegistry.loadFromClassNames(
            listOf("com.mustafadakhel.oag.inspection.spi.TestDetectorProvider")
        )

        assertEquals(1, registry.providers.size)
        assertEquals("test-provider", registry.providers[0].id)
        assertEquals(1, registry.allRegistrations().size)
    }

    @Test
    fun `loadFromClassNames skips invalid class names`() {
        val errors = mutableListOf<String>()
        val registry = DetectorRegistry.loadFromClassNames(
            listOf("com.nonexistent.FakeProvider"),
            onError = errors::add
        )

        assertTrue(registry.providers.isEmpty())
        assertTrue(errors.isNotEmpty())
        assertTrue(errors[0].contains("FakeProvider"))
    }

    @Test
    fun `loadFromClassNames with empty list returns empty registry`() {
        val registry = DetectorRegistry.loadFromClassNames(emptyList())

        assertTrue(registry.providers.isEmpty())
        assertTrue(registry.allRegistrations().isEmpty())
    }

    @Test
    fun `empty registry has no registrations`() {
        val registry = DetectorRegistry.empty()

        assertTrue(registry.allRegistrations().isEmpty())
        assertTrue(registry.providers.isEmpty())
        assertTrue(registry.detectorsFor(TextBody::class.java).isEmpty())
    }

    @Test
    fun `detector produces findings through registry`() {
        val finding = Finding(
            type = FindingType.CUSTOM,
            severity = FindingSeverity.HIGH,
            confidence = 0.9,
            location = FindingLocation.Body,
            evidence = mapOf("pattern" to "test"),
            recommendedActions = listOf(RecommendedAction.DENY)
        )
        val detector = Detector<TextBody> { _, _ -> listOf(finding) }
        val reg = DetectorRegistration(TextBody::class.java, detector, setOf(FindingType.CUSTOM), "test-det")
        val provider = testProvider("p", listOf(reg))

        val registry = DetectorRegistry.fromProviders(listOf(provider))
        val detectors = registry.detectorsFor(TextBody::class.java)
        val results = detectors.flatMap { it.inspect(TextBody("hello"), InspectionContext()) }

        assertEquals(1, results.size)
        assertEquals(FindingType.CUSTOM, results[0].type)
        assertEquals(0.9, results[0].confidence)
    }

    private fun testProvider(
        id: String,
        registrations: List<DetectorRegistration<*>>,
        priority: Int = DetectorProvider.DEFAULT_PRIORITY
    ) = object : DetectorProvider {
        override val id = id
        override val description = "test provider $id"
        override val priority = priority
        override fun detectors() = registrations
    }

    private fun textDetectorRegistration(id: String) = DetectorRegistration(
        artifactType = TextBody::class.java,
        detector = Detector<TextBody> { _, _ -> emptyList() },
        findingTypes = setOf(FindingType.CUSTOM),
        id = id
    )
}
