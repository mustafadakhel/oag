package com.mustafadakhel.oag.inspection.injection

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class OnnxInjectionClassifierTest {

    @Test
    fun `isAvailable returns true when ONNX runtime is on classpath`() {
        assertTrue(OnnxInjectionClassifier.isAvailable())
    }

    @Test
    fun `createOrNull returns null for missing model file`() {
        val errors = mutableListOf<String>()
        val classifier = OnnxInjectionClassifier.createOrNull(
            modelPath = "/nonexistent/model.onnx",
            onError = { errors.add(it) }
        )
        assertNull(classifier)
        assertTrue(errors.isNotEmpty())
    }

    @Test
    fun `source is onnx`() {
        assertTrue(OnnxInjectionClassifier.SOURCE == "onnx")
    }
}
