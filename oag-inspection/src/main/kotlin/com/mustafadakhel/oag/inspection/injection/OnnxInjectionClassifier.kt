package com.mustafadakhel.oag.inspection.injection

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession

import java.nio.LongBuffer

class OnnxInjectionClassifier(
    private val session: OrtSession,
    private val maxLength: Int = DEFAULT_MAX_LENGTH,
    private val confidenceThreshold: Double = DEFAULT_CONFIDENCE_THRESHOLD
) : InjectionClassifier, AutoCloseable {

    override fun classify(content: String): ClassificationResult {
        val tokenIds = tokenize(content)
        val inputTensor = OnnxTensor.createTensor(
            OrtEnvironment.getEnvironment(),
            LongBuffer.wrap(tokenIds),
            longArrayOf(1, tokenIds.size.toLong())
        )
        val attentionMask = OnnxTensor.createTensor(
            OrtEnvironment.getEnvironment(),
            LongBuffer.wrap(LongArray(tokenIds.size) { 1L }),
            longArrayOf(1, tokenIds.size.toLong())
        )
        val inputs = mapOf(INPUT_IDS to inputTensor, ATTENTION_MASK to attentionMask)
        val output = session.run(inputs)
        val logits = (output[0].value as Array<FloatArray>)[0]
        val score = softmaxInjectionScore(logits)

        return ClassificationResult(
            score = score,
            signals = if (score >= confidenceThreshold) listOf("ml:onnx") else emptyList(),
            source = SOURCE
        )
    }

    override fun close() {
        session.close()
    }

    private fun tokenize(text: String): LongArray {
        val tokens = mutableListOf(CLS_TOKEN_ID)
        for (char in text.take(maxLength)) {
            tokens.add(char.code.toLong())
        }
        tokens.add(SEP_TOKEN_ID)
        return tokens.toLongArray()
    }

    companion object {
        const val SOURCE = "onnx"
        const val DEFAULT_MAX_LENGTH = 512
        const val DEFAULT_CONFIDENCE_THRESHOLD = 0.8

        private const val INPUT_IDS = "input_ids"
        private const val ATTENTION_MASK = "attention_mask"
        private const val CLS_TOKEN_ID = 101L
        private const val SEP_TOKEN_ID = 102L

        fun createOrNull(
            modelPath: String,
            maxLength: Int = DEFAULT_MAX_LENGTH,
            confidenceThreshold: Double = DEFAULT_CONFIDENCE_THRESHOLD,
            onError: (String) -> Unit = {}
        ): OnnxInjectionClassifier? = runCatching {
            val env = OrtEnvironment.getEnvironment()
            val session = env.createSession(modelPath)
            OnnxInjectionClassifier(session, maxLength, confidenceThreshold)
        }.onFailure { e ->
            onError("ONNX classifier creation failed: ${e.message}")
        }.getOrNull()

        fun isAvailable(): Boolean = runCatching {
            Class.forName("ai.onnxruntime.OrtEnvironment")
        }.isSuccess

        private fun softmaxInjectionScore(logits: FloatArray): Double {
            if (logits.size < 2) return 0.0
            val max = logits.max()
            val exps = logits.map { Math.exp((it - max).toDouble()) }
            val sum = exps.sum()
            return exps[1] / sum
        }
    }
}
