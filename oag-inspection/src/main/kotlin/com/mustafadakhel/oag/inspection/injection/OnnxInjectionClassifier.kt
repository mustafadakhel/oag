package com.mustafadakhel.oag.inspection.injection

import ai.onnxruntime.OnnxTensor
import ai.onnxruntime.OrtEnvironment
import ai.onnxruntime.OrtSession

import java.nio.LongBuffer

class OnnxInjectionClassifier(
    private val session: OrtSession,
    private val maxLength: Int = DEFAULT_MAX_LENGTH,
    private val confidenceThreshold: Double = DEFAULT_CONFIDENCE_THRESHOLD,
    private val tokenizer: Tokenizer = CharCodeTokenizer()
) : InjectionClassifier, AutoCloseable {

    override fun classify(content: String): ClassificationResult {
        val encoding = tokenizer.encode(content, maxLength)
        val inputTensor = OnnxTensor.createTensor(
            OrtEnvironment.getEnvironment(),
            LongBuffer.wrap(encoding.ids),
            longArrayOf(1, encoding.ids.size.toLong())
        )
        val attentionMask = OnnxTensor.createTensor(
            OrtEnvironment.getEnvironment(),
            LongBuffer.wrap(encoding.attentionMask),
            longArrayOf(1, encoding.attentionMask.size.toLong())
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

    companion object {
        const val SOURCE = "onnx"
        const val DEFAULT_MAX_LENGTH = 512
        const val DEFAULT_CONFIDENCE_THRESHOLD = 0.8

        private const val INPUT_IDS = "input_ids"
        private const val ATTENTION_MASK = "attention_mask"

        fun createOrNull(
            modelPath: String,
            maxLength: Int = DEFAULT_MAX_LENGTH,
            confidenceThreshold: Double = DEFAULT_CONFIDENCE_THRESHOLD,
            tokenizer: Tokenizer = CharCodeTokenizer(),
            onError: (String) -> Unit = {}
        ): OnnxInjectionClassifier? = runCatching {
            val env = OrtEnvironment.getEnvironment()
            val session = env.createSession(modelPath)
            OnnxInjectionClassifier(session, maxLength, confidenceThreshold, tokenizer)
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
