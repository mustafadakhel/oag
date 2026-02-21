package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.IO_BUFFER_SIZE
import com.mustafadakhel.oag.LOG_PREFIX
import com.mustafadakhel.oag.inspection.content.AhoCorasickAutomaton
import com.mustafadakhel.oag.policy.core.PolicyBodyMatch
import com.mustafadakhel.oag.cachedRegex
import com.mustafadakhel.oag.policy.lifecycle.PolicyService
import com.mustafadakhel.oag.http.HttpConstants
import com.mustafadakhel.oag.pipeline.DEFAULT_RESPONSE_SCAN_LIMIT
import com.mustafadakhel.oag.pipeline.HEX_TOKEN_REGEX
import com.mustafadakhel.oag.pipeline.MAX_CHUNK_SIZE
import com.mustafadakhel.oag.pipeline.inspection.RegexPatternEntry
import com.mustafadakhel.oag.pipeline.inspection.StreamingScanResult
import com.mustafadakhel.oag.pipeline.inspection.StreamingScanner
import com.mustafadakhel.oag.pipeline.phase.validateHeaderLine
import com.mustafadakhel.oag.pipeline.readLine

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

private data class ChunkHeader(val sizeLine: String, val chunkSize: Long)

private fun readChunkHeader(upstreamIn: InputStream): ChunkHeader {
    val sizeLine = requireNotNull(readLine(upstreamIn)) { "Malformed chunked response" }
    val sizeToken = sizeLine.substringBefore(';').trim()
    require(sizeToken.matches(HEX_TOKEN_REGEX)) { "Malformed chunk size" }
    val chunkSize = sizeToken.toLongOrNull(16)
    requireNotNull(chunkSize) { "Malformed chunk size" }
    require(chunkSize >= 0) { "Invalid chunk size" }
    require(chunkSize <= MAX_CHUNK_SIZE) { "Chunk size exceeds maximum ($MAX_CHUNK_SIZE bytes)" }
    return ChunkHeader(sizeLine, chunkSize)
}

private fun relayTrailers(upstreamIn: InputStream, clientOutput: OutputStream): Long {
    var bytes = 0L
    while (true) {
        val trailerLine = requireNotNull(readLine(upstreamIn)) { "Malformed chunk trailer" }
        if (trailerLine.isNotEmpty()) {
            validateHeaderLine(trailerLine, "Invalid chunk trailer header")
        }
        val trailerBytes = "$trailerLine${HttpConstants.CRLF}".toByteArray(Charsets.US_ASCII)
        clientOutput.write(trailerBytes)
        bytes += trailerBytes.size
        if (trailerLine.isEmpty()) return bytes
    }
}

fun relayChunkedResponse(
    upstreamIn: InputStream,
    clientOutput: OutputStream,
    scanner: StreamingScanner? = null,
    enforcementMode: Boolean = false,
    policyService: PolicyService? = null,
    onError: (String) -> Unit = defaultRelayErrorHandler
): StreamingScanResult {
    val automaton = scanner?.automaton
    val acMatcher = automaton?.newMatcher()
    val matchedPatterns = mutableSetOf<String>()
    val scanLimit = policyService?.current?.defaults?.maxResponseScanBytes ?: DEFAULT_RESPONSE_SCAN_LIMIT
    val needsAccumulation = scanner?.regexPatterns?.isNotEmpty() == true || scanner?.accumulateForPlugins == true
    val regexBuffer = if (needsAccumulation) StringBuilder() else null
    val unmatchedRegex = scanner?.regexPatterns?.toMutableList()
    var total = 0L
    val buffer = ByteArray(IO_BUFFER_SIZE)

    chunks@ while (true) {
        val (sizeLine, chunkSize) = readChunkHeader(upstreamIn)
        val sizeLineBytes = "$sizeLine${HttpConstants.CRLF}".toByteArray(Charsets.US_ASCII)
        clientOutput.write(sizeLineBytes)
        total += sizeLineBytes.size

        if (chunkSize == 0L) {
            total += relayTrailers(upstreamIn, clientOutput)
            clientOutput.flush()
            return StreamingScanResult(total, matchedPatterns.toList(), truncated = false, accumulatedBody = regexBuffer?.toString())
        }

        if (scanner != null) {
            var remaining = chunkSize
            while (remaining > 0) {
                val read = try {
                    upstreamIn.read(buffer, 0, minOf(buffer.size.toLong(), remaining).toInt())
                } catch (e: Exception) {
                    throw IOException("chunked relay read failed remaining=$remaining: ${e.message}", e)
                }
                if (read == -1) break
                clientOutput.write(buffer, 0, read)

                if (acMatcher != null) {
                    val matches = acMatcher.feed(buffer, 0, read)
                    for (match in matches) {
                        matchedPatterns.add(requireNotNull(automaton).patterns[match.patternIndex])
                    }
                }

                if (regexBuffer != null && regexBuffer.length < scanLimit) {
                    regexBuffer.append(String(buffer, 0, read, Charsets.UTF_8))
                    val iter = requireNotNull(unmatchedRegex).iterator()
                    while (iter.hasNext()) {
                        val (source, regex) = iter.next()
                        if (runCatching { regex.containsMatchIn(regexBuffer) }
                            .onFailure { e -> onError("chunked scan regex failed source=$source: ${e.message}") }
                            .getOrDefault(true)) {
                            matchedPatterns.add("regex:$source")
                            iter.remove()
                        }
                    }
                }

                remaining -= read
                total += read

                if (matchedPatterns.isNotEmpty() && enforcementMode) {
                    clientOutput.flush()
                    return StreamingScanResult(total, matchedPatterns.toList(), truncated = true, accumulatedBody = regexBuffer?.toString())
                }
            }
            if (matchedPatterns.isEmpty() || !enforcementMode) {
                require(remaining == 0L) { "Truncated chunked body" }
            }
        } else {
            total += relayExactBytes(upstreamIn, clientOutput, chunkSize)
        }

        val chunkTerminator = requireNotNull(readLine(upstreamIn)) { "Malformed chunk terminator" }
        require(chunkTerminator.isEmpty()) { "Malformed chunk terminator" }
        clientOutput.write(HttpConstants.CRLF.toByteArray(Charsets.US_ASCII))
        total += 2
    }
}

fun buildStreamingScanner(responseMatch: PolicyBodyMatch, onError: (String) -> Unit = defaultRelayErrorHandler): StreamingScanner? {
    val contains = responseMatch.contains
    val automaton = contains?.takeIf { it.isNotEmpty() }?.let { AhoCorasickAutomaton.build(it) }

    val regexPatterns = responseMatch.patterns?.mapNotNull { pattern ->
        runCatching { RegexPatternEntry(pattern, cachedRegex(pattern)) }
            .onFailure { e -> onError("response scan regex compilation failed pattern=$pattern: ${e.message}") }
            .getOrNull()
    } ?: emptyList()

    if (automaton == null && regexPatterns.isEmpty()) return null
    return StreamingScanner(automaton, regexPatterns)
}
