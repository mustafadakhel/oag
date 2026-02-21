package com.mustafadakhel.oag.inspection.content

private const val ALPHABET_SIZE = 256
private const val NO_TRANSITION = -1

class AhoCorasickAutomaton private constructor(
    private val goto: Array<Map<Int, Int>>,
    private val fail: IntArray,
    private val output: Array<List<Int>>,
    val patterns: List<String>
) {
    fun newMatcher(): AhoCorasickMatcher = AhoCorasickMatcher(this)

    internal fun nextState(state: Int, byte: Int): Int {
        var current = state
        // Terminates because root (state 0) has a transition for every byte value (set in computeFailureLinks).
        while (goto[current].getOrDefault(byte, NO_TRANSITION) == NO_TRANSITION) {
            current = fail[current]
        }
        return goto[current].getValue(byte)
    }

    internal fun outputAt(state: Int): List<Int> = output[state]

    companion object {
        fun build(patterns: List<String>): AhoCorasickAutomaton {
            require(patterns.isNotEmpty()) { "At least one pattern is required" }
            require(patterns.all { it.isNotEmpty() }) { "Patterns must not be empty" }

            val patternBytes = patterns.map { it.toByteArray(Charsets.UTF_8) }
            val maxStates = patternBytes.sumOf { it.size } + 1
            val goto = Array(maxStates) { IntArray(ALPHABET_SIZE) { NO_TRANSITION } }
            val fail = IntArray(maxStates)
            val output = Array<MutableList<Int>>(maxStates) { mutableListOf() }

            val stateCount = buildTrie(patternBytes, goto, output)
            computeFailureLinks(goto, fail, output)
            return compactAutomaton(goto, fail, output, stateCount, patterns)
        }

        private fun buildTrie(
            patternBytes: List<ByteArray>,
            goto: Array<IntArray>,
            output: Array<MutableList<Int>>
        ): Int {
            var stateCount = 1
            for ((patternIndex, bytes) in patternBytes.withIndex()) {
                var current = 0
                for (b in bytes) {
                    val byte = b.toInt() and 0xFF
                    if (goto[current][byte] == NO_TRANSITION) {
                        goto[current][byte] = stateCount++
                    }
                    current = goto[current][byte]
                }
                output[current].add(patternIndex)
            }
            return stateCount
        }

        private fun computeFailureLinks(
            goto: Array<IntArray>,
            fail: IntArray,
            output: Array<MutableList<Int>>
        ) {
            for (c in 0 until ALPHABET_SIZE) {
                if (goto[0][c] == NO_TRANSITION) {
                    goto[0][c] = 0
                }
            }

            val queue = ArrayDeque<Int>()
            for (c in 0 until ALPHABET_SIZE) {
                val s = goto[0][c]
                if (s != 0) {
                    fail[s] = 0
                    queue.addLast(s)
                }
            }

            while (queue.isNotEmpty()) {
                val r = queue.removeFirst()
                for (c in 0 until ALPHABET_SIZE) {
                    val s = goto[r][c]
                    if (s == NO_TRANSITION) continue
                    queue.addLast(s)
                    // Walk failure links toward root to find the longest suffix with a transition
                    // for character c. Terminates because fail[0] == 0 and goto[0][c] != NO_TRANSITION.
                    var state = fail[r]
                    while (goto[state][c] == NO_TRANSITION) {
                        state = fail[state]
                    }
                    fail[s] = goto[state][c]
                    output[s].addAll(output[fail[s]])
                }
            }
        }

        private fun compactAutomaton(
            goto: Array<IntArray>,
            fail: IntArray,
            output: Array<MutableList<Int>>,
            stateCount: Int,
            patterns: List<String>
        ): AhoCorasickAutomaton {
            val compactGoto = Array(stateCount) { i ->
                val row = goto[i]
                val map = HashMap<Int, Int>(8)
                for (c in 0 until ALPHABET_SIZE) {
                    if (row[c] != NO_TRANSITION) {
                        map[c] = row[c]
                    }
                }
                map as Map<Int, Int>
            }
            val trimmedFail = fail.copyOf(stateCount)
            val trimmedOutput = Array(stateCount) { output[it].toList() }
            return AhoCorasickAutomaton(compactGoto, trimmedFail, trimmedOutput, patterns)
        }
    }
}

data class AhoCorasickMatch(
    val patternIndex: Int,
    val endPosition: Long
)

class AhoCorasickMatcher(private val automaton: AhoCorasickAutomaton) {
    private var state: Int = 0
    private var position: Long = 0

    fun feed(data: ByteArray, offset: Int = 0, length: Int = data.size): List<AhoCorasickMatch> {
        require(offset >= 0 && length >= 0 && length <= data.size - offset) {
            "Invalid offset=$offset length=$length for data.size=${data.size}"
        }
        return buildList {
            for (i in offset until offset + length) {
                val byte = data[i].toInt() and 0xFF
                state = automaton.nextState(state, byte)
                position++
                for (patternIndex in automaton.outputAt(state)) {
                    add(AhoCorasickMatch(patternIndex, position))
                }
            }
        }
    }

    fun feed(data: String): List<AhoCorasickMatch> =
        feed(data.toByteArray(Charsets.UTF_8))

    fun reset() {
        state = 0
        position = 0
    }
}
