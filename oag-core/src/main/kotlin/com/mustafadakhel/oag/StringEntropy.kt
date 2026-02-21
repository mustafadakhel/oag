package com.mustafadakhel.oag

import kotlin.math.log2

fun String.shannonEntropy(): Double {
    if (isEmpty()) return 0.0
    val freq = groupingBy { it }.eachCount()
    val len = length.toDouble()
    return freq.values.fold(0.0) { acc, count ->
        val probability = count / len
        acc - probability * log2(probability)
    }
}
