package com.mustafadakhel.oag

import java.util.Locale

fun Enum<*>.label(): String = name.lowercase(Locale.ROOT)
