package com.mustafadakhel.oag.pipeline

import java.net.InetAddress

fun interface HostResolver {
    fun resolve(host: String): List<InetAddress>
}
