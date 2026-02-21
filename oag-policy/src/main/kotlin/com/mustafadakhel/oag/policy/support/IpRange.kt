package com.mustafadakhel.oag.policy.support

import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

private const val IPV4_MAX_PREFIX = 32
private const val IPV6_MAX_PREFIX = 128

data class IpRange(
    val address: InetAddress,
    val prefixLength: Int
)

fun parseIpRange(value: String): IpRange {
    val trimmed = value.trim()
    val parts = trimmed.split("/", limit = 2)
    require(parts.size == 2) { "Invalid CIDR format" }
    val (addressStr, prefixStr) = parts
    val address = InetAddress.getByName(addressStr)
    val prefix = requireNotNull(prefixStr.toIntOrNull()) { "Invalid CIDR prefix length" }
    val max = when (address) {
        is Inet4Address -> IPV4_MAX_PREFIX
        is Inet6Address -> IPV6_MAX_PREFIX
        else -> error("Unsupported IP address")
    }
    require(prefix in 0..max) { "Invalid CIDR prefix length" }
    return IpRange(address, prefix)
}

fun IpRange.contains(address: InetAddress): Boolean {
    if (address.javaClass != this.address.javaClass) return false
    val bytes = address.address
    val base = this.address.address
    val fullBytes = prefixLength / 8
    val remainderBits = prefixLength % 8

    for (i in 0 until fullBytes) {
        if (bytes[i] != base[i]) return false
    }
    if (remainderBits == 0) return true
    val mask = (0xFF shl (8 - remainderBits)).toByte()
    return (bytes[fullBytes].toInt() and mask.toInt()) == (base[fullBytes].toInt() and mask.toInt())
}
