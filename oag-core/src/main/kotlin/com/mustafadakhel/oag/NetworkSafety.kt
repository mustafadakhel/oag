package com.mustafadakhel.oag

import java.net.Inet6Address
import java.net.InetAddress

/**
 * Returns `true` if this address belongs to a special-purpose range that should
 * not be reachable as an upstream destination (loopback, private, link-local,
 * CGNAT, documentation, benchmarking, reserved, ULA IPv6, etc.).
 */
fun InetAddress.isSpecialPurposeAddress(): Boolean {
    if (isAnyLocalAddress || isLoopbackAddress || isLinkLocalAddress || isSiteLocalAddress || isMulticastAddress) {
        return true
    }
    val addr = address
    if (addr.size == IPv4_BYTE_COUNT) {
        val b0 = addr[0].toInt() and BYTE_MASK
        val b1 = addr[1].toInt() and BYTE_MASK
        val b2 = addr[2].toInt() and BYTE_MASK
        // 100.64.0.0/10 — CGNAT (RFC 6598), often reaches cloud metadata services
        if (b0 == CGNAT_FIRST_OCTET && (b1 and CGNAT_MASK) == CGNAT_SECOND_OCTET) return true
        // 192.0.0.0/24 — IETF Protocol Assignments (RFC 6890)
        if (b0 == IETF_FIRST_OCTET && b1 == 0 && b2 == 0) return true
        // 192.0.2.0/24 — Documentation TEST-NET-1 (RFC 5737)
        if (b0 == IETF_FIRST_OCTET && b1 == 0 && b2 == TEST_NET_1_THIRD_OCTET) return true
        // 198.18.0.0/15 — Benchmarking (RFC 2544)
        if (b0 == BENCH_FIRST_OCTET && (b1 == BENCH_SECOND_LOW || b1 == BENCH_SECOND_HIGH)) return true
        // 198.51.100.0/24 — Documentation TEST-NET-2 (RFC 5737)
        if (b0 == BENCH_FIRST_OCTET && b1 == TEST_NET_2_SECOND_OCTET && b2 == TEST_NET_2_THIRD_OCTET) return true
        // 203.0.113.0/24 — Documentation TEST-NET-3 (RFC 5737)
        if (b0 == TEST_NET_3_FIRST_OCTET && b1 == 0 && b2 == TEST_NET_3_THIRD_OCTET) return true
        // 240.0.0.0/4 — Reserved (formerly Class E, RFC 1112)
        if (b0 and CLASS_E_MASK == CLASS_E_MASK) return true
    }
    if (this is Inet6Address) {
        val first = addr.firstOrNull()?.toInt()?.and(BYTE_MASK) ?: return false
        if ((first and ULA_MASK) == ULA_PREFIX) return true
    }
    return false
}

private const val IPv4_BYTE_COUNT = 4
private const val BYTE_MASK = 0xFF
private const val CGNAT_FIRST_OCTET = 100
private const val CGNAT_SECOND_OCTET = 64
private const val CGNAT_MASK = 0xC0
private const val IETF_FIRST_OCTET = 192
private const val TEST_NET_1_THIRD_OCTET = 2
private const val BENCH_FIRST_OCTET = 198
private const val BENCH_SECOND_LOW = 18
private const val BENCH_SECOND_HIGH = 19
private const val TEST_NET_2_SECOND_OCTET = 51
private const val TEST_NET_2_THIRD_OCTET = 100
private const val TEST_NET_3_FIRST_OCTET = 203
private const val TEST_NET_3_THIRD_OCTET = 113
private const val CLASS_E_MASK = 0xF0
private const val ULA_MASK = 0xFE
private const val ULA_PREFIX = 0xFC
