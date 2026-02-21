package com.mustafadakhel.oag.policy.support

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

import java.net.InetAddress

class IpRangeTest {
    @Test
    fun `ipv4 range matches address`() {
        val range = parseIpRange("10.0.0.0/24")
        assertTrue(range.contains(InetAddress.getByName("10.0.0.10")))
        assertFalse(range.contains(InetAddress.getByName("10.0.1.10")))
    }

    @Test
    fun `ipv6 range matches address`() {
        val range = parseIpRange("2001:db8::/32")
        assertTrue(range.contains(InetAddress.getByName("2001:db8::1")))
        assertFalse(range.contains(InetAddress.getByName("2001:dead::1")))
    }

    @Test
    fun `ipv4 slash-0 matches everything`() {
        val range = parseIpRange("0.0.0.0/0")
        assertTrue(range.contains(InetAddress.getByName("10.0.0.1")))
        assertTrue(range.contains(InetAddress.getByName("192.168.1.1")))
        assertTrue(range.contains(InetAddress.getByName("255.255.255.255")))
    }

    @Test
    fun `ipv4 slash-32 matches exact address only`() {
        val range = parseIpRange("10.0.0.5/32")
        assertTrue(range.contains(InetAddress.getByName("10.0.0.5")))
        assertFalse(range.contains(InetAddress.getByName("10.0.0.4")))
        assertFalse(range.contains(InetAddress.getByName("10.0.0.6")))
    }

    @Test
    fun `ipv6 slash-128 matches exact address only`() {
        val range = parseIpRange("2001:db8::1/128")
        assertTrue(range.contains(InetAddress.getByName("2001:db8::1")))
        assertFalse(range.contains(InetAddress.getByName("2001:db8::2")))
    }

    @Test
    fun `ipv4 network address is included`() {
        val range = parseIpRange("10.0.0.0/24")
        assertTrue(range.contains(InetAddress.getByName("10.0.0.0")))
    }

    @Test
    fun `ipv4 broadcast address is included`() {
        val range = parseIpRange("10.0.0.0/24")
        assertTrue(range.contains(InetAddress.getByName("10.0.0.255")))
    }

}
