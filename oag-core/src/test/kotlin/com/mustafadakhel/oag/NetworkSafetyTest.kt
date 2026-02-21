package com.mustafadakhel.oag

import java.net.Inet6Address
import java.net.InetAddress

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class NetworkSafetyTest {

    private fun addr(ip: String): InetAddress = InetAddress.getByName(ip)

    @Test
    fun `loopback is special purpose`() {
        assertTrue(addr("127.0.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `any-local is special purpose`() {
        assertTrue(addr("0.0.0.0").isSpecialPurposeAddress())
    }

    @Test
    fun `link-local is special purpose`() {
        assertTrue(addr("169.254.1.1").isSpecialPurposeAddress())
    }

    @Test
    fun `site-local 10-dot is special purpose`() {
        assertTrue(addr("10.0.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `site-local 172-16 is special purpose`() {
        assertTrue(addr("172.16.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `site-local 192-168 is special purpose`() {
        assertTrue(addr("192.168.1.1").isSpecialPurposeAddress())
    }

    @Test
    fun `multicast is special purpose`() {
        assertTrue(addr("224.0.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `CGNAT 100-64 is special purpose`() {
        assertTrue(addr("100.64.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `CGNAT 100-127 is special purpose`() {
        assertTrue(addr("100.127.255.255").isSpecialPurposeAddress())
    }

    @Test
    fun `IETF protocol assignments 192-0-0 is special purpose`() {
        assertTrue(addr("192.0.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `documentation TEST-NET-1 is special purpose`() {
        assertTrue(addr("192.0.2.1").isSpecialPurposeAddress())
    }

    @Test
    fun `benchmarking 198-18 is special purpose`() {
        assertTrue(addr("198.18.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `benchmarking 198-19 is special purpose`() {
        assertTrue(addr("198.19.255.255").isSpecialPurposeAddress())
    }

    @Test
    fun `documentation TEST-NET-2 is special purpose`() {
        assertTrue(addr("198.51.100.1").isSpecialPurposeAddress())
    }

    @Test
    fun `documentation TEST-NET-3 is special purpose`() {
        assertTrue(addr("203.0.113.1").isSpecialPurposeAddress())
    }

    @Test
    fun `reserved class E is special purpose`() {
        assertTrue(addr("240.0.0.1").isSpecialPurposeAddress())
        assertTrue(addr("255.255.255.255").isSpecialPurposeAddress())
    }

    @Test
    fun `IPv6 loopback is special purpose`() {
        assertTrue(addr("::1").isSpecialPurposeAddress())
    }

    @Test
    fun `IPv6 ULA fc00 is special purpose`() {
        assertTrue(addr("fc00::1").isSpecialPurposeAddress())
    }

    @Test
    fun `IPv6 ULA fd00 is special purpose`() {
        assertTrue(addr("fd12::1").isSpecialPurposeAddress())
    }

    @Test
    fun `public IP is not special purpose`() {
        assertFalse(addr("8.8.8.8").isSpecialPurposeAddress())
    }

    @Test
    fun `public IP 1-1-1-1 is not special purpose`() {
        assertFalse(addr("1.1.1.1").isSpecialPurposeAddress())
    }

    @Test
    fun `public IP 93-184-216-34 is not special purpose`() {
        assertFalse(addr("93.184.216.34").isSpecialPurposeAddress())
    }

    @Test
    fun `100-0 outside CGNAT is not special purpose`() {
        assertFalse(addr("100.0.0.1").isSpecialPurposeAddress())
    }

    @Test
    fun `198-20 outside benchmarking is not special purpose`() {
        assertFalse(addr("198.20.0.1").isSpecialPurposeAddress())
    }
}
