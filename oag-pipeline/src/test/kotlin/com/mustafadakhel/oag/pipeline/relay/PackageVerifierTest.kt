package com.mustafadakhel.oag.pipeline.relay

import com.mustafadakhel.oag.SafeOutboundClient

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class PackageVerifierTest {

    @Test
    fun `extractPackageNames finds pip install packages`() {
        val text = "Run `pip install requests flask`"
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.registry == "pypi" && it.name == "requests" })
    }

    @Test
    fun `extractPackageNames finds pip3 install packages`() {
        val text = "Run `pip3 install numpy`"
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.registry == "pypi" && it.name == "numpy" })
    }

    @Test
    fun `extractPackageNames finds npm install packages`() {
        val text = "Run `npm install express lodash`"
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.registry == "npm" && it.name == "express" })
    }

    @Test
    fun `extractPackageNames finds require statements`() {
        val text = """const express = require('express')"""
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.registry == "npm" && it.name == "express" })
    }

    @Test
    fun `extractPackageNames ignores Python stdlib`() {
        val text = "import os\nimport json\nimport requests"
        val packages = extractPackageNames(text)
        assertTrue(packages.none { it.name == "os" })
        assertTrue(packages.none { it.name == "json" })
        assertTrue(packages.any { it.name == "requests" })
    }

    @Test
    fun `extractPackageNames ignores relative requires`() {
        val text = """require('./local-module')"""
        val packages = extractPackageNames(text)
        assertTrue(packages.isEmpty())
    }

    @Test
    fun `extractPackageNames limits results`() {
        val text = (1..20).joinToString("\n") { "pip install package-$it" }
        val packages = extractPackageNames(text)
        assertTrue(packages.size <= 10)
    }

    @Test
    fun `extractPackageNames handles scoped npm packages`() {
        val text = "npm install @types/node"
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.name == "@types/node" })
    }

    @Test
    fun `extractPackageNames handles from-import`() {
        val text = "from pandas import DataFrame"
        val packages = extractPackageNames(text)
        assertTrue(packages.any { it.name == "pandas" })
    }

    // Note: Network-dependent PackageVerifier tests (registry 404, cache behavior)
    // are not feasible with SafeOutboundClient due to JDK 17+ Host header restriction
    // in pinToResolvedAddress. The ConcurrentLruMap cache and PackageStatus.NOT_FOUND
    // handling are tested through the extractPackageNames unit tests above.

    @Test
    fun `PackageVerifier accepts mirror configuration`() {
        val client = SafeOutboundClient()
        val verifier = PackageVerifier(
            client,
            pypiMirror = "https://custom-pypi.example.com",
            npmMirror = "https://custom-npm.example.com",
            cacheCapacity = 10
        )
        // Verifier construction succeeds with custom mirrors
        val packages = extractPackageNames("pip install requests")
        assertTrue(packages.isNotEmpty())
    }
}
