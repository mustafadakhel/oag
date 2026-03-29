/*
 * Copyright 2026 Mustafa Dakhel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.mustafadakhel.oag.pipeline.relay

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

    @Test
    fun `PackageVerifier accepts mirror configuration`() {
        val client = com.mustafadakhel.oag.SafeOutboundClient()
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
