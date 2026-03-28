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

package com.mustafadakhel.oag.policy.validation

import com.mustafadakhel.oag.policy.core.PolicySchemaValidation
import com.mustafadakhel.oag.validateJsonPointer

private val VALID_ON_FAIL = setOf("block", "pass")

internal fun PolicySchemaValidation.validate(base: String): List<ValidationError> = buildList {
    if (schema.isNullOrBlank()) {
        add(ValidationError("$base.schema", "Must be set"))
    }

    if (onFail != null && onFail.lowercase() !in VALID_ON_FAIL) {
        add(ValidationError("$base.on_fail", "Must be one of: ${VALID_ON_FAIL.joinToString()}"))
    }

    if (extractPath != null) {
        val error = validateJsonPointer(extractPath)
        if (error != null) {
            add(ValidationError("$base.extract_path", error))
        }
    }
}
