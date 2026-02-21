package com.mustafadakhel.oag.pipeline

import com.mustafadakhel.oag.audit.AuditEvent

fun interface AuditEmitter {
    fun emit(event: AuditEvent)
}
