package com.mustafadakhel.oag.proxy.admin

internal enum class AdminPath(val path: String) {
    HEALTHZ("/healthz"),
    METRICS("/metrics"),
    RELOAD("/admin/reload"),
    POOL("/admin/pool"),
    POLICY("/admin/policy"),
    AUDIT("/admin/audit"),
    TASKS("/admin/tasks")
}
