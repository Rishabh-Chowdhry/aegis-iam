package iam.authz

import future.keywords

# =============================================================================
# Admin Policy - Full Administrative Access
# =============================================================================
# This policy grants full administrative access to users with the 'admin' role.
# It provides unrestricted access to all resources and actions within the tenant.

# Default decision is deny
default allow = false

# -----------------------------------------------------------------------------
# Admin Role Grant
# -----------------------------------------------------------------------------
# Grant access to anyone with the admin role for any action on any resource

allow {
    input.subject.roles[_] = "admin"
}

# -----------------------------------------------------------------------------
# Tenant Isolation for Admins
# -----------------------------------------------------------------------------
# Ensure admin can only access resources within their own tenant

allow {
    input.subject.roles[_] = "admin"
    input.subject.tenant_id = input.resource.tenant_id
}

# -----------------------------------------------------------------------------
# Super Admin - Cross-Tenant Access (requires explicit attribute)
# -----------------------------------------------------------------------------
# Grant cross-tenant access for super admins (attribute: super_admin = true)

allow {
    input.subject.attributes.super_admin = true
    input.resource.type != "tenant"
}

allow {
    input.subject.attributes.super_admin = true
    input.action.name = "TENANT_MANAGE"
}

# -----------------------------------------------------------------------------
# Admin Actions on User Resources
# -----------------------------------------------------------------------------

allow {
    input.subject.roles[_] = "admin"
    input.resource.type = "user"
}

allow {
    input.subject.roles[_] = "admin"
    input.resource.type = "role"
}

allow {
    input.subject.roles[_] = "admin"
    input.resource.type = "policy"
}

# -----------------------------------------------------------------------------
# Admin Actions on System Resources
# -----------------------------------------------------------------------------

allow {
    input.subject.roles[_] = "admin"
    input.resource.type = "system"
    input.action.name != "SYSTEM_DELETE"
}

# -----------------------------------------------------------------------------
# MFA Requirement for High-Risk Admin Actions
# -----------------------------------------------------------------------------

allow {
    input.subject.roles[_] = "admin"
    input.action.risk_level = "critical"
    input.context.mfa = true
}

# -----------------------------------------------------------------------------
# Office Hours Restriction for Non-Emergency Admin Actions
# -----------------------------------------------------------------------------

allow {
    input.subject.roles[_] = "admin"
    input.action.risk_level != "critical"
    input.context.hour >= 8
    input.context.hour <= 18
    input.context.day_of_week <= 5
}

# -----------------------------------------------------------------------------
# Explicit Deny Rules (Override Allow)
# -----------------------------------------------------------------------------

deny {
    input.subject.roles[_] = "admin"
    input.action.name = "DELETE_ALL_USERS"
    input.context.environment = "production"
}

deny {
    input.subject.roles[_] = "admin"
    input.resource.type = "audit_log"
    input.action.name = "EXPORT"
    input.context.mfa != true
}
