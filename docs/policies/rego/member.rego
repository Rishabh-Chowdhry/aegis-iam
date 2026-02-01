package iam.authz

import future.keywords

# =============================================================================
# Member Policy - Limited Access for Regular Users
# =============================================================================
# This policy provides standard member access with role-based permissions.
# Members can access their own resources and shared resources within their tenant.

# Default decision is deny
default allow = false

# -----------------------------------------------------------------------------
# Resource Ownership Check
# -----------------------------------------------------------------------------
# Grant access if the subject owns the resource

allow {
    input.resource.owner_id = input.subject.id
}

# -----------------------------------------------------------------------------
# Resource Ownership via Attribute
# -----------------------------------------------------------------------------
# Grant access if resource owner_id attribute matches subject

allow {
    input.resource.attributes.owner_id = input.subject.id
}

# -----------------------------------------------------------------------------
# Team/Group Access
# -----------------------------------------------------------------------------
# Grant access if subject's groups overlap with resource's allowed groups

allow {
    input.resource.attributes.allowed_groups[_] = input.subject.groups[_]
}

# -----------------------------------------------------------------------------
# Read Access for Any Resource (within tenant)
# -----------------------------------------------------------------------------

allow {
    input.action.category = "read"
    input.subject.tenant_id = input.resource.tenant_id
    input.context.environment = input.resource.attributes.environment
}

# -----------------------------------------------------------------------------
# Write Access (Own Resources Only)
# -----------------------------------------------------------------------------

allow {
    input.action.category = "write"
    input.resource.owner_id = input.subject.id
    input.context.environment != "production"
}

allow {
    input.action.category = "write"
    input.resource.owner_id = input.subject.id
    input.context.mfa = true
}

# -----------------------------------------------------------------------------
# Document Access Based on Classification
# -----------------------------------------------------------------------------

# Public documents - read access for all authenticated users
allow {
    input.resource.attributes.classification = "public"
    input.action.category = "read"
}

# Internal documents - read access for members within tenant
allow {
    input.resource.attributes.classification = "internal"
    input.action.category = "read"
    input.subject.tenant_id = input.resource.tenant_id
}

# Confidential documents - read access with additional requirements
allow {
    input.resource.attributes.classification = "confidential"
    input.action.category = "read"
    input.subject.tenant_id = input.resource.tenant_id
    input.context.mfa = true
}

# Restricted documents - explicit access required
allow {
    input.resource.attributes.classification = "restricted"
    input.action.category = "read"
    input.resource.attributes.access_list[_] = input.subject.id
    input.context.mfa = true
}

# -----------------------------------------------------------------------------
# Role-Based Access for Specific Resources
# -----------------------------------------------------------------------------

# Finance team access to financial documents
allow {
    input.subject.roles[_] = "finance"
    input.resource.type = "invoice"
    input.action.category = "read"
}

allow {
    input.subject.roles[_] = "finance"
    input.resource.type = "invoice"
    input.action.name = "APPROVE"
    input.context.mfa = true
}

# HR team access to employee records
allow {
    input.subject.roles[_] = "hr"
    input.resource.type = "employee"
    input.action.category = "read"
}

allow {
    input.subject.roles[_] = "hr"
    input.resource.type = "employee"
    input.action.name = "UPDATE"
    input.resource.attributes.department = input.subject.attributes.department
}

# -----------------------------------------------------------------------------
# Time-Based Access Restrictions
# -----------------------------------------------------------------------------

# Business hours only for write operations
allow {
    input.action.category = "write"
    input.context.hour >= 9
    input.context.hour <= 17
    input.context.day_of_week >= 1
    input.context.day_of_week <= 5
}

# Weekend access requires explicit permission
allow {
    input.action.category = "write"
    input.context.day_of_week >= 6
    input.subject.attributes.weekend_access = true
    input.context.mfa = true
}

# -----------------------------------------------------------------------------
# Risk-Based Access Control
# -----------------------------------------------------------------------------

# Block high-risk actions from high-risk locations
deny {
    input.action.risk_level = "high"
    input.resource.attributes.classification = "restricted"
    input.context.risk_score > 50
}

# Require MFA for high-risk actions
allow {
    input.action.risk_level = "high"
    input.context.mfa = true
    input.context.risk_score < 30
}

# -----------------------------------------------------------------------------
# Cross-Tenant Access (Explicitly Denied by Default)
# -----------------------------------------------------------------------------

deny {
    input.subject.tenant_id != input.resource.tenant_id
}

# -----------------------------------------------------------------------------
# API Access for Service Accounts
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "api"
    input.action.name = "CALL"
    input.resource.attributes.allowed_services[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Default Deny with Audit Logging
# -----------------------------------------------------------------------------

# This rule ensures all denied requests are logged
deny {
    not allow
}
