package iam.authz

import future.keywords

# =============================================================================
# Service Account Policy - Machine-to-Machine Access
# =============================================================================
# This policy governs access for service accounts (machine-to-machine).
# Service accounts have specific, limited permissions based on their configured scope.

# Default decision is deny
default allow = false

# -----------------------------------------------------------------------------
# Service Account Basic Access
# -----------------------------------------------------------------------------
# Grant access if the subject is a service account with matching scope

allow {
    input.subject.type = "Service"
    input.resource.type = "api"
    input.action.name = "INTERNAL_CALL"
    input.resource.attributes.service_scope[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Service Account API Key Validation
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.context.api_key_valid = true
    input.action.name = "INTERNAL_CALL"
}

# -----------------------------------------------------------------------------
# Database Access for Service Accounts
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "database"
    input.action.name = "READ"
    input.resource.attributes.allowed_services[_] = input.subject.id
}

allow {
    input.subject.type = "Service"
    input.resource.type = "database"
    input.action.name = "WRITE"
    input.resource.attributes.allowed_services[_] = input.subject.id
    input.context.mfa = false  # Services don't have MFA
    input.context.risk_score < 20
}

# -----------------------------------------------------------------------------
# Message Queue Access
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "message_queue"
    input.action.name = "PUBLISH"
    input.resource.attributes.publishers[_] = input.subject.id
}

allow {
    input.subject.type = "Service"
    input.resource.type = "message_queue"
    input.action.name = "SUBSCRIBE"
    input.resource.attributes.subscribers[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Event Stream Access
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "event_stream"
    input.action.name = "PRODUCE"
    input.resource.attributes.producers[_] = input.subject.id
}

allow {
    input.subject.type = "Service"
    input.resource.type = "event_stream"
    input.action.name = "CONSUME"
    input.resource.attributes.consumers[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Storage Access
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "storage"
    input.action.name = "READ"
    input.resource.attributes.read_services[_] = input.subject.id
}

allow {
    input.subject.type = "Service"
    input.resource.type = "storage"
    input.action.name = "WRITE"
    input.resource.attributes.write_services[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Cache Access
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "cache"
    input.action.name = "GET"
}

allow {
    input.subject.type = "Service"
    input.resource.type = "cache"
    input.action.name = "SET"
    input.resource.attributes.write_services[_] = input.subject.id
}

# -----------------------------------------------------------------------------
# Service Mesh / Discovery
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "service_discovery"
    input.action.name = "LOOKUP"
}

allow {
    input.subject.type = "Service"
    input.resource.type = "service_discovery"
    input.action.name = "REGISTER"
    input.subject.id = input.resource.attributes.service_id
}

# -----------------------------------------------------------------------------
# Configuration Access
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "config"
    input.action.name = "READ"
}

allow {
    input.subject.type = "Service"
    input.resource.type = "config"
    input.action.name = "WRITE"
    input.resource.attributes.write_services[_] = input.subject.id
    input.context.environment != "production"
}

# -----------------------------------------------------------------------------
# Monitoring and Metrics
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "metrics"
    input.action.name = "PUSH"
}

allow {
    input.subject.type = "Service"
    input.resource.type = "monitoring"
    input.action.name = "READ"
}

allow {
    input.subject.type = "Service"
    input.resource.type = "health"
    input.action.name = "CHECK"
}

# -----------------------------------------------------------------------------
# Secrets Access (Strictly Controlled)
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.resource.type = "secret"
    input.action.name = "READ"
    input.resource.attributes.read_services[_] = input.subject.id
    input.context.environment != "development"
}

deny {
    input.subject.type = "Service"
    input.resource.type = "secret"
    input.action.name = "WRITE"
    input.context.environment = "production"
}

# -----------------------------------------------------------------------------
# Rate Limiting for Services
# -----------------------------------------------------------------------------

deny {
    input.subject.type = "Service"
    input.resource.type = "api"
    input.context.rate_limit_exceeded = true
}

# -----------------------------------------------------------------------------
# Environment Restrictions
# -----------------------------------------------------------------------------

# Services can only access resources in their configured environment
allow {
    input.subject.type = "Service"
    input.resource.attributes.service_environment = input.subject.attributes.environment
}

# Cross-environment access requires explicit configuration
allow {
    input.subject.type = "Service"
    input.resource.attributes.cross_environment_access = true
    input.subject.attributes.cross_environment_allowed = true
}

# -----------------------------------------------------------------------------
# Tenant Isolation for Services
# -----------------------------------------------------------------------------

# Service accounts are scoped to a single tenant
deny {
    input.subject.type = "Service"
    input.subject.tenant_id != input.resource.tenant_id
}

# -----------------------------------------------------------------------------
# Critical Service Operations (Highly Restricted)
# -----------------------------------------------------------------------------

allow {
    input.subject.type = "Service"
    input.action.name = "CRITICAL_OPERATION"
    input.resource.attributes.critical_services[_] = input.subject.id
    input.context.risk_score = 0
    input.context.approved = true
}

# -----------------------------------------------------------------------------
# Logging for Service Actions
# -----------------------------------------------------------------------------

# All service actions should be logged
deny {
    not allow
    input.subject.type = "Service"
}
