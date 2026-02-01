# Enterprise IAM & Authorization Platform

This is an IAM and authorization platform we built for multi-tenant SaaS applications. We went with attribute-based access control (ABAC) instead of role-based permissions because it gives us way more flexibility for making context-aware access decisions. There's also an AWS-IAM-style policy DSL in case that model works better for your team, and we've got enterprise SSO integration sorted.

## Project Overview

The short version: we needed an authorization system that could handle complex, dynamic access decisions without getting stuck in role-permission hell. ABAC lets us make decisions based on attributes of the user, the resource, the action being performed, and the environment the request is coming from.

The code is organized into clean layers. REST APIs sit on top, handling policy management, authentication, and identity administration. The application layer uses domain-driven design with entities, value objects, and domain services doing the actual work. Infrastructure adapters handle persistence, caching, and external integrations.

Policy evaluation lives in the IAM module and runs as a cross-cutting concern through middleware and guards. This means every protected endpoint gets consistent authorization enforcement without each endpoint having to implement auth logic. We also support dropping in OPA/Rego if your organization prefers that route.

## Core Security Principles

We took security pretty seriously when designing this. Here's what we built:

Tenant boundaries run deep - enforced at the database layer, application layer, and through network policies. Even if there's a bug in the application code, tenant data stays isolated because queries are automatically scoped.

Deny-by-default on everything. Unless a policy explicitly says yes, the answer is no. This makes it much easier to reason about security and prevents accidental over-permissioning.

Secrets live outside the repo. We use environment-based configuration with runtime injection. Nothing sensitive gets committed to version control. In production, you pull secrets from proper secret management systems.

All tokens are signed with industry-standard algorithms and we do refresh token rotation. Inter-service communication uses TLS with mutual authentication.

## High-Level Architecture

The code lives in these main directories:

- `src/application/` - Use cases that orchestrate domain objects
- `src/domain/` - Entities, value objects, and domain services
- `src/infrastructure/` - Database adapters, Redis clients, external integrations
- `src/modules/` - Feature modules (auth, iam, users, roles, permissions, policies)

The IAM module is where policy evaluation happens. It loads policies from the database, caches them in Redis, and enforces authorization through middleware. If Redis goes down, it falls back to direct database queries with proper logging.

Scaling is horizontal. Policy evaluation is stateless, and the cache provides eventual consistency across instances.

## Authorization Model (ABAC)

We implemented ABAC following NIST SP 800-162. Authorization decisions look at four categories of attributes:

Subject attributes describe who is requesting access - user attributes, roles, groups. Resource attributes describe what's being accessed - metadata, classification, ownership. Action attributes describe the operation being performed. Environment attributes cover the context - time, network, authentication method.

Policies can combine multiple conditions with boolean logic. You can reference nested attributes, use wildcards, and work with sets. The policy combination algorithm follows AWS IAM's model - multiple applicable policies are evaluated and the most permissive outcome wins.

## Policy DSL (AWS-IAM Style)

Policies are JSON documents that look familiar if you've used AWS IAM. Each statement has:

- Effect: Allow or Deny
- Action: one or more action patterns (wildcards supported)
- Resource: one or more resource patterns
- Conditions: optional requirements that must be met

Condition keys give you access to attribute values at evaluation time. We support standard keys for common attributes plus custom keys for tenant-specific stuff.

The parser validates syntax during policy creation. Invalid policies get rejected with helpful error messages. Policy versioning is built-in for safe rollbacks.

## Multi-Tenant Isolation

Tenant isolation was a first-class concern from day one. Every tenant-scoped table includes tenant_id as a partitioning key. Queries are automatically scoped to the current tenant context. Cross-tenant operations are only allowed through explicit admin APIs that require elevated privileges.

The tenant context is established during authentication and validated on every request. Onboarding new tenants provisions their policy sets, role hierarchies, and initial admin users. We support both self-service provisioning and custom enterprise setups.

## OAuth2 / SSO (Enterprise-Ready)

We implemented OAuth 2.0 with OIDC for identity verification. Supported grant types include authorization code flow for web apps, client credentials for service-to-service auth, and device authorization for constrained devices.

Enterprise IdP integration works through SAML 2.0 and OpenID Connect. We act as a service provider, accepting assertions from corporate IdPs and mapping federated identities to local users.

Token management includes short-lived access tokens with rotation. Refresh tokens are encrypted and bound to the requesting client. Session management supports concurrent sessions with configurable limits.

## Audit & Compliance

Everything that happens gets logged. Authentication events, authorization decisions, admin operations - all of it. Audit logs capture who did what, when, from where, and the outcome.

Logs are structured JSON ready for SIEM ingestion. We ship to Elasticsearch, Splunk, or any JSON-compatible destination. Compliance reports aggregate events into summaries for regulatory review.

Data retention policies keep logs for required periods. Older logs get archived to cold storage. Log integrity is maintained through cryptographic signing of log batches.

## Repository Structure

```
src/
├── application/          # Use case implementations
│   └── use-cases/       # Business workflow implementations
├── core/                 # Cross-cutting concerns
│   └── logger/          # Structured logging infrastructure
├── domain/               # Domain models and business logic
│   ├── entities/        # Domain aggregates
│   ├── policies/        # Policy domain services
│   └── value-objects/   # Immutable domain values
├── infrastructure/       # External system integrations
│   ├── database/        # Prisma database adapters
│   ├── redis/           # Redis caching and session storage
│   ├── repositories/    # Data access abstractions
│   └── services/        # Infrastructure services
├── modules/              # Feature modules
│   ├── auth/            # Authentication and token services
│   ├── health/          # Health check endpoints
│   ├── iam/             # Identity and access management
│   │   ├── audit/       # Audit logging and SIEM integration
│   │   ├── cache/       # Policy caching
│   │   ├── conditions/  # Condition evaluation
│   │   ├── enforcement/ # Authorization middleware and guards
│   │   ├── engine/      # Policy evaluation engine
│   │   ├── errors/      # IAM-specific error types
│   │   ├── opa/         # OPA integration
│   │   ├── policy/      # Policy models and parsing
│   │   ├── repositories/# Tenant and policy repositories
│   │   ├── services/    # Policy management services
│   │   ├── tenancy/     # Tenant isolation
│   │   └── types/       # TypeScript type definitions
│   ├── permissions/     # Permission management
│   ├── policies/        # Policy CRUD operations
│   ├── roles/           # Role management
│   └── users/           # User management
└── shared/              # Shared utilities
    ├── config/          # Configuration management
    ├── errors/          # Error handling
    ├── logger/          # Logging utilities
    └── middleware/      # Express middleware

docs/
└── policies/            # Policy documentation and examples
    └── rego/           # OPA Rego policy examples

prisma/                  # Database schema and migrations

docker/                  # Docker configuration files
```

## Security Guarantees

Here's what you get out of the box:

**Authentication**: Passwords hashed with Argon2id. MFA support via TOTP and WebAuthn. Brute force protection with progressive delays and account lockout.

**Tokens**: JWTs signed with RS256. Encrypted refresh tokens bound to clients. Configurable lifetimes with secure defaults.

**Tenant Isolation**: Automatic query scoping. Cross-tenant queries blocked at the repository layer. Middleware validates tenant context on every request.

**Audit Integrity**: Logs written with fsync for durability. Batches cryptographically hashed. Modification detected during review.

**Transport**: TLS 1.3 required everywhere. Configurable trust stores. Mutual TLS for service-to-service auth.

## Getting Started

Prerequisites: Node.js 20+, PostgreSQL 15+, Redis 7+, Docker.

```bash
# Install dependencies
npm install

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Initialize database
npx prisma migrate deploy
npx prisma db seed

# Start development server
npm run dev
```

API runs at http://localhost:3000. Health checks at http://localhost:3000/health.

## Extension Points

The platform is designed for extension:

**Custom Condition Operators**: Implement `ConditionOperator` in `src/modules/iam/conditions/`. Register through the factory for auto-discovery.

**Policy Storage Backends**: Implement `IPolicyRepository` to support alternative storage systems.

**Audit Sinks**: Implement `AuditLoggerService` to forward audit events to custom destinations.

**Auth Providers**: Extend the auth module for additional identity providers. Follow OAuth/OIDC protocols.

**Custom Token Claims**: Register additional JWT claims through the token service config.

## Non-Goals

This platform doesn't try to do everything. What's explicitly out of scope:

No UI components - we only provide APIs. Build your own dashboard.

No privileged access management for infrastructure - integrate with dedicated PAM solutions if you need that.

No identity governance features - access certifications, separation of duties, etc. require dedicated GIA platforms.

No legacy auth protocols - NTLM, Kerberos, etc. are not supported.
