# Rego Policy Examples

This directory contains example Rego policies for the enterprise IAM platform's OPA/Rego compatibility layer.

## Overview

These policies demonstrate various access control patterns using Rego, the policy language for Open Policy Agent (OPA). They can be used as templates or starting points for your own policies.

## Policy Files

### [admin.rego](admin.rego)

Full administrative access policy for users with the `admin` role.

**Key Features:**

- Grants unrestricted access to admin users within their tenant
- Supports super admin cross-tenant access via `super_admin` attribute
- MFA requirement for critical actions
- Office hours restrictions for non-emergency actions
- Explicit deny rules for production safety

**Use Cases:**

- Platform administrators
- Tenant administrators
- Security operations teams

### [member.rego](member.rego)

Standard member access policy for regular authenticated users.

**Key Features:**

- Resource ownership-based access
- Team/group-based permissions
- Document classification handling (public, internal, confidential, restricted)
- Role-based access for specific resource types
- Time-based access restrictions
- Risk-based access control
- Tenant isolation enforcement

**Use Cases:**

- Regular application users
- Department-specific access (finance, HR, etc.)
- Document management systems

### [service.rego](service.rego)

Machine-to-machine access policy for service accounts.

**Key Features:**

- Service account scope validation
- API key validation
- Database, message queue, and storage access
- Service mesh and discovery permissions
- Configuration and monitoring access
- Secrets access with strict controls
- Rate limiting enforcement
- Environment-based restrictions

**Use Cases:**

- Microservices authentication
- Batch job authorization
- CI/CD pipeline access
- Background worker permissions

## Input Document Structure

All policies expect an input document with the following structure:

```json
{
  "subject": {
    "id": "user-123",
    "tenant_id": "tenant-456",
    "type": "User",
    "roles": ["admin", "finance"],
    "groups": ["team-leads"],
    "attributes": {
      "department": "finance",
      "level": 3
    }
  },
  "action": {
    "name": "INVOICE_APPROVE",
    "method": "POST",
    "category": "write",
    "risk_level": "high"
  },
  "resource": {
    "type": "invoice",
    "id": "inv-789",
    "tenant_id": "tenant-456",
    "owner_id": "user-123",
    "attributes": {
      "classification": "confidential",
      "amount": 10000
    }
  },
  "context": {
    "timestamp": "2026-02-01T14:00:00Z",
    "ip": "192.168.1.100",
    "mfa": true,
    "risk_score": 10,
    "environment": "production",
    "hour": 14,
    "day_of_week": 3
  },
  "tenant_id": "tenant-456"
}
```

## Common Patterns

### Deny by Default

```rego
default allow = false
```

Always start policies with a default deny to ensure explicit allow rules.

### Ownership Check

```rego
allow {
    input.resource.owner_id = input.subject.id
}
```

### Tenant Isolation

```rego
deny {
    input.subject.tenant_id != input.resource.tenant_id
}
```

### MFA Requirement

```rego
allow {
    input.action.risk_level = "high"
    input.context.mfa = true
}
```

### Role-Based Access

```rego
allow {
    input.subject.roles[_] = "admin"
}
```

## Best Practices

1. **Start with deny by default** - Always use `default allow = false`
2. **Use explicit deny rules** - Place deny rules after allow rules for overrides
3. **Keep policies simple** - Break complex policies into smaller, composable rules
4. **Test thoroughly** - Use OPA's built-in testing framework
5. **Document rules** - Add comments explaining the intent of each rule
6. **Consider performance** - Avoid expensive operations in hot paths

## Testing Policies

Use OPA's test framework to validate policies:

```bash
opa test admin.rego member.rego service.rego -v
```

## Integration

To use these policies with the IAM platform:

1. Load the policy file via the API
2. Configure the OPA engine to use the policy
3. Submit authorization requests with the standard input format

```typescript
import { OPAEngine, RegoMapper } from "./opa";

const engine = new OPAEngine();
const mapper = new RegoMapper();

const request = {
  /* authorization request */
};
const opaInput = mapper.toOPAInput(request);

const result = await engine.evaluate(request, policies);
```

## Additional Resources

- [OPA Documentation](https://www.openpolicyagent.org/docs/)
- [Rego Reference](https://www.openpolicyagent.org/docs/latest/policy-reference/)
- [Policy Best Practices](https://www.openpolicyagent.org/docs/latest/best-policies/)
