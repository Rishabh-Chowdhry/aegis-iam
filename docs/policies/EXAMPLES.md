# Enterprise IAM Policy Examples

## Overview

This document provides comprehensive policy examples for an enterprise-grade Attribute-Based Access Control (ABAC) policy engine. These examples demonstrate how to structure policies for different roles, handle complex conditions, and implement advanced authorization scenarios across multi-tenant environments.

The policy examples in this document follow a standardized JSON format that is compatible with Open Policy Agent (OPA) and can be used directly with the policy engine. Each policy includes version metadata, tenant identification, descriptive naming, and a collection of statements that define access rules with granular conditions.

The examples cover four primary policy categories: administrative access for system administrators, standard member access for regular users, service account access for automated systems, and financial operations access for finance teams. Additionally, Rego policy examples are provided for organizations that prefer using OPA's native policy language for complex authorization logic.

These policies are designed with security best practices in mind, including explicit deny statements, tenant boundary enforcement, and least-privilege principles. The examples can be used as starting points for production deployments and should be customized based on specific organizational requirements.

## Policy Structure

### Policy JSON Format

All policies in this documentation follow a consistent JSON structure that enables precise access control definition. The structure includes metadata fields for policy identification and versioning, along with an array of statements that define the actual access rules.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Policy Name",
  "description": "Detailed description of policy purpose",
  "statements": [
    {
      "sid": "StatementIdentifier",
      "effect": "ALLOW | DENY",
      "actions": ["action1", "action2", "*"],
      "resources": ["resource1", "resource2", "*"],
      "conditions": {
        "StringEquals": { ... },
        "StringNotEquals": { ... },
        "NumericEquals": { ... },
        "DateGreaterThan": { ... },
        "IpAddressEquals": [ ... ]
      }
    }
  ]
}
```

### Field Definitions

The `version` field uses ISO 8601 date format (YYYY-MM-DD) to indicate the policy schema version. This versioning enables backward compatibility and allows the policy engine to correctly parse policies as the schema evolves over time. The tenant identifier in the `tenantId` field ensures that policies are scoped to specific tenants in multi-tenant deployments, preventing cross-tenant access unless explicitly authorized.

Each statement within the policy contains several critical components. The `sid` (statement identifier) provides a human-readable label for the statement that appears in audit logs, making it easier to trace authorization decisions. The `effect` field determines whether the statement grants (`ALLOW`) or restricts (`DENY`) access, with DENY statements typically taking precedence in policy evaluation.

The `actions` array specifies which operations are affected by the statement, supporting both specific action names and wildcard patterns. Similarly, the `resources` array defines the target objects or paths that the statement applies to. The `conditions` object provides the most powerful aspect of ABAC policies, enabling context-aware access decisions based on subject attributes, resource attributes, and environmental factors.

### Policy Evaluation Logic

The policy engine evaluates statements in a specific order that ensures consistent and predictable results. When an authorization request is received, the engine collects all applicable policies for the requesting principal and then evaluates each statement in sequence. Deny statements take precedence over allow statements, meaning that if any applicable deny statement exists, the request will be denied regardless of allow statements.

The evaluation process considers the intersection of actions, resources, and conditions. For a statement to apply to a request, the requested action must match one of the specified actions, the target resource must match one of the specified resources, and all conditions must evaluate to true. Only when all three criteria are met does the statement's effect come into play.

Conditions support multiple comparison operators that enable sophisticated access logic. String-based operators include exact matching (`StringEquals`), case-insensitive matching (`StringEqualsIgnoreCase`), and pattern matching (`StringLike`). Numeric operators support standard comparisons (`NumericEquals`, `NumericGreaterThan`, `NumericLessThanOrEquals`). Date and time operators enable time-based access control (`DateGreaterThan`, `DateLessThanOrEquals`). IP address operators support network-based restrictions (`IpAddressEquals`, `IpAddressNotEquals`).

---

## Admin Policies

### Full Administrator Access

The Full Administrator policy provides comprehensive administrative privileges within tenant boundaries. This policy is designed for users who need complete control over all resources and operations within their organization, such as IT administrators, DevOps engineers, and security officers with elevated responsibilities.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Full Administrator Access",
  "description": "Grants full administrative access within tenant boundary for system management",
  "statements": [
    {
      "sid": "AdminAllResources",
      "effect": "ALLOW",
      "actions": ["*"],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "DenyCrossTenant",
      "effect": "DENY",
      "actions": ["*"],
      "resources": ["*"],
      "conditions": {
        "StringNotEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `AdminAllResources` statement grants unrestricted access to all actions and resources within the tenant. The wildcard (`*`) for actions matches any operation, including read, write, delete, and administrative actions. The condition ensures that this access is only granted when the subject's tenant ID matches the resource's tenant ID, creating a hard boundary that prevents administrators from accessing resources in other tenants even with elevated privileges.

The `DenyCrossTenant` statement serves as an explicit security boundary, denying all operations when tenant IDs do not match. While the implicit deny would accomplish much of the same, this explicit statement makes the cross-tenant restriction clear in audit logs and policy analysis, improving visibility into security-relevant decisions.

**Use Cases:**

This policy is appropriate for users who need to manage all aspects of their tenant environment, including user management, resource provisioning, configuration changes, security settings, and audit log access. Typical roles that might receive this policy include the primary tenant administrator, senior IT operations staff, and security engineers who need comprehensive access for incident response and security monitoring.

**Security Considerations:**

While this policy provides maximum flexibility for administrators, it should be assigned sparingly. The principle of least privilege suggests that most administrative users should receive more granular policies that restrict access to only the resources and actions they require for their specific responsibilities. Organizations should implement additional controls such as privileged access management (PAM) systems, just-in-time access provisioning, and comprehensive audit logging for administrators with this level of access.

---

### Read-Only Administrator

The Read-Only Administrator policy enables users to view all resources and configurations within a tenant without the ability to modify anything. This policy is essential for compliance auditors, security reviewers, and support personnel who need visibility into system state without the risk of accidental or malicious changes.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Read-Only Administrator",
  "description": "Grants read-only access to all resources for monitoring and auditing purposes",
  "statements": [
    {
      "sid": "ReadAllResources",
      "effect": "ALLOW",
      "actions": [
        "read",
        "list",
        "describe",
        "get",
        "view",
        "export",
        "download"
      ],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "DenyWriteOperations",
      "effect": "DENY",
      "actions": [
        "create",
        "update",
        "delete",
        "modify",
        "write",
        "upload",
        "import"
      ],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "DenyCrossTenantRead",
      "effect": "DENY",
      "actions": ["read", "list", "describe", "get", "view"],
      "resources": ["*"],
      "conditions": {
        "StringNotEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ReadAllResources` statement explicitly enumerates all read-related actions that are permitted. Rather than using a wildcard, this approach provides clear documentation of exactly what read operations are authorized. The actions listed cover the common read patterns across different resource types, including both individual resource access (`get`, `describe`, `view`) and collection access (`list`).

The `DenyWriteOperations` statement explicitly blocks all modification actions. While a default-deny approach would prevent writes by default, this explicit statement ensures that the intent to block writes is clearly documented and visible in policy analysis. The broad list of write-related actions covers various ways systems might express modification operations.

The `DenyCrossTenantRead` statement maintains the tenant boundary even for read operations. While reading data from other tenants might seem harmless, it could leak sensitive information about other organizations, violate compliance requirements, or enable reconnaissance attacks. This explicit deny ensures that read-only administrators cannot access cross-tenant data under any circumstances.

**Use Cases:**

This policy is commonly assigned to compliance officers who need to verify that systems are properly configured, security teams performing vulnerability assessments and penetration testing, external auditors who need to review system state without making changes, and support engineers who need to investigate issues without risking configuration drift.

**Security Considerations:**

Even read-only access to all resources can expose sensitive information, including personal data, security configurations, and business intelligence. Organizations should consider whether additional data masking or redaction should be applied to read-only administrative access. Additionally, the audit logs for read operations by administrators should be monitored for patterns that might indicate unauthorized data exfiltration or reconnaissance activity.

---

### User Management Administrator

The User Management Administrator policy provides focused access for managing user accounts, roles, and permissions without granting broader administrative capabilities. This policy is designed for HR administrators, team leads with user management responsibilities, and identity management systems that need to automate user lifecycle operations.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "User Management Administrator",
  "description": "Grants permissions to manage users, roles, and permissions within tenant scope",
  "statements": [
    {
      "sid": "ManageUsers",
      "effect": "ALLOW",
      "actions": [
        "create",
        "read",
        "update",
        "delete",
        "list",
        "deactivate",
        "reactivate"
      ],
      "resources": ["users/*", "users"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ManageRoles",
      "effect": "ALLOW",
      "actions": ["create", "read", "update", "delete", "list"],
      "resources": ["roles/*", "roles"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "AssignPermissions",
      "effect": "ALLOW",
      "actions": ["assign", "revoke", "list"],
      "resources": [
        "permissions/*",
        "permissions",
        "role-assignments/*",
        "role-assignments"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ReadAuditLogs",
      "effect": "ALLOW",
      "actions": ["read", "list", "export"],
      "resources": ["audit-logs/*", "audit-logs"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "DenySelfModifications",
      "effect": "DENY",
      "actions": ["update", "delete", "deactivate"],
      "resources": ["users/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ManageUsers` statement provides comprehensive access to user lifecycle operations. The resource pattern `users/*` matches all individual user resources while `users` matches the collection endpoint, enabling both individual and batch operations. All standard user management actions are permitted, including account creation, deactivation for offboarding, and reactivation for returning employees.

The `ManageRoles` statement enables management of role definitions without providing access to role assignments. This separation allows administrators to define roles and their associated permissions without being able to assign those roles to themselves or others, preventing privilege escalation through role manipulation.

The `AssignPermissions` statement controls the ability to grant and revoke role assignments. This is a sensitive operation that connects principals to permissions, and its inclusion in a user management policy enables administrators to assign roles as part of user onboarding and access change processes. The separation of role management from role assignment provides an additional control point for access governance.

The `ReadAuditLogs` statement provides visibility into user activity and system events. This capability is essential for user management administrators to investigate security incidents, verify that access changes were properly authorized, and maintain compliance with audit trail requirements.

The `DenySelfModifications` statement prevents administrators from modifying their own accounts. This is a critical security control that prevents administrators from removing their own restrictions, escalating their own privileges, or deactivating their own accounts to evade oversight. Any changes to an administrator's own account must go through a separate administrative path with appropriate oversight.

**Use Cases:**

This policy is designed for HR administrators who manage employee onboarding and offboarding, team leads who need to manage access for their direct reports, identity governance systems that automate access certification and provisioning, and compliance teams that need to verify user access configurations without making changes.

**Security Considerations:**

User management administrators have significant power over access rights within the organization. Organizations should implement workflow controls that require approval for sensitive role assignments, maintain separation between those who can assign permissions and those who are assigned permissions, and monitor user management activity for unusual patterns that might indicate insider threats or compromised accounts.

---

### Billing Administrator

The Billing Administrator policy provides access to financial data, payment methods, and billing operations. This policy is essential for finance teams, procurement specialists, and billing systems that need to manage organizational spending and payment processing.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Billing Administrator",
  "description": "Grants access to billing, payments, and financial reporting within tenant scope",
  "statements": [
    {
      "sid": "ManageBilling",
      "effect": "ALLOW",
      "actions": ["read", "update", "list"],
      "resources": [
        "billing/*",
        "billing",
        "invoices/*",
        "invoices",
        "subscriptions/*",
        "subscriptions"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ManagePaymentMethods",
      "effect": "ALLOW",
      "actions": ["create", "read", "update", "delete"],
      "resources": ["payment-methods/*", "payment-methods"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ViewFinancialReports",
      "effect": "ALLOW",
      "actions": ["read", "export", "download"],
      "resources": [
        "reports/financial/*",
        "reports/financial",
        "usage-reports/*",
        "usage-reports"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ApprovePayments",
      "effect": "ALLOW",
      "actions": ["approve", "process"],
      "resources": [
        "payments/*",
        "payments",
        "pending-payments/*",
        "pending-payments"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "NumericLessThanEquals": {
          "input.amount": 10000
        }
      }
    },
    {
      "sid": "RequireApprovalForLargePayments",
      "effect": "DENY",
      "actions": ["approve", "process"],
      "resources": [
        "payments/*",
        "payments",
        "pending-payments/*",
        "pending-payments"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "NumericGreaterThan": {
          "input.amount": 10000
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ManageBilling` statement provides access to core billing information including invoices, subscriptions, and billing configurations. The read and list actions enable viewing of historical billing data while update allows modifications to billing settings such as payment terms and notification preferences.

The `ManagePaymentMethods` statement controls access to stored payment instruments, including credit cards, bank accounts, and other payment mechanisms. This is highly sensitive access that enables adding new payment methods and removing existing ones, which could impact the organization's ability to make payments or result in unauthorized charges.

The `ViewFinancialReports` statement grants access to usage reports and financial summaries. This data is important for budget planning, cost optimization, and financial reconciliation. The export action enables downloading reports for offline analysis and inclusion in financial systems.

The `ApprovePayments` statement includes a monetary limit condition that restricts approval authority to transactions of $10,000 or less. This condition uses `input.amount` to reference the payment amount in the authorization request, enabling dynamic limits based on transaction value. Payments above this threshold require additional authorization.

The `RequireApprovalForLargePayments` statement explicitly denies approval of large transactions, creating a clear control point for high-value payments. While the absence of an allow statement for large payments would also prevent them, this explicit deny ensures that the policy clearly communicates the requirement for additional oversight.

**Use Cases:**

This policy is appropriate for accounts payable specialists who process invoices and payments, finance managers who review and approve expenditures, procurement teams who manage vendor relationships and contracts, and billing systems that automate payment processing within established limits.

**Security Considerations:**

Billing access involves highly sensitive financial data and payment capabilities. Organizations should implement additional controls such as dual approval for payments above certain thresholds, segregation of duties between those who can approve payments and those who can initiate them, and integration with fraud detection systems for unusual billing patterns. All billing access should be logged with sufficient detail to support forensic investigation if needed.

---

## Member Policies

### Basic Member Access

The Basic Member policy provides standard access rights for regular users within an organization. This policy enables users to perform their daily work activities while maintaining appropriate boundaries around organizational resources. It represents a typical starting point for new employees and serves as a baseline that can be extended with additional policies for specific needs.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Basic Member Access",
  "description": "Standard access rights for regular organizational members",
  "statements": [
    {
      "sid": "ReadOwnProfile",
      "effect": "ALLOW",
      "actions": ["read", "update"],
      "resources": ["users/self", "profile"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        }
      }
    },
    {
      "sid": "ReadPublicResources",
      "effect": "ALLOW",
      "actions": ["read", "list"],
      "resources": ["resources/public/*", "resources/public"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ReadSharedResources",
      "effect": "ALLOW",
      "actions": ["read", "list"],
      "resources": ["resources/shared/*", "resources/shared"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "CreateOwnResources",
      "effect": "ALLOW",
      "actions": ["create"],
      "resources": ["resources/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ModifyOwnResources",
      "effect": "ALLOW",
      "actions": ["update", "delete"],
      "resources": ["resources/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ReadOwnProfile` statement enables users to view and update their own profile information. The condition comparing `subject.id` to `resource.ownerId` ensures that users can only access their own profile, preventing unauthorized access to other users' personal information. This self-service capability reduces administrative burden while maintaining privacy.

The `ReadPublicResources` statement allows access to resources explicitly marked as public within the tenant. Public resources are intended for broad consumption and do not require specific ownership or permission to access. This pattern supports shared documents, company policies, and team resources that are meant to be widely available.

The `ReadSharedResources` statement enables access to shared resources that are available to all members of the tenant. While similar to public resources, shared resources might have additional controls or organization that distinguishes them from truly public content. The tenant boundary condition ensures that only authenticated members of the organization can access these resources.

The `CreateOwnResources` statement allows users to create new resources within the tenant. This capability is essential for users to do their work, whether that involves creating documents, submitting forms, or generating data. The tenant boundary ensures that resource creation is scoped to the user's organization.

The `ModifyOwnResources` statement provides control over resources that the user has created. By comparing the subject identifier to the resource owner, this statement ensures that users can only modify and delete their own creations. This ownership model supports individual accountability and prevents unauthorized modification of others' work.

**Use Cases:**

This policy serves as the baseline access level for all regular employees, contractors, and other organizational members. New hires typically receive this policy as part of their initial access provisioning, with additional policies added as their role requires. The policy supports common work activities including document creation, profile management, and access to shared organizational resources.

**Security Considerations:**

While this policy provides reasonable baseline access, organizations should consider the implications of broad resource creation permissions. Without appropriate controls, users could create excessive resources that consume storage, create confusion, or inadvertently expose sensitive information. Consider implementing resource quotas, naming conventions, and data classification guidance alongside this policy.

---

### Resource Owner Access

The Resource Owner policy extends basic member access with enhanced control over resources that the user has created or explicitly owns. This policy is appropriate for power users, project leads, and anyone who needs extended control over organizational resources.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Resource Owner Access",
  "description": "Enhanced access for resource owners including sharing and delegation capabilities",
  "statements": [
    {
      "sid": "FullControlOwnResources",
      "effect": "ALLOW",
      "actions": [
        "read",
        "update",
        "delete",
        "share",
        "transfer",
        "archive",
        "restore"
      ],
      "resources": ["resources/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        }
      }
    },
    {
      "sid": "ShareWithTeam",
      "effect": "ALLOW",
      "actions": ["share"],
      "resources": ["resources/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        },
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        }
      }
    },
    {
      "sid": "ViewDelegatedResources",
      "effect": "ALLOW",
      "actions": ["read"],
      "resources": ["resources/*", "delegations/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.delegatedTo"
        }
      }
    },
    {
      "sid": "ManageDelegations",
      "effect": "ALLOW",
      "actions": ["create", "read", "update", "delete"],
      "resources": ["delegations/*", "delegations"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.ownerId"
        }
      }
    },
    {
      "sid": "DenyCrossTenantOwnership",
      "effect": "DENY",
      "actions": ["create", "update", "transfer"],
      "resources": ["resources/*"],
      "conditions": {
        "StringNotEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `FullControlOwnResources` statement grants comprehensive control over resources owned by the user. Beyond the basic read, update, and delete operations, this includes sharing capabilities, ownership transfer, and lifecycle management actions like archiving and restoration. This enables resource owners to fully manage their resources throughout their lifecycle.

The `ShareWithTeam` statement allows resource owners to share resources with team members. The condition that checks both ownership and team membership ensures that sharing is limited to members of the same team as the resource owner. This creates a boundary that prevents users from sharing resources with individuals outside their team, even for resources they own.

The `ViewDelegatedResources` statement enables access to resources that have been delegated to the user by other owners. The `delegatedTo` attribute on the resource identifies who has been granted access through delegation. This capability enables workflow patterns where one user can temporarily manage resources owned by another.

The `ManageDelegations` statement provides control over the delegation relationships that the user has created. This includes the ability to create new delegations, view existing ones, modify delegation terms, and revoke delegations when they are no longer needed. The ownership condition ensures that users can only manage their own delegation relationships.

The `DenyCrossTenantOwnership` statement explicitly prevents users from creating or transferring resources across tenant boundaries. This is particularly important for resource owners who might attempt to share organizational resources with users from other tenants. The explicit deny ensures that such attempts are logged and rejected.

**Use Cases:**

This policy is appropriate for project managers who need to share project resources with team members, team leads who manage resources on behalf of their team, users who need to delegate tasks during absences or workload spikes, and power users who create and manage significant numbers of organizational resources.

**Security Considerations:**

Resource owner capabilities can be misused to exfiltrate data, circumvent access controls, or create shadow IT systems outside of organizational oversight. Organizations should implement monitoring for unusual sharing patterns, consider requiring approval for external sharing, and maintain audit trails that capture resource ownership transfers. The delegation capability should be limited in duration and scope to prevent permanent bypass of access controls.

---

### Team-Based Access

The Team-Based Access policy implements access control based on team membership, enabling collaboration patterns where team members share responsibility for resources. This policy is essential for organizations that use teams as their primary organizational unit for access management.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Team-Based Access",
  "description": "Access control based on team membership for collaborative resource management",
  "statements": [
    {
      "sid": "ReadTeamResources",
      "effect": "ALLOW",
      "actions": ["read", "list", "describe"],
      "resources": [
        "teams/*/resources/*",
        "teams/*/resources",
        "projects/*/resources/*",
        "projects/*/resources"
      ],
      "conditions": {
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        }
      }
    },
    {
      "sid": "ModifyTeamResources",
      "effect": "ALLOW",
      "actions": ["update", "comment"],
      "resources": [
        "teams/*/resources/*",
        "teams/*/resources",
        "projects/*/resources/*",
        "projects/*/resources"
      ],
      "conditions": {
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        }
      }
    },
    {
      "sid": "CreateTeamResources",
      "effect": "ALLOW",
      "actions": ["create"],
      "resources": ["teams/*/resources/*", "teams/*/resources"],
      "conditions": {
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        }
      }
    },
    {
      "sid": "DeleteTeamResources",
      "effect": "ALLOW",
      "actions": ["delete"],
      "resources": ["teams/*/resources/*", "teams/*/resources"],
      "conditions": {
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        },
        "StringEquals": {
          "subject.role": "team.lead"
        }
      }
    },
    {
      "sid": "ManageTeamMembership",
      "effect": "ALLOW",
      "actions": ["add", "remove", "invite"],
      "resources": ["teams/*/members/*", "teams/*/members"],
      "conditions": {
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        },
        "StringEquals": {
          "subject.role": "team.lead"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ReadTeamResources` statement provides read access to all resources associated with the user's team. The resource pattern `teams/*/resources/*` uses wildcards to match any team identifier and any resource within that team. The condition that compares `subject.teamId` to `resource.teamId` ensures that access is only granted when the user's team matches the resource's team.

The `ModifyTeamResources` statement allows team members to update existing team resources. This supports collaborative editing and maintenance of shared resources. Unlike delete permissions, modification does not require team lead role, enabling all team members to contribute to team resources.

The `CreateTeamResources` statement enables team members to add new resources to the team. This capability supports organic growth of team content as work progresses. The team ID is typically set automatically based on the user's team membership when resources are created.

The `DeleteTeamResources` statement restricts deletion capability to team leads. The additional condition checking `subject.role` for the value `team.lead` ensures that only designated leaders can remove resources from the team. This control prevents accidental or unauthorized deletion of shared resources by regular team members.

The `ManageTeamMembership` statement provides team lead capabilities for managing who belongs to the team. This includes adding new members, removing existing members, and sending invitations to potential team members. The restriction to team leads ensures that team composition is controlled by leadership rather than being open to all members.

**Use Cases:**

This policy supports agile team structures where cross-functional groups work together on projects, committee-based organizations where members share responsibility for committee resources, department-based access where all members of a department need access to departmental resources, and project-based collaboration where project teams need shared access to project artifacts.

**Security Considerations:**

Team-based access can create large access groups if teams are not carefully managed. Organizations should implement team governance policies that define appropriate team sizes, regular review processes for team membership, and clear ownership accountability for team resources. The team lead role should be limited and audited, as it provides significant control over team resources and membership.

---

### Department-Based Access

The Department-Based Access policy implements access control at the department level, providing broader access than team-based policies while maintaining organizational boundaries. This policy is appropriate for organizations with formal department structures where cross-team collaboration within departments is common.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Department-Based Access",
  "description": "Access control based on department membership for cross-team departmental collaboration",
  "statements": [
    {
      "sid": "ReadDepartmentResources",
      "effect": "ALLOW",
      "actions": ["read", "list", "describe", "search"],
      "resources": [
        "departments/*/resources/*",
        "departments/*/resources",
        "departments/*/documents/*",
        "departments/*/documents"
      ],
      "conditions": {
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        }
      }
    },
    {
      "sid": "CreateDepartmentResources",
      "effect": "ALLOW",
      "actions": ["create"],
      "resources": ["departments/*/resources/*", "departments/*/resources"],
      "conditions": {
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        }
      }
    },
    {
      "sid": "ModifyDepartmentResources",
      "effect": "ALLOW",
      "actions": ["update", "comment", "review"],
      "resources": ["departments/*/resources/*", "departments/*/resources"],
      "conditions": {
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        },
        "StringEquals": {
          "subject.status": "active"
        }
      }
    },
    {
      "sid": "DepartmentAdmin",
      "effect": "ALLOW",
      "actions": ["create", "read", "update", "delete", "list", "manage"],
      "resources": [
        "departments/*/settings/*",
        "departments/*/settings",
        "departments/*/policies/*",
        "departments/*/policies"
      ],
      "conditions": {
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        },
        "StringEquals": {
          "subject.departmentRole": "admin"
        }
      }
    },
    {
      "sid": "DenyCrossDepartmentAccess",
      "effect": "DENY",
      "actions": ["read", "create", "update", "delete"],
      "resources": [
        "departments/*/resources/*",
        "departments/*/resources",
        "departments/*/documents/*",
        "departments/*/documents"
      ],
      "conditions": {
        "StringNotEquals": {
          "subject.departmentId": "resource.departmentId"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ReadDepartmentResources` statement provides read access to all resources within the user's department. This includes departmental documents, shared resources, and project outputs. The broad read access enables department members to stay informed about departmental activities and access information needed for their work.

The `CreateDepartmentResources` statement allows users to create resources within the department. This capability supports departmental knowledge management, document creation, and project initiation. Resources created by department members are automatically associated with the department through the creation context.

The `ModifyDepartmentResources` statement includes an additional condition checking that the subject's status is active. This prevents deactivated users from continuing to modify departmental resources after their employment has ended or their access has been revoked. The active status should be maintained as a subject attribute that is updated through employee lifecycle processes.

The `DepartmentAdmin` statement provides administrative capabilities over departmental settings and policies, but only for users with the department admin role. This separates general department members from those responsible for governing departmental resources. The role check ensures that only designated administrators can modify departmental configurations.

The `DenyCrossDepartmentAccess` statement creates an explicit boundary between departments. While implicit deny would prevent cross-department access, this explicit statement ensures that unauthorized cross-department access attempts are logged and clearly identified in security monitoring systems.

**Use Cases:**

This policy is appropriate for large departments where teams frequently collaborate across team boundaries, functional departments that need shared access to departmental knowledge and resources, organizational units that maintain department-specific policies and procedures, and compliance environments where department-level access boundaries are required for regulatory purposes.

**Security Considerations:**

Department-level access grants broader permissions than team-based access, making it important to carefully define department boundaries. Organizations should implement data classification to identify sensitive departmental resources that require additional access controls, consider department-specific policies for highly regulated areas like finance or human resources, and implement monitoring for unusual cross-department access patterns that might indicate policy violations.

---

## Service Policies

### API Service Access

The API Service policy provides access patterns for automated services that interact with APIs. This policy is designed for microservices, integration layers, and any automated system that needs to perform operations on behalf of the organization.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "API Service Access",
  "description": "Access permissions for automated services and API clients",
  "statements": [
    {
      "sid": "ServiceReadResources",
      "effect": "ALLOW",
      "actions": ["read", "list", "get", "describe", "search", "query"],
      "resources": ["api/*", "resources/*", "data/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "service"
        }
      }
    },
    {
      "sid": "ServiceWriteResources",
      "effect": "ALLOW",
      "actions": ["create", "update", "upsert"],
      "resources": ["api/*", "resources/*", "data/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "service"
        },
        "StringEquals": {
          "subject.serviceLevel": "trusted"
        }
      }
    },
    {
      "sid": "ServiceDeleteResources",
      "effect": "ALLOW",
      "actions": ["delete", "remove", "purge"],
      "resources": ["api/*", "resources/*", "data/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "service"
        },
        "StringEquals": {
          "subject.serviceLevel": "trusted"
        },
        "StringEquals": {
          "subject.deletePermission": "granted"
        }
      }
    },
    {
      "sid": "DenyExternalAccess",
      "effect": "DENY",
      "actions": ["*"],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "subject.type": "service"
        },
        "StringNotEquals": {
          "subject.networkZone": "internal"
        }
      }
    },
    {
      "sid": "RequireServiceToken",
      "effect": "ALLOW",
      "actions": ["*"],
      "resources": ["*"],
      "conditions": {
        "StringEquals": {
          "subject.credentialType": "serviceToken"
        },
        "StringEquals": {
          "subject.tokenValid": "true"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ServiceReadResources` statement grants read access to resources for services. The subject type condition ensures that this access is only available to service accounts rather than human users. This separation enables different security controls for automated access versus interactive access.

The `ServiceWriteResources` statement allows services to modify resources, but only if they have the trusted service level. This creates a tiered access model where services must be vetted and approved before being granted write capabilities. The service level attribute can be managed through a service governance process.

The `ServiceDeleteResources` statement includes multiple restrictive conditions. Beyond being a trusted service, services must also have explicit delete permission granted. This additional check prevents even trusted services from accidentally deleting resources without specific authorization. The combination of conditions creates defense in depth for the most destructive operations.

The `DenyExternalAccess` statement ensures that services can only operate from internal network locations. The network zone condition restricts service access to internal systems, preventing compromised services from accessing organizational resources from external networks. This control is particularly important for services that might be deployed across multiple environments.

The `RequireServiceToken` statement provides a baseline control that requires services to authenticate with valid service tokens. The credential type check ensures that only service-specific credentials are accepted, while the token valid check ensures that only currently valid tokens can be used. This prevents the use of expired, revoked, or borrowed credentials.

**Use Cases:**

This policy is appropriate for microservices that need to read and write application data, integration services that connect to external systems, data synchronization services that maintain data consistency across systems, automation services that perform scheduled operations, and webhook handlers that respond to external events.

**Security Considerations:**

Service accounts often have elevated privileges compared to individual users and represent attractive targets for attackers. Organizations should implement strict credential management for services, including regular rotation, minimal permission scopes, and monitoring for unusual service behavior. Network restrictions should be applied to limit the potential impact of compromised services, and services should be designed with defense in depth principles that do not rely solely on service account security.

---

### Batch Processing Service

The Batch Processing Service policy provides specialized access patterns for services that perform bulk data operations. This policy recognizes that batch jobs have different operational characteristics than interactive services, including longer execution times, larger data volumes, and different failure modes.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Batch Processing Service",
  "description": "Access permissions for batch processing and scheduled job services",
  "statements": [
    {
      "sid": "BatchReadData",
      "effect": "ALLOW",
      "actions": ["read", "list", "export", "dump"],
      "resources": ["data/*", "datasets/*", "exports/*", "batch-inputs/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "batch-service"
        }
      }
    },
    {
      "sid": "BatchWriteOutput",
      "effect": "ALLOW",
      "actions": ["create", "write", "upload"],
      "resources": ["outputs/*", "results/*", "reports/*", "batch-outputs/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "batch-service"
        }
      }
    },
    {
      "sid": "BatchJobManagement",
      "effect": "ALLOW",
      "actions": ["create", "read", "update", "status", "cancel"],
      "resources": ["jobs/*", "jobs", "batch-jobs/*", "batch-jobs"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "batch-service"
        }
      }
    },
    {
      "sid": "AllowScheduledExecution",
      "effect": "ALLOW",
      "actions": ["execute", "start", "trigger"],
      "resources": ["jobs/*", "batch-jobs/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "batch-service"
        },
        "StringEquals": {
          "input.scheduler": "true"
        }
      }
    },
    {
      "sid": "DenyManualExecution",
      "effect": "DENY",
      "actions": ["execute", "start", "trigger"],
      "resources": ["jobs/*", "batch-jobs/*"],
      "conditions": {
        "StringEquals": {
          "subject.type": "batch-service"
        },
        "StringNotEquals": {
          "input.scheduler": "true"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `BatchReadData` statement grants access to read data for batch processing operations. The included export and dump actions recognize that batch jobs often need to extract large datasets for processing. These operations should be restricted to designated batch service accounts to prevent users from exporting large volumes of data.

The `BatchWriteOutput` statement allows batch services to write results and outputs. Batch jobs typically produce reports, processed data, and other outputs that need to be stored. This statement enables the creation of these outputs while maintaining tenant boundaries.

The `BatchJobManagement` statement provides control over job resources themselves, including the ability to create new jobs, check status, and cancel running jobs. This enables batch services to manage their own job queue and respond to operational needs like job cancellation.

The `AllowScheduledExecution` statement specifically permits job execution when triggered by the scheduler. The input condition checking `input.scheduler` ensures that execution is only allowed when the request comes from an authorized scheduler component rather than arbitrary sources.

The `DenyManualExecution` statement explicitly prevents batch jobs from being started outside of scheduled contexts. This ensures that batch processing is controlled through proper scheduling mechanisms rather than ad-hoc execution requests, which could be used to bypass workload management controls.

**Use Cases:**

This policy is appropriate for data processing pipelines that run on scheduled intervals, ETL services that extract, transform, and load data, report generation services that produce scheduled reports, data synchronization jobs that maintain data consistency, and backup services that perform scheduled data protection operations.

**Security Considerations:**

Batch processing services often have access to large volumes of sensitive data and may perform destructive operations. Organizations should implement additional controls such as input validation for batch jobs, output verification to detect tampering, execution monitoring to identify unauthorized job patterns, and integration with data loss prevention systems to prevent unauthorized data exfiltration through batch outputs.

---

### Integration Service

The Integration Service policy provides access patterns for services that integrate with external systems. This policy recognizes the unique security considerations of external integration, including the need for careful boundary control and secure communication patterns.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Integration Service",
  "description": "Access permissions for external integration services",
  "statements": [
    {
      "sid": "IntegrationRead",
      "effect": "ALLOW",
      "actions": ["read", "get", "pull", "sync"],
      "resources": [
        "integrations/*/data/*",
        "integrations/*/endpoints/*",
        "sync/*"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "integration"
        },
        "StringEquals": {
          "subject.integrationApproved": "true"
        }
      }
    },
    {
      "sid": "IntegrationWrite",
      "effect": "ALLOW",
      "actions": ["create", "update", "push", "send"],
      "resources": [
        "integrations/*/data/*",
        "integrations/*/endpoints/*",
        "webhooks/*"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "integration"
        },
        "StringEquals": {
          "subject.integrationApproved": "true"
        },
        "StringEquals": {
          "subject.writePermission": "granted"
        }
      }
    },
    {
      "sid": "IntegrationAuth",
      "effect": "ALLOW",
      "actions": ["authenticate", "authorize", "refresh-token"],
      "resources": ["integrations/*/credentials/*", "integrations/*/tokens/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "integration"
        }
      }
    },
    {
      "sid": "RequireSecureChannel",
      "effect": "ALLOW",
      "actions": ["*"],
      "resources": ["integrations/*"],
      "conditions": {
        "StringEquals": {
          "subject.tlsVersion": "1.2"
        },
        "StringEquals": {
          "input.secureChannel": "true"
        }
      }
    },
    {
      "sid": "DenyUnapprovedIntegrations",
      "effect": "DENY",
      "actions": ["*"],
      "resources": ["integrations/*"],
      "conditions": {
        "StringEquals": {
          "subject.type": "integration"
        },
        "StringNotEquals": {
          "subject.integrationApproved": "true"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `IntegrationRead` statement enables integration services to read data from integrated systems. The integration approved condition ensures that only vetted and approved integrations can access organizational data. This gate prevents unauthorized third-party services from accessing sensitive information.

The `IntegrationWrite` statement allows approved integrations to push data to external systems and receive webhook calls. This capability requires both integration approval and explicit write permission, recognizing that data export to external systems represents a significant security consideration. The combination of conditions creates appropriate controls for data sharing.

The `IntegrationAuth` statement provides access to credential management for integrations. Integration services need to authenticate with external systems, which requires storing and managing credentials securely. This statement enables integration services to access their own credentials and token resources while maintaining tenant boundaries.

The `RequireSecureChannel` statement enforces secure communication requirements for integration endpoints. The TLS version check ensures that only connections using appropriate encryption levels are accepted, while the secure channel condition verifies that the connection has been properly secured at the transport level.

The `DenyUnapprovedIntegrations` statement creates an explicit boundary that blocks all access for integrations that have not been approved. This provides a clear and auditable control point for integration governance, ensuring that only authorized external services can interact with organizational systems.

**Use Cases:**

This policy is appropriate for CRM integrations that synchronize customer data, ERP integrations that connect financial and operational systems, marketing automation integrations that share customer engagement data, legacy system connectors that enable modern applications to interact with older systems, and partner integrations that facilitate business-to-business data exchange.

**Security Considerations:**

Integration services represent an extended attack surface that includes both internal systems and external partners. Organizations should implement integration governance processes that vet and approve integrations before deployment, maintain inventories of active integrations with their data access patterns, monitor integration activity for unusual data volumes or access patterns, and establish clear data classification and handling requirements for integrated data flows.

---

### Cron Job Service

The Cron Job Service policy provides access patterns for scheduled task execution. This policy recognizes that scheduled jobs have specific operational requirements including time-based execution windows, credential handling for scheduled contexts, and job lifecycle management.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Cron Job Service",
  "description": "Access permissions for scheduled cron job services",
  "statements": [
    {
      "sid": "CronRead",
      "effect": "ALLOW",
      "actions": ["read", "list", "get"],
      "resources": ["cron-jobs/*", "schedules/*", "configurations/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "cron-service"
        }
      }
    },
    {
      "sid": "CronExecute",
      "effect": "ALLOW",
      "actions": ["execute", "run", "start"],
      "resources": ["cron-jobs/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "cron-service"
        },
        "StringEquals": {
          "input.scheduledTime": "true"
        }
      }
    },
    {
      "sid": "CronUpdateStatus",
      "effect": "ALLOW",
      "actions": ["update", "status"],
      "resources": ["cron-jobs/*", "job-executions/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "cron-service"
        }
      }
    },
    {
      "sid": "DenyManualCronExecution",
      "effect": "DENY",
      "actions": ["execute", "run", "start"],
      "resources": ["cron-jobs/*"],
      "conditions": {
        "StringEquals": {
          "subject.type": "cron-service"
        },
        "StringNotEquals": {
          "input.scheduledTime": "true"
        }
      }
    },
    {
      "sid": "EnforceExecutionWindow",
      "effect": "ALLOW",
      "actions": ["execute", "run", "start"],
      "resources": ["cron-jobs/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "cron-service"
        },
        "StringEquals": {
          "input.scheduledTime": "true"
        },
        "DateGreaterThan": {
          "input.currentTime": "input.windowStart"
        },
        "DateLessThan": {
          "input.currentTime": "input.windowEnd"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `CronRead` statement provides read access to cron job configurations and schedules. This enables the cron service to retrieve job definitions and determine what work needs to be executed. The subject type restriction ensures that only cron services can access these configurations.

The `CronExecute` statement allows cron services to execute scheduled jobs. The scheduled time condition ensures that execution is only permitted when the request is recognized as coming from the scheduler. This prevents unauthorized manual execution of scheduled jobs that might bypass operational controls.

The `CronUpdateStatus` statement enables cron services to update job execution status. This capability is essential for tracking job progress, recording results, and providing visibility into scheduled task outcomes. The status updates enable monitoring and alerting systems to track job health.

The `DenyManualCronExecution` statement explicitly prevents cron jobs from being executed outside of scheduled contexts. This creates a clear control boundary that ensures scheduled jobs only run according to their defined schedules, preventing operational disruptions from ad-hoc job execution.

The `EnforceExecutionWindow` statement implements time-based restrictions on job execution. By comparing the current time to configured window boundaries, this statement ensures that jobs only run during their designated execution windows. This capability supports scenarios like maintenance jobs that should only run during off-peak hours or batch processing that must complete before business hours.

**Use Cases:**

This policy is appropriate for data cleanup jobs that run during off-peak hours, report generation that must complete before business days begin, system maintenance tasks that run on scheduled intervals, data synchronization that needs to occur at specific times, and notification services that send scheduled communications.

**Security Considerations:**

Cron jobs often run with elevated privileges and can have significant system impact. Organizations should implement approval workflows for new cron jobs, monitor execution patterns for anomalies, restrict execution windows to reduce the window of opportunity for attacks, and ensure that cron job credentials are properly rotated and secured. Additionally, the output and logs of cron job executions should be monitored for indicators of compromise.

---

## Finance Policies

### Invoice Approval

The Invoice Approval policy provides access control for invoice processing and approval workflows. This policy implements financial controls including approval limits, segregation of duties, and audit trail requirements.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Invoice Approval",
  "description": "Access permissions for invoice processing and approval workflows",
  "statements": [
    {
      "sid": "ViewInvoices",
      "effect": "ALLOW",
      "actions": ["read", "list", "search", "export"],
      "resources": ["invoices/*", "invoices", "invoice-attachments/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.department": [
            "finance",
            "accounting",
            "procurement",
            "management"
          ]
        }
      }
    },
    {
      "sid": "CreateInvoices",
      "effect": "ALLOW",
      "actions": ["create", "import"],
      "resources": ["invoices/*", "invoices"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.department": ["finance", "accounting", "procurement"]
        }
      }
    },
    {
      "sid": "ApproveSmallInvoices",
      "effect": "ALLOW",
      "actions": ["approve"],
      "resources": ["invoices/*", "invoices"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.role": [
            "finance.manager",
            "finance.analyst",
            "department.lead"
          ]
        },
        "NumericLessThanEquals": {
          "input.invoiceAmount": 5000
        }
      }
    },
    {
      "sid": "ApproveMediumInvoices",
      "effect": "ALLOW",
      "actions": ["approve"],
      "resources": ["invoices/*", "invoices"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.role": ["finance.manager", "finance.director"]
        },
        "NumericGreaterThan": {
          "input.invoiceAmount": 5000
        },
        "NumericLessThanEquals": {
          "input.invoiceAmount": 25000
        }
      }
    },
    {
      "sid": "RequireDualApproval",
      "effect": "DENY",
      "actions": ["approve"],
      "resources": ["invoices/*", "invoices"],
      "conditions": {
        "NumericGreaterThan": {
          "input.invoiceAmount": 25000
        },
        "NumericEquals": {
          "input.approvalCount": 1
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ViewInvoices` statement provides read access to invoice data for authorized departments. The `StringEqualsAny` condition allows multiple departments to access invoices, recognizing that finance, accounting, procurement, and management all have legitimate needs to view invoice information. The export action enables auditors and compliance teams to extract invoice data for review.

The `CreateInvoices` statement allows authorized departments to create new invoices. This supports both manual invoice entry and automated import from external systems. The restriction to finance, accounting, and procurement departments ensures that only appropriate teams can initiate the invoicing process.

The `ApproveSmallInvoices` statement enables approval of invoices up to $5,000 by authorized roles. The approval limit is encoded in the condition, creating an automatic approval authority based on the invoice amount. This enables efficient processing of routine invoices while maintaining appropriate controls.

The `ApproveMediumInvoices` statement extends approval authority to mid-range invoices between $5,000 and $25,000 for senior finance roles. The combination of roles and amount ranges creates a tiered approval structure that matches approval authority to transaction risk.

The `RequireDualApproval` statement ensures that large invoices require multiple approvals. The condition checking that approval count equals one prevents single-party approval of invoices above $25,000, requiring at least two approvers before such invoices can be processed.

**Use Cases:**

This policy supports accounts payable processes where invoices must be reviewed and approved before payment, procurement workflows where purchase-related invoices require management review, expense reimbursement processes where employee expenses require approval, vendor management where vendor invoices need verification, and audit compliance where invoice trails must be maintained and accessible.

**Security Considerations:**

Invoice approval involves financial transactions and requires controls. Organizations should implement segregation strong of duties to prevent the same person from creating and approving the same invoice, maintain audit trails that capture who approved what and when, integrate with fraud detection systems for unusual invoice patterns, and establish regular review processes for approval patterns and exception handling.

---

### Payment Processing

The Payment Processing policy provides access control for payment operations including execution, monitoring, and reversal capabilities. This policy implements financial controls for payment security including limits, approvals, and audit requirements.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Payment Processing",
  "description": "Access permissions for payment execution and financial transaction processing",
  "statements": [
    {
      "sid": "ViewPaymentHistory",
      "effect": "ALLOW",
      "actions": ["read", "list", "search", "export"],
      "resources": [
        "payments/*",
        "payments",
        "payment-history/*",
        "transactions/*"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.department": ["finance", "treasury", "accounting"]
        }
      }
    },
    {
      "sid": "InitiatePayments",
      "effect": "ALLOW",
      "actions": ["create", "initiate", "submit"],
      "resources": ["payments/*", "payments", "pending-payments/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.role": ["accounts.payable", "treasury.analyst"]
        }
      }
    },
    {
      "sid": "ProcessSmallPayments",
      "effect": "ALLOW",
      "actions": ["process", "execute", "send"],
      "resources": ["payments/*", "payments", "pending-payments/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.role": ["treasury.manager", "finance.director", "cfo"]
        },
        "NumericLessThanEquals": {
          "input.amount": 10000
        }
      }
    },
    {
      "sid": "ProcessLargePayments",
      "effect": "ALLOW",
      "actions": ["process", "execute", "send"],
      "resources": ["payments/*", "payments", "pending-payments/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.role": "cfo"
        },
        "StringEquals": {
          "input.dualApproval": "confirmed"
        },
        "NumericGreaterThan": {
          "input.amount": 10000
        }
      }
    },
    {
      "sid": "ReversePayments",
      "effect": "ALLOW",
      "actions": ["reverse", "void", "recall"],
      "resources": ["payments/*", "payments"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.role": "treasury.manager"
        },
        "StringEquals": {
          "input.reversalReason": "documented"
        }
      }
    },
    {
      "sid": "DenySelfPaymentApproval",
      "effect": "DENY",
      "actions": ["approve", "process"],
      "resources": ["payments/*", "payments"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.createdBy"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ViewPaymentHistory` statement provides read access to payment records for authorized finance departments. This enables reconciliation, reporting, and audit activities. The restriction to specific departments ensures that payment history is only accessible to those with legitimate financial oversight responsibilities.

The `InitiatePayments` statement allows authorized roles to create and submit payments for processing. This is typically an accounts payable function that prepares payments based on approved invoices. The initiation capability includes creating payment records and submitting them to the payment queue.

The `ProcessSmallPayments` statement enables processing of payments up to $10,000 for authorized approvers. This creates an approval limit that matches typical daily payment volumes while requiring appropriate authorization. The combination of roles and amounts ensures that processing authority is appropriately tiered.

The `ProcessLargePayments` statement requires CFO approval and dual confirmation for payments over $10,000. The `input.dualApproval` condition ensures that large payments have been reviewed and approved through a secondary process before execution. This provides additional oversight for significant financial transactions.

The `ReversePayments` statement allows treasury managers to reverse payments that have been processed in error. The documented reversal reason requirement ensures that reversals are justified and tracked, supporting audit requirements and preventing unauthorized reversals.

The `DenySelfPaymentApproval` statement prevents individuals from approving their own payments. This critical control prevents fraud by ensuring that the person who created a payment cannot also approve its execution. Any payment must go through a separate approver.

**Use Cases:**

This policy supports accounts payable processes where approved invoices are converted to payments, treasury operations where cash management and payment execution occur, vendor payments where supplier invoices are settled, payroll processing where employee compensation is distributed, and expense reimbursement where employee expenses are reimbursed.

**Security Considerations:**

Payment processing represents the highest-risk financial operation and requires comprehensive controls. Organizations should implement multiple approval levels based on payment amounts, maintain separation between payment initiation and approval, integrate with fraud detection systems, require documented justification for all reversals, and maintain comprehensive audit trails that capture all payment activities with sufficient detail for forensic investigation.

---

### Expense Management

The Expense Management policy provides access control for expense reporting, reimbursement, and policy enforcement. This policy implements controls for both employee expense submission and management review.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Expense Management",
  "description": "Access permissions for expense reporting and reimbursement workflows",
  "statements": [
    {
      "sid": "SubmitExpenses",
      "effect": "ALLOW",
      "actions": ["create", "submit", "upload"],
      "resources": ["expenses/*", "expenses", "expense-receipts/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        }
      }
    },
    {
      "sid": "ManageOwnExpenses",
      "effect": "ALLOW",
      "actions": ["read", "update", "delete", "withdraw"],
      "resources": ["expenses/*"],
      "conditions": {
        "StringEquals": {
          "subject.id": "resource.submitterId"
        },
        "StringEquals": {
          "resource.status": "draft"
        }
      }
    },
    {
      "sid": "ViewTeamExpenses",
      "effect": "ALLOW",
      "actions": ["read", "list", "export"],
      "resources": ["expenses/*", "expenses", "expense-reports/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.teamId": "resource.teamId"
        },
        "StringEqualsAny": {
          "subject.role": ["team.lead", "manager", "finance.analyst"]
        }
      }
    },
    {
      "sid": "ApproveExpenses",
      "effect": "ALLOW",
      "actions": ["approve", "reject", "return"],
      "resources": ["expenses/*", "expenses", "expense-reports/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.id": "resource.approverId"
        },
        "StringEquals": {
          "resource.status": "submitted"
        }
      }
    },
    {
      "sid": "EnforceExpensePolicy",
      "effect": "ALLOW",
      "actions": ["validate", "flag", "notify"],
      "resources": ["expenses/*", "policy-checks/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.type": "expense-service"
        }
      }
    },
    {
      "sid": "DenyExpensePolicyViolations",
      "effect": "DENY",
      "actions": ["approve"],
      "resources": ["expenses/*"],
      "conditions": {
        "StringEquals": {
          "resource.policyCompliant": "false"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `SubmitExpenses` statement allows all users to submit expenses. This self-service capability enables employees to report their business expenses for reimbursement. The broad access recognizes that expense submission is a common activity that should not be restricted.

The `ManageOwnExpenses` statement provides control over expenses in draft status. This allows users to modify or delete their own expenses before submission. The draft status check ensures that once expenses are submitted, they cannot be modified without going through the approval workflow.

The `ViewTeamExpenses` statement enables managers and team leads to view expenses from their team members. This supports oversight and review responsibilities. The combination of team matching and role requirements ensures that managers can only view expenses from their direct reports.

The `ApproveExpenses` statement enables designated approvers to process submitted expenses. The conditions ensure that approvers are those specifically designated for the expense, the expense is in submitted status (not draft or already processed), and the approver's tenant matches the resource tenant.

The `EnforceExpensePolicy` statement allows the expense service to automatically validate expenses against policy rules. This enables policy enforcement without manual intervention for common violations like missing receipts, excessive amounts, or unapproved categories.

The `DenyExpensePolicyViolations` statement prevents approval of expenses that have been flagged as policy non-compliant. This ensures that automatic policy enforcement cannot be bypassed by manual approvers, creating a hard control for policy violations.

**Use Cases:**

This policy supports travel expense reporting where employees submit business travel costs, entertainment expenses where business entertainment costs are claimed, client expenses where costs incurred for client meetings are reimbursed, equipment purchases where business equipment purchases are expensed, and mileage reimbursement where business vehicle use is compensated.

**Security Considerations:**

Expense management requires controls to prevent fraud and ensure policy compliance. Organizations should implement receipt requirements for all expenses above threshold amounts, enforce category-specific policies that limit reimbursement for certain expense types, require manager approval that cannot be self-approved, monitor for unusual expense patterns that might indicate policy violations, and integrate expense data with fraud detection systems.

---

### Budget Oversight

The Budget Oversight policy provides access control for budget management, monitoring, and reporting. This policy implements controls for financial planning and expenditure tracking at various organizational levels.

```json
{
  "version": "2026-01-01",
  "tenantId": "tenant-abc",
  "name": "Budget Oversight",
  "description": "Access permissions for budget management and financial planning",
  "statements": [
    {
      "sid": "ViewBudgets",
      "effect": "ALLOW",
      "actions": ["read", "list", "export", "report"],
      "resources": [
        "budgets/*",
        "budgets",
        "budget-reports/*",
        "budget-history/*"
      ],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEqualsAny": {
          "subject.department": ["finance", "management", "executive"]
        }
      }
    },
    {
      "sid": "ManageDepartmentBudgets",
      "effect": "ALLOW",
      "actions": ["create", "update", "allocate", "reallocate"],
      "resources": ["budgets/*", "budgets"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.department": "finance"
        },
        "StringEquals": {
          "subject.budgetAuthority": "department"
        }
      }
    },
    {
      "sid": "ManageOwnDepartmentBudget",
      "effect": "ALLOW",
      "actions": ["read", "update"],
      "resources": ["budgets/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        },
        "StringEquals": {
          "subject.budgetAuthority": "manager"
        }
      }
    },
    {
      "sid": "ViewBudgetAlerts",
      "effect": "ALLOW",
      "actions": ["read", "acknowledge"],
      "resources": ["budget-alerts/*", "budget-notifications/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.departmentId": "resource.departmentId"
        }
      }
    },
    {
      "sid": "OverrideBudgetRestrictions",
      "effect": "ALLOW",
      "actions": ["override", "bypass"],
      "resources": ["budgets/*", "spending-limits/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "subject.role": "finance.director"
        },
        "StringEquals": {
          "input.overrideReason": "documented"
        }
      }
    },
    {
      "sid": "RequireBudgetForSpending",
      "effect": "DENY",
      "actions": ["create", "approve"],
      "resources": ["expenses/*", "purchase-orders/*", "invoices/*"],
      "conditions": {
        "StringEquals": {
          "subject.tenantId": "resource.tenantId"
        },
        "StringEquals": {
          "input.budgetAvailable": "false"
        }
      }
    }
  ]
}
```

**Statement Explanations:**

The `ViewBudgets` statement provides read access to budget information for authorized departments. The restriction to finance, management, and executive departments recognizes that budget information is sensitive and should be limited to those with financial oversight responsibilities.

The `ManageDepartmentBudgets` statement enables finance department members with budget authority to create and modify department budgets. This represents the primary budget management capability for organizational financial planning. The budget authority attribute ensures that only authorized finance staff can exercise this capability.

The `ManageOwnDepartmentBudget` statement provides department managers with view and update access to their own department's budget. This enables managers to track spending against their allocation and make adjustments within their authority. The combination of department ID matching and manager budget authority creates appropriate access controls.

The `ViewBudgetAlerts` statement enables department members to receive and acknowledge budget alerts. This supports proactive budget management by ensuring that relevant parties are notified when budgets approach or exceed thresholds. The department matching ensures alerts are routed to the appropriate teams.

The `OverrideBudgetRestrictions` statement allows finance directors to bypass budget restrictions when justified. The documented override reason requirement ensures that exceptions are tracked and justified, supporting audit requirements. This capability is essential for handling legitimate situations where business needs require spending beyond budgeted amounts.

The `RequireBudgetForSpending` statement creates a hard control that prevents spending when budget is not available. This ensures that organizational spending stays within approved budgets and prevents unauthorized overruns. The explicit deny creates a clear control point that cannot be bypassed without proper authorization.

**Use Cases:**

This policy supports departmental budgeting where departments manage their annual spending plans, project budgeting where project budgets are tracked and controlled, capital expenditure planning where major investments are budgeted and monitored, contingency management where unexpected costs are handled within budget constraints, and financial reporting where budget versus actual spending is analyzed.

**Security Considerations:**

Budget oversight involves significant financial authority and requires appropriate controls. Organizations should implement approval workflows for budget modifications, maintain segregation between budget creation and spending authority, monitor for budget manipulation attempts, integrate with spending controls to prevent overruns, and establish regular budget review processes with executive oversight.

---

## Rego Policy Examples

### Basic Rego Policy

This section provides Rego policies compatible with Open Policy Agent (OPA). Rego is OPA's native policy language, designed for expressing complex authorization logic with powerful query capabilities. The following examples demonstrate fundamental Rego patterns that can be used directly with OPA or integrated with the ABAC policy engine.

```rego
package policy.basic

# Import common attributes that will be used in policy evaluation
import input.subject
import input.resource
import input.action
import input.environment

# Default decision is to deny access
default allow = false

# Allow access if any statement grants permission
allow {
    some statement in data.policies[_].statements
    statement.effect == "ALLOW"
    action_matches(statement.actions, action)
    resource_matches(statement.resources, resource)
    conditions_met(statement.conditions)
}

# Deny access if any statement explicitly denies
deny[decision] {
    some statement in data.policies[_].statements
    statement.effect == "DENY"
    action_matches(statement.actions, action)
    resource_matches(statement.resources, resource)
    conditions_met(statement.conditions)
    decision := {
        "reason": "Denied by statement",
        "statement": statement.sid
    }
}

# Final decision logic - deny if any deny statements match
allow = false {
    count(deny) > 0
}

# Helper function to check if action matches allowed actions
action_matches(allowed_actions, requested_action) {
    allowed_actions[_] == "*"
}

action_matches(allowed_actions, requested_action) {
    allowed_actions[_] == requested_action
}

# Helper function to check if resource matches allowed resources
resource_matches(allowed_resources, requested_resource) {
    allowed_resources[_] == "*"
}

resource_matches(allowed_resources, requested_resource) {
    allowed_resources[_] == requested_resource
}

resource_matches(allowed_resources, requested_resource) {
    glob.match(allowed_resources[_], ["/"], requested_resource)
}

# Helper function to evaluate conditions
conditions_met(statement_conditions) {
    # If no conditions are specified, allow access
    count(statement_conditions) == 0
}

conditions_met(statement_conditions) {
    # Evaluate StringEquals conditions
    all_conditions_met(statement_conditions)
}

all_conditions_met(conditions) {
    # Check all StringEquals conditions
    all key, value in conditions.StringEquals {
        subject[key] == value
    }
}

all_conditions_met(conditions) {
    # Check all StringNotEquals conditions
    all key, value in conditions.StringNotEquals {
        subject[key] != value
    }
}

all_conditions_met(conditions) {
    # Check all NumericEquals conditions
    all key, value in conditions.NumericEquals {
        to_number(subject[key]) == value
    }
}

# Function to get denial reasons for debugging
deny_reasons[reason] {
    some statement in data.policies[_].statements
    statement.effect == "DENY"
    action_matches(statement.actions, action)
    resource_matches(statement.resources, resource)
    reason := statement.sid
}
```

**Explanation:**

This basic Rego package demonstrates the fundamental structure of an authorization policy. The `allow` rule is the primary decision point, evaluating to true if any allow statement matches the request context. The `deny` rule collects explicit deny statements that match the request.

The helper functions (`action_matches`, `resource_matches`, `conditions_met`) encapsulate the matching logic that compares policy statements against the authorization request. These functions handle wildcard patterns using OPA's built-in glob matching and evaluate conditions against the subject, resource, and action in the request context.

The package imports input attributes including the subject (who is making the request), resource (what is being accessed), action (what operation is requested), and environment (contextual information like time and IP address). These attributes are used to evaluate policy conditions.

**Use Cases:**

This policy pattern is appropriate for basic RBAC and ABAC enforcement where policies are stored in OPA's data repository, simple allow/deny decision making with explicit deny taking precedence, organizations already using OPA for policy decisions, and as a starting point for more complex policy logic.

**Security Considerations:**

Rego policies should be thoroughly tested using OPA's test framework before deployment. The policy should be evaluated for potential bypass vectors, especially around wildcard matching and condition evaluation. Organizations should implement policy versioning and change management processes for Rego policies.

---

### Complex Conditions Rego

This example demonstrates advanced Rego patterns for handling complex conditions including multi-value comparisons, temporal restrictions, and attribute-based access control with derived attributes.

```rego
package policy.complex

import input.subject
import input.resource
import input.action
import input.environment
import input.context

# Default decision
default allow = false

# Main allow rule with complex condition evaluation
allow {
    # Check for explicit allow statement
    some statement in data.policies[_].statements
    statement.effect == "ALLOW"
    action_matches(statement.actions)
    resource_matches(statement.resources)
    all_conditions_met(statement.conditions)
}

# Complex action matching with hierarchy
action_matches(statement_actions) {
    statement_actions[_] == "*"
}

action_matches(statement_actions) {
    statement_actions[_] == action
}

action_matches(statement_actions) {
    # Check action hierarchy - e.g., "write" covers "create", "update", "delete"
    data.action_hierarchy[action][_] == statement_actions[_]
}

# Resource matching with hierarchical paths
resource_matches(statement_resources) {
    statement_resources[_] == "*"
}

resource_matches(statement_resources) {
    statement_resources[_] == resource.path
}

resource_matches(statement_resources) {
    # Parent resource covers all children
    some parent_resource in statement_resources
    startswith(resource.path, parent_resource)
    endswith(parent_resource, "*")
}

resource_matches(statement_resources) {
    # Glob pattern matching
    glob.match(statement_resources[_], ["/"], resource.path)
}

# Comprehensive condition evaluation
all_conditions_met(conditions) {
    count(conditions) == 0
}

all_conditions_met(conditions) {
    not conditions.StringEquals
    not conditions.StringNotEquals
    not conditions.NumericEquals
    not conditions.NumericGreaterThan
    not conditions.NumericLessThan
    not conditions.DateGreaterThan
    not conditions.DateLessThan
    not conditions.IpAddressEquals
}

# StringEquals condition evaluation
all_conditions_met(conditions) {
    conditions.StringEquals
    all key, value in conditions.StringEquals {
        # Support dotted path access
        get_attribute(subject, key) == value
    }
}

# StringNotEquals condition evaluation
all_conditions_met(conditions) {
    conditions.StringNotEquals
    all key, value in conditions.StringNotEquals {
        get_attribute(subject, key) != value
    }
}

# Numeric condition evaluation
all_conditions_met(conditions) {
    conditions.NumericEquals
    all key, value in conditions.NumericEquals {
        to_number(get_attribute(subject, key)) == value
    }
}

all_conditions_met(conditions) {
    conditions.NumericGreaterThan
    all key, value in conditions.NumericGreaterThan {
        to_number(get_attribute(subject, key)) > value
    }
}

all_conditions_met(conditions) {
    conditions.NumericLessThan
    all key, value in conditions.NumericLessThan {
        to_number(get_attribute(subject, key)) < value
    }
}

# Date/time condition evaluation
all_conditions_met(conditions) {
    conditions.DateGreaterThan
    all key, value in conditions.DateGreaterThan {
        time.parse_rfc3339(value) < time.parse_rfc3339(get_attribute(input.context, key))
    }
}

all_conditions_met(conditions) {
    conditions.DateLessThan
    all key, value in conditions.DateLessThan {
        time.parse_rfc3339(value) > time.parse_rfc3339(get_attribute(input.context, key))
    }
}

# IP address condition evaluation with CIDR support
all_conditions_met(conditions) {
    conditions.IpAddressEquals
    all key, value in conditions.IpAddressEquals {
        is_ip_in_range(input.environment.sourceIp, value)
    }
}

all_conditions_met(conditions) {
    conditions.IpAddressNotEquals
    all key, value in conditions.IpAddressNotEquals {
        not is_ip_in_range(input.environment.sourceIp, value)
    }
}

# IP range checking with CIDR support
is_ip_in_range(ip, cidr) {
    net.cidr_contains(cidr, ip)
}

# Derive computed attributes for policy evaluation
is_within_office_hours {
    current_hour := time.hour(time.now_ns())
    current_hour >= 9
    current_hour <= 17
    day_of_week := time.weekday(time.now_ns())
    day_of_week != "Saturday"
    day_of_week != "Sunday"
}

is_business_location {
    subject.location in {"office", "home"}
}

# Attribute access helper with dotted path support
get_attribute(obj, path) {
    # Handle dotted paths like "subject.department.id"
    parts := split(path, ".")
    value := obj[parts[0]]
    value := walk_path(value, parts[1:])
}

get_attribute(obj, path) {
    # Simple direct access
    obj[path]
}

# Recursive path walking for nested attributes
walk_path(value, [head]) {
    value[head]
}

walk_path(value, [head | tail]) {
    value := value[head]
    walk_path(value, tail)
}

# Derived attribute rules for enhanced policy evaluation
subject_has_mfa {
    subject.mfaEnabled == true
    subject.lastMfaUsedwithin "1h"
}

subject_is_active {
    subject.status == "active"
    subject.employmentStatus == "full-time"
}

# Role-based access with role hierarchy
has_role(required_role) {
    # Check direct role assignment
    subject.roles[_] == required_role
}

has_role(required_role) {
    # Check role hierarchy - admin covers all other roles
    subject.roles[_] == "admin"
}

has_role(required_role) {
    # Check inherited roles
    some assigned_role in subject.roles
    data.role_hierarchy[assigned_role][_] == required_role
}
```

**Explanation:**

This advanced Rego package demonstrates complex policy patterns including action hierarchies, resource path matching, comprehensive condition operators, computed attributes, and role hierarchy support. The policy supports sophisticated ABAC scenarios that go beyond simple allow/deny rules.

The action matching logic includes hierarchy support where higher-level actions can encompass multiple specific actions. For example, a "write" action might cover "create", "update", and "delete" operations, reducing the number of policy statements needed.

Resource matching supports hierarchical paths where parent resource permissions implicitly grant access to child resources. Combined with glob pattern matching, this enables flexible resource specification that matches organizational resource hierarchies.

The condition evaluation functions support all major operators including string comparisons, numeric comparisons, date/time comparisons, and IP address matching with CIDR notation. Each condition type is evaluated separately and combined using AND logic.

**Use Cases:**

This policy pattern is appropriate for complex enterprise authorization scenarios with multiple condition types, organizations requiring hierarchical resource structures, time-based access restrictions (business hours, maintenance windows), IP-based access controls with CIDR ranges, and role hierarchies that enable flexible permission inheritance.

**Security Considerations:**

Complex Rego policies require comprehensive testing to ensure correct evaluation under all conditions. Organizations should implement policy testing as part of CI/CD pipelines, maintain policy documentation that explains complex logic, consider policy complexity limits to prevent maintenance challenges, and implement policy analysis tools to identify potential issues before deployment.

---

### Multi-Tenant Rego Policy

This example demonstrates Rego policies designed specifically for multi-tenant environments, with strong tenant isolation, cross-tenant access controls, and tenant-specific policy customization.

```rego
package policy.tenant

import input.subject
import input.resource
import input.action
import input.environment
import input.request

# Default to deny for security
default allow = false

# Primary authorization decision
allow {
    # Check tenant boundary first
    same_tenant
    # Check for allow statement
    some statement in data.tenant_policies[subject.tenantId].statements
    statement.effect == "ALLOW"
    action_matches(statement.actions)
    resource_matches(statement.resources)
    tenant_conditions_met(statement.conditions)
}

# Tenant boundary check - fundamental security control
same_tenant {
    subject.tenantId == resource.tenantId
}

same_tenant {
    # Allow cross-tenant access only if explicitly permitted
    some cross_tenant_policy in data.cross_tenant_policies
    cross_tenant_policy.sourceTenant == subject.tenantId
    cross_tenant_policy.targetTenant == resource.tenantId
    cross_tenant_policy.resourcePattern == resource.path
    cross_tenant_policy.actionPattern == action
    cross_tenant_policy.enabled == true
}

# Deny all cross-tenant access by default
deny_cross_tenant {
    not same_tenant
    not cross_tenant_allowed
}

cross_tenant_allowed {
    some cross_tenant_policy in data.cross_tenant_policies
    cross_tenant_policy.sourceTenant == subject.tenantId
    cross_tenant_policy.targetTenant == resource.tenantId
    cross_tenant_policy.resourcePattern == resource.path
    cross_tenant_policy.actionPattern == action
    cross_tenant_policy.enabled == true
}

# Tenant-specific policy evaluation
tenant_conditions_met(conditions) {
    count(conditions) == 0
}

tenant_conditions_met(conditions) {
    # Tenant ID matching - always required for tenant-scoped resources
    conditions.StringEquals
    all key, value in conditions.StringEquals {
        key == "subject.tenantId"
        subject.tenantId == value
    }
}

tenant_conditions_met(conditions) {
    # Multi-tenant conditions with tenant-specific values
    conditions.TenantSpecificConditions
    tenant_config := data.tenant_config[subject.tenantId]
    conditions.TenantSpecificConditions[condition_key] == tenant_config[condition_key]
}

# Resource type-specific tenant checks
tenant_conditions_met(conditions) {
    conditions.ResourceTenantMatch
    subject.tenantId == resource.tenantId
}

# Tenant configuration lookup for derived attributes
tenant_max_file_size {
    tenant_config := data.tenant_config[subject.tenantId]
    tenant_config.maxFileSize
}

tenant_allow_external_sharing {
    tenant_config := data.tenant_config[subject.tenantId]
    tenant_config.allowExternalSharing == true
}

tenant_enforce_mfa {
    tenant_config := data.tenant_config[subject.tenantId]
    tenant_config.mfaRequired == true
}

# Tenant-specific feature flags
feature_enabled(feature_name) {
    tenant_config := data.tenant_config[subject.tenantId]
    tenant_config.features[feature_name] == true
}

# Role-based access with tenant scoping
has_tenant_role(role) {
    subject.tenantId == resource.tenantId
    subject.roles[_] == role
}

has_tenant_role(role) {
    # Tenant-scoped role from tenant-specific role assignment
    subject.tenantScopedRoles[subject.tenantId][_] == role
}

# Tenant data residency compliance
data_residency_compliant {
    resource.data residencyRegion
    subject.tenantId
    tenant_config := data.tenant_config[subject.tenantId]
    tenant_config.requiredDataResidency == resource.dataResidencyRegion
}

# Audit logging for cross-tenant access
audit_cross_tenant_access {
    not same_tenant
    cross_tenant_allowed
}

# Tenant isolation enforcement
deny[result] {
    not same_tenant
    not cross_tenant_allowed
    result := {
        "decision": "deny",
        "reason": "Cross-tenant access not permitted",
        "subject_tenant": subject.tenantId,
        "resource_tenant": resource.tenantId
    }
}

# Tenant-specific rate limiting
within_rate_limit {
    tenant_config := data.tenant_config[subject.tenantId]
    requests := count_requests(subject.tenantId, environment.sourceIp)
    requests < tenant_config.rateLimitPerMinute
}

count_requests(tenant_id, source_ip) = count {
    recent_requests := data.request_logs[tenant_id][source_ip]
    count := count(recent_requests)
}

count_requests(tenant_id, source_ip) = 0 {
    not data.request_logs[tenant_id]
}

count_requests(tenant_id, source_ip) = 0 {
    not data.request_logs[tenant_id][source_ip]
}
```

**Explanation:**

This Rego package is specifically designed for multi-tenant environments where strong tenant isolation is critical. The policy implements fundamental tenant boundary checks that prevent cross-tenant access by default, with explicit cross-tenant policies required for any inter-tenant data sharing.

The `same_tenant` rule is the primary boundary check, comparing the subject's tenant ID against the resource's tenant ID. This comparison is fundamental to multi-tenant security and is required for most access decisions. Cross-tenant access is only permitted through explicit cross-tenant policies stored separately, enabling controlled data sharing between tenants.

The policy includes tenant configuration lookup functions that retrieve tenant-specific settings for feature flags, rate limits, data residency requirements, and other configurable aspects. This enables tenants to have different security configurations while maintaining consistent policy evaluation.

The tenant isolation enforcement uses explicit deny statements that provide clear rejection reasons for cross-tenant access attempts. This supports both security monitoring and user experience by providing clear feedback when access is denied due to tenant boundaries.

**Use Cases:**

This policy pattern is appropriate for SaaS providers serving multiple independent customers, multi-tenant applications with strong isolation requirements, organizations with multiple subsidiaries requiring controlled data sharing, cloud platforms implementing tenant isolation, and any environment where data residency or compliance requirements mandate tenant boundaries.

**Security Considerations:**

Multi-tenant policies require careful implementation to prevent cross-tenant data leakage. Organizations should implement thorough testing of tenant boundary enforcement, regular audits of cross-tenant policies, monitoring for cross-tenant access attempts, and clear separation between tenant-specific data in the policy decision point. The policy should be designed to fail securely, defaulting to deny when tenant information is missing or ambiguous.

---

## Use Cases

### Common Scenarios

This section describes common authorization scenarios and how the policy examples in this document address them.

**Scenario 1: User Accessing Own Data**

A standard user wants to access their own profile, documents, and personal settings. This is the most common authorization scenario and is handled by the Basic Member policy's owner-based access rules. The policy evaluates conditions comparing the subject's identifier against the resource's owner identifier, granting access when they match. This pattern ensures users can access their own data while preventing access to others' private information. The implementation is straightforward and performant, using direct attribute comparison rather than complex queries. Organizations should ensure that owner attributes are consistently populated and maintained as users create and transfer resources.

**Scenario 2: Administrator Managing Users**

An administrator needs to create, update, and deactivate user accounts. This scenario requires elevated privileges that are granted through the User Management Administrator policy. The policy provides comprehensive user management capabilities while maintaining tenant boundaries and preventing administrators from modifying their own accounts. The separation of management capabilities from the ability to assign permissions provides additional security controls. Organizations should implement workflow approvals for sensitive user management operations and maintain audit logs of all administrative actions.

**Scenario 3: Service Calling API**

An automated service needs to read and write data on behalf of the organization. Service account access is controlled by the API Service policy, which implements strict requirements including service type verification, credential validation, and network zone restrictions. Services must authenticate with valid service tokens and operate from designated network zones. The policy separates read and write permissions, with write operations requiring additional trust level verification. Organizations should implement strict credential management for services, including regular rotation and minimal permission scopes.

**Scenario 4: Team Collaboration**

Team members need shared access to project resources. Team-based access is implemented through the Team-Based Access policy, which grants permissions based on team membership. Team leads have additional capabilities for resource deletion and membership management. The policy supports the full team lifecycle including resource creation, collaboration, and cleanup. Organizations should implement team governance policies that define appropriate team sizes and membership review processes.

**Scenario 5: Invoice Approval Workflow**

Finance team members need to approve invoices within their authority limits. Invoice approval is handled by the Finance policies, which implement tiered approval limits based on invoice amounts. The policy ensures that approvers have appropriate authority for the invoice value and that large invoices require multiple approvals. Organizations should implement segregation of duties to prevent the same person from creating and approving the same invoice.

**Scenario 6: Batch Data Processing**

A scheduled job processes large volumes of data overnight. Batch processing is controlled by the Batch Processing Service policy, which provides appropriate access patterns for bulk operations. The policy restricts execution to scheduler-initiated requests, preventing manual triggering that could bypass workload management. Organizations should implement monitoring for batch job patterns and validate inputs to prevent processing of unauthorized data.

### Advanced Patterns

This section describes advanced authorization patterns that extend the basic policy examples.

**Pattern 1: Hierarchical Roles**

Organizations often have role hierarchies where senior roles inherit permissions from junior roles. The Rego policy examples demonstrate how to implement role hierarchies using data lookups that define inheritance relationships. For example, a manager role might inherit all permissions from the member role, while an admin role inherits from manager. This pattern reduces policy complexity by eliminating the need to duplicate permissions across roles. Implementation requires maintaining accurate role hierarchy data and ensuring that inheritance is properly evaluated during policy decisions.

**Pattern 2: Attribute-Based Conditions**

Beyond simple equality checks, ABAC policies can evaluate complex conditions based on multiple attributes. The policy examples demonstrate conditions that combine multiple checks using AND logic, evaluate temporal attributes like current time and day of week, and derive computed attributes like MFA status. This pattern enables sophisticated access control that considers the full context of access requests. Organizations should carefully design condition logic to avoid contradictions that could result in unintended denials.

**Pattern 3: Time-Based Restrictions**

Access can be restricted to specific time windows using date comparison conditions. The policies demonstrate how to restrict access to business hours, enforce maintenance windows, and implement time-limited access grants. This pattern is particularly useful for sensitive operations that should only be performed during controlled periods. Implementation requires reliable time sources and proper handling of time zones.

**Pattern 4: Risk-Based Access Control**

Access decisions can incorporate risk signals from external systems. The policy examples demonstrate how to reference external attributes like risk scores and incorporate them into decision logic. High-risk access requests might require additional verification or be denied entirely. Organizations should integrate with risk assessment systems and define clear escalation paths for risk-based denials.

**Pattern 5: Delegation-Based Access**

Users can temporarily delegate access to others through explicit delegation relationships. The Resource Owner policy demonstrates delegation patterns where resource owners can grant access to delegates. Delegations should be time-limited and trackable to prevent unauthorized permanent access grants. Organizations should implement delegation monitoring and automatic expiration.

**Pattern 6: Just-In-Time Access**

Privileged access can be granted temporarily through just-in-time (JIT) access systems. The admin policies support JIT patterns by allowing time-limited elevated access. Access requests go through an approval workflow, and granted access automatically expires after a defined period. Organizations should implement JIT access for all elevated privileges and maintain audit trails of JIT access grants.

---

## Security Considerations

### Default Deny Principle

All authorization systems should follow the default deny principle, where access is denied unless explicitly allowed by policy. The policy examples in this document implement this principle through explicit allow statements and deny statements that capture known denial scenarios. When designing policies, start with an empty set of permissions and add only those that are explicitly required. This approach minimizes the attack surface and reduces the risk of unintended access grants.

The default deny principle requires careful attention to policy completeness. Missing policies or undefined resource types should result in denial rather than implicit allowance. Organizations should implement comprehensive policy coverage for all resource types and regularly review policies to ensure completeness.

### Explicit Allow Requirements

All allowed access should be explicitly defined in policy statements rather than relying on the absence of deny statements. Explicit allow statements provide clear documentation of intended access patterns and enable policy analysis tools to identify potential issues. The policy examples use explicit allow statements with specific action and resource patterns rather than broad wildcards.

When using wildcards for actions or resources, ensure that the scope is appropriate and that conditions provide sufficient restriction. Wildcards should be combined with conditions that limit their effect to appropriate contexts.

### Tenant Isolation

In multi-tenant environments, tenant boundaries are fundamental security controls. The policy examples implement tenant isolation through explicit tenant ID comparisons in conditions and cross-tenant access controls that require explicit authorization. Tenant isolation should be enforced at every layer of the authorization system, including policy evaluation, data access, and audit logging.

Cross-tenant access should only be permitted through explicit cross-tenant policies that define the allowed data sharing relationships. Organizations should regularly review cross-tenant policies to ensure that they reflect current business requirements.

### Audit Logging

All authorization decisions should be logged with sufficient detail to support security monitoring and forensic investigation. The policy examples include statement identifiers that enable tracking of which policy statements authorized or denied specific access requests. Audit logs should capture the subject, resource, action, decision, and relevant conditions for each request.

Organizations should implement log retention policies that meet compliance requirements and enable long-term security analysis. Logs should be protected against tampering and stored in secure locations.

### Credential Security

Service accounts and API credentials require special security attention due to their elevated privileges and automated use. The policy examples implement credential type verification and token validation to ensure that only valid credentials are accepted. Organizations should implement strict credential management including regular rotation, minimal permission scopes, and monitoring for unusual credential usage.

Service credentials should be stored securely using appropriate secrets management solutions. Access to service credentials should be limited and monitored.

### Policy Versioning

Policies should be versioned to enable tracking of changes and rollback capabilities. The version field in policy metadata supports policy evolution while maintaining backward compatibility. Organizations should implement change management processes for policy modifications and test policies thoroughly before deployment.

Policy history should be maintained to support audit requirements and incident investigation. Previous versions should be retained according to organizational retention policies.

### Least Privilege

The principle of least privilege should guide all policy design. Policies should grant only the permissions required for specific tasks, with access limited to the minimum set of actions and resources needed. The policy examples demonstrate this principle through specific action and resource patterns rather than broad wildcards.

Organizations should regularly review policies to identify and remove unnecessary permissions. Access reviews should be conducted periodically to ensure that permissions remain appropriate.

---

## Best Practices

### Policy Design Guidelines

When designing ABAC policies, start with a clear understanding of the access requirements for each role and use case. Map permissions to specific business needs rather than copying generic policy templates. Policies should be scoped appropriately to the resource types and actions they govern.

Use consistent naming conventions for policy statements and clear descriptions that explain the purpose of each statement. This documentation supports policy maintenance and audit requirements.

Group related permissions into cohesive policies rather than scattering permissions across multiple policies. This organization makes policies easier to understand and maintain.

### Testing and Validation

All policies should be thoroughly tested before deployment. Use OPA's built-in testing framework to create comprehensive test cases that cover both expected access grants and edge cases. Test cases should verify that policies correctly handle both positive and negative scenarios.

Implement policy analysis tools that can identify potential issues before deployment. These tools can detect contradictory statements, overly broad permissions, and common security anti-patterns.

### Monitoring and Alerting

Implement monitoring for authorization patterns that might indicate security issues. Alert on unusual access patterns, repeated denied requests, and access attempts from unexpected locations or times.

Regularly review authorization metrics to identify opportunities for policy optimization and security improvement. Access patterns can reveal both security risks and operational inefficiencies.

### Documentation and Governance

Maintain comprehensive documentation of all policies and their intended effects. Documentation should explain the business purpose of each policy and any specific security considerations.

Implement governance processes for policy changes that include review, approval, and testing requirements. Policy changes should be tracked with sufficient detail to support audit requirements.

---

## Conclusion

This document has provided comprehensive examples of ABAC policies for enterprise authorization scenarios. The examples cover administrative access, standard user access, service account access, financial operations, and Rego policies for OPA integration.

Each policy example includes detailed explanations of its structure, intended use cases, and security considerations. The document also covers common scenarios and advanced patterns that demonstrate how to apply these policies in real-world situations.

Organizations implementing these policies should adapt the examples to their specific requirements, considering their unique security needs, compliance requirements, and operational constraints. Regular review and refinement of policies will ensure that authorization controls remain effective as organizational needs evolve.

The combination of JSON-based policy examples and Rego implementations provides flexibility for different deployment scenarios, whether using the native policy engine or integrating with Open Policy Agent. This flexibility enables organizations to choose the approach that best fits their technical architecture and operational preferences.
