/**
 * Policy-Based Authorization Engine
 *
 * This module implements a flexible policy engine for fine-grained authorization.
 * Policies can be based on roles, attributes, conditions, and resource properties.
 */

import { User } from "../entities/User";

// ==================== Policy Types ====================

export enum PolicyEffect {
  ALLOW = "ALLOW",
  DENY = "DENY",
}

export enum PolicyConditionOperator {
  EQUALS = "EQUALS",
  NOT_EQUALS = "NOT_EQUALS",
  IN = "IN",
  NOT_IN = "NOT_IN",
  CONTAINS = "CONTAINS",
  GREATER_THAN = "GREATER_THAN",
  LESS_THAN = "LESS_THAN",
  EXISTS = "EXISTS",
  NOT_EXISTS = "NOT_EXISTS",
  REGEX = "REGEX",
}

export interface PolicyCondition {
  field: string; // e.g., "resource.ownerId", "user.department"
  operator: PolicyConditionOperator;
  value: any;
}

export interface Policy {
  id: string;
  name: string;
  description?: string;
  effect: PolicyEffect;
  conditions: PolicyCondition[];
  priority: number; // Higher priority = evaluated first
  enabled: boolean;
  createdAt: Date;
  updatedAt: Date;
}

export interface Resource {
  id: string;
  type: string;
  ownerId?: string;
  tenantId: string;
  attributes?: Record<string, any>;
}

export interface AuthorizationContext {
  user: User;
  resource: Resource;
  action: string;
  environment?: {
    ip?: string;
    userAgent?: string;
    time?: Date;
    [key: string]: any;
  };
}

export interface AuthorizationDecision {
  allowed: boolean;
  policyId?: string;
  policyName?: string;
  reason?: string;
  matchedConditions?: PolicyCondition[];
}

// ==================== Policy Evaluator ====================

export interface PolicyEvaluator {
  evaluate(policy: Policy, context: AuthorizationContext): boolean;
}

export class ConditionEvaluator {
  /**
   * Evaluate a single condition against the context
   */
  static evaluate(
    condition: PolicyCondition,
    context: AuthorizationContext,
  ): boolean {
    const fieldValue = this.getFieldValue(condition.field, context);

    switch (condition.operator) {
      case PolicyConditionOperator.EQUALS:
        return fieldValue === condition.value;

      case PolicyConditionOperator.NOT_EQUALS:
        return fieldValue !== condition.value;

      case PolicyConditionOperator.IN:
        return (
          Array.isArray(condition.value) && condition.value.includes(fieldValue)
        );

      case PolicyConditionOperator.NOT_IN:
        return (
          Array.isArray(condition.value) &&
          !condition.value.includes(fieldValue)
        );

      case PolicyConditionOperator.CONTAINS:
        if (Array.isArray(fieldValue)) {
          return fieldValue.includes(condition.value);
        }
        if (typeof fieldValue === "string") {
          return fieldValue.includes(condition.value);
        }
        return false;

      case PolicyConditionOperator.GREATER_THAN:
        return typeof fieldValue === "number" && fieldValue > condition.value;

      case PolicyConditionOperator.LESS_THAN:
        return typeof fieldValue === "number" && fieldValue < condition.value;

      case PolicyConditionOperator.EXISTS:
        return fieldValue !== undefined && fieldValue !== null;

      case PolicyConditionOperator.NOT_EXISTS:
        return fieldValue === undefined || fieldValue === null;

      case PolicyConditionOperator.REGEX:
        if (typeof fieldValue === "string") {
          const regex = new RegExp(condition.value);
          return regex.test(fieldValue);
        }
        return false;

      default:
        return false;
    }
  }

  /**
   * Get the value of a field from the context using dot notation
   */
  private static getFieldValue(
    field: string,
    context: AuthorizationContext,
  ): any {
    const parts = field.split(".");
    let current: any = context;

    for (const part of parts) {
      if (current === undefined || current === null) {
        return undefined;
      }

      if (part === "resource" || part === "user" || part === "environment") {
        current = current[part];
      } else if (part === "attributes") {
        current = current.attributes;
      } else {
        current = current[part];
      }
    }

    return current;
  }
}

export class StandardPolicyEvaluator implements PolicyEvaluator {
  evaluate(policy: Policy, context: AuthorizationContext): boolean {
    // If no conditions, the policy applies to everything
    if (policy.conditions.length === 0) {
      return true;
    }

    // All conditions must match (AND logic)
    return policy.conditions.every((condition) =>
      ConditionEvaluator.evaluate(condition, context),
    );
  }
}

// ==================== Policy Engine ====================

export class PolicyEngine {
  private evaluators: Map<string, PolicyEvaluator> = new Map();
  private policies: Map<string, Policy> = new Map();
  private defaultEffect: PolicyEffect;

  constructor(options: { defaultEffect?: PolicyEffect } = {}) {
    this.defaultEffect = options.defaultEffect ?? PolicyEffect.DENY;

    // Register default evaluators
    this.registerEvaluator("standard", new StandardPolicyEvaluator());
  }

  /**
   * Register a policy evaluator for a specific policy type
   */
  registerEvaluator(type: string, evaluator: PolicyEvaluator): void {
    this.evaluators.set(type, evaluator);
  }

  /**
   * Add a policy to the engine
   */
  addPolicy(policy: Policy): void {
    if (!policy.enabled) {
      return;
    }
    this.policies.set(policy.id, policy);
  }

  /**
   * Remove a policy from the engine
   */
  removePolicy(policyId: string): void {
    this.policies.delete(policyId);
  }

  /**
   * Get a policy by ID
   */
  getPolicy(policyId: string): Policy | undefined {
    return this.policies.get(policyId);
  }

  /**
   * Get all policies
   */
  getAllPolicies(): Policy[] {
    return Array.from(this.policies.values());
  }

  /**
   * Clear all policies
   */
  clearPolicies(): void {
    this.policies.clear();
  }

  /**
   * Evaluate authorization for a context
   */
  authorize(context: AuthorizationContext): AuthorizationDecision {
    // Get all applicable policies sorted by priority
    const applicablePolicies = this.getApplicablePolicies(context);

    // Evaluate each policy in priority order
    for (const policy of applicablePolicies) {
      const evaluator = this.getEvaluator(policy);

      if (evaluator.evaluate(policy, context)) {
        return {
          allowed: policy.effect === PolicyEffect.ALLOW,
          policyId: policy.id,
          policyName: policy.name,
          reason:
            policy.effect === PolicyEffect.ALLOW
              ? "Access granted by policy"
              : "Access denied by policy",
          matchedConditions: policy.conditions,
        };
      }
    }

    // No policy matched, apply default effect
    return {
      allowed: this.defaultEffect === PolicyEffect.ALLOW,
      reason: `No matching policy, defaulting to ${this.defaultEffect}`,
    };
  }

  /**
   * Check if an action is allowed (returns boolean)
   */
  isAllowed(context: AuthorizationContext): boolean {
    return this.authorize(context).allowed;
  }

  /**
   * Get all policies applicable to the context
   */
  private getApplicablePolicies(context: AuthorizationContext): Policy[] {
    return Array.from(this.policies.values())
      .filter((policy) => {
        // Check if policy is for the same tenant
        const policyTenantId = this.getPolicyTenantId(policy);
        return (
          policyTenantId === context.resource.tenantId || policyTenantId === "*"
        );
      })
      .sort((a, b) => b.priority - a.priority);
  }

  /**
   * Get the appropriate evaluator for a policy
   */
  private getEvaluator(policy: Policy): PolicyEvaluator {
    // Default to standard evaluator
    return this.evaluators.get("standard") ?? new StandardPolicyEvaluator();
  }

  /**
   * Get tenant ID from a policy
   */
  private getPolicyTenantId(policy: Policy): string {
    // Policies store tenantId in conditions or metadata
    const tenantCondition = policy.conditions.find(
      (c) => c.field === "resource.tenantId",
    );
    return (tenantCondition?.value as string) ?? "*";
  }
}

// ==================== RBAC + Policy Hybrid Authorizer ====================

export interface RolePermissions {
  roleId: string;
  permissions: string[]; // Format: "resource:action"
}

export class HybridAuthorizer {
  private policyEngine: PolicyEngine;
  private roleHierarchy: Map<string, string[]> = new Map();
  private rolePermissions: Map<string, string[]> = new Map();

  constructor(policyEngine: PolicyEngine) {
    this.policyEngine = policyEngine;
  }

  /**
   * Set up role hierarchy
   */
  setRoleHierarchy(parentRole: string, childRoles: string[]): void {
    this.roleHierarchy.set(parentRole, childRoles);
  }

  /**
   * Set permissions for a role
   */
  setRolePermissions(roleId: string, permissions: string[]): void {
    this.rolePermissions.set(roleId, permissions);
  }

  /**
   * Check if user has permission
   */
  hasPermission(user: User, resource: string, action: string): boolean {
    // Check direct permissions
    if (this.hasDirectPermission(user, resource, action)) {
      return true;
    }

    // Check inherited permissions through role hierarchy
    return this.hasInheritedPermission(user, resource, action);
  }

  /**
   * Check if user has direct permission
   */
  private hasDirectPermission(
    user: User,
    resource: string,
    action: string,
  ): boolean {
    for (const roleId of user.roles) {
      const permissions = this.rolePermissions.get(roleId) || [];
      if (this.permissionsIncludeAction(permissions, resource, action)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if user has inherited permission through role hierarchy
   */
  private hasInheritedPermission(
    user: User,
    resource: string,
    action: string,
  ): boolean {
    const inheritedRoleIds = this.getInheritedRoles(user);

    for (const roleId of inheritedRoleIds) {
      const permissions = this.rolePermissions.get(roleId) || [];
      if (this.permissionsIncludeAction(permissions, resource, action)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if a list of permissions includes the requested action
   */
  private permissionsIncludeAction(
    permissions: string[],
    resource: string,
    action: string,
  ): boolean {
    for (const perm of permissions) {
      if (this.matchesPermission(perm, resource, action)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Get all inherited role IDs for a user
   */
  private getInheritedRoles(user: User): string[] {
    const inheritedRoles: string[] = [];
    const visited = new Set<string>();

    for (const roleId of user.roles) {
      this.collectInheritedRoles(roleId, inheritedRoles, visited);
    }

    return inheritedRoles;
  }

  /**
   * Recursively collect inherited role IDs
   */
  private collectInheritedRoles(
    roleId: string,
    collected: string[],
    visited: Set<string>,
  ): void {
    if (visited.has(roleId)) {
      return;
    }
    visited.add(roleId);

    if (!collected.includes(roleId)) {
      collected.push(roleId);
    }

    // Collect parent roles
    const childRoles = this.roleHierarchy.get(roleId) || [];
    for (const childRole of childRoles) {
      this.collectInheritedRoles(childRole, collected, visited);
    }
  }

  /**
   * Check if a permission matches the resource and action
   */
  private matchesPermission(
    permission: string,
    resource: string,
    action: string,
  ): boolean {
    // Permission format: "resource:action" or "*:*"
    const parts = permission.split(":");
    if (parts.length !== 2) {
      return false;
    }

    const [permResource, permAction] = parts;

    // Check for wildcards
    if (permResource === "*" || permResource === resource) {
      if (permAction === "*" || permAction === action) {
        return true;
      }
    }

    return false;
  }

  /**
   * Authorize with hybrid RBAC + Policy approach
   */
  authorize(context: AuthorizationContext): AuthorizationDecision {
    // First, check RBAC permissions
    if (
      this.hasPermission(context.user, context.resource.type, context.action)
    ) {
      // Then check if there are any DENY policies
      const decision = this.policyEngine.authorize(context);

      if (decision.allowed && decision.policyId) {
        // There's an explicit policy - respect it
        return decision;
      }

      // RBAC allows and no explicit DENY policy
      if (!decision.policyId || decision.allowed) {
        return {
          allowed: true,
          reason: "Access granted by role-based permissions",
        };
      }

      // Policy denied
      return decision;
    }

    // RBAC doesn't allow, check for explicit ALLOW policy
    const policyDecision = this.policyEngine.authorize(context);

    if (policyDecision.allowed) {
      return {
        allowed: true,
        policyId: policyDecision.policyId,
        policyName: policyDecision.policyName,
        reason: "Access granted by policy override",
      };
    }

    // Access denied
    return {
      allowed: false,
      reason: "Access denied: insufficient permissions",
    };
  }
}

// ==================== Common Policy Templates ====================

export class PolicyTemplates {
  /**
   * Create an owner-only policy
   */
  static ownerOnly(resourceType: string, action: string): Policy {
    return {
      id: `policy:${resourceType}:${action}:owner`,
      name: `${resourceType}:${action} - Owner Only`,
      description: `Only the owner of a ${resourceType} can ${action} it`,
      effect: PolicyEffect.ALLOW,
      conditions: [
        {
          field: "resource.type",
          operator: PolicyConditionOperator.EQUALS,
          value: resourceType,
        },
        {
          field: "resource.ownerId",
          operator: PolicyConditionOperator.EQUALS,
          value: "${user.id}",
        },
      ],
      priority: 100,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Create a role-based policy
   */
  static roleBased(
    resourceType: string,
    action: string,
    allowedRoles: string[],
  ): Policy {
    return {
      id: `policy:${resourceType}:${action}:roles`,
      name: `${resourceType}:${action} - Role Based`,
      description: `Users with specific roles can ${action} ${resourceType}`,
      effect: PolicyEffect.ALLOW,
      conditions: [
        {
          field: "resource.type",
          operator: PolicyConditionOperator.EQUALS,
          value: resourceType,
        },
        {
          field: "user.roles",
          operator: PolicyConditionOperator.IN,
          value: allowedRoles,
        },
      ],
      priority: 50,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Create a time-based policy
   */
  static timeBased(
    resourceType: string,
    action: string,
    allowedHours: { start: number; end: number },
  ): Policy {
    return {
      id: `policy:${resourceType}:${action}:time`,
      name: `${resourceType}:${action} - Time Based`,
      description: `Only allowed during specific hours`,
      effect: PolicyEffect.ALLOW,
      conditions: [
        {
          field: "resource.type",
          operator: PolicyConditionOperator.EQUALS,
          value: resourceType,
        },
        {
          field: "environment.time",
          operator: PolicyConditionOperator.GREATER_THAN,
          value: allowedHours.start,
        },
        {
          field: "environment.time",
          operator: PolicyConditionOperator.LESS_THAN,
          value: allowedHours.end,
        },
      ],
      priority: 75,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }

  /**
   * Create an IP-based whitelist policy
   */
  static ipWhitelist(
    resourceType: string,
    action: string,
    allowedIps: string[],
  ): Policy {
    return {
      id: `policy:${resourceType}:${action}:ip`,
      name: `${resourceType}:${action} - IP Whitelist`,
      description: `Only requests from specific IPs can ${action} ${resourceType}`,
      effect: PolicyEffect.ALLOW,
      conditions: [
        {
          field: "resource.type",
          operator: PolicyConditionOperator.EQUALS,
          value: resourceType,
        },
        {
          field: "environment.ip",
          operator: PolicyConditionOperator.IN,
          value: allowedIps,
        },
      ],
      priority: 200,
      enabled: true,
      createdAt: new Date(),
      updatedAt: new Date(),
    };
  }
}
