/**
 * ABAC Policy DSL Type Definitions
 *
 * AWS IAM-style policy language for enterprise-grade attribute-based access control.
 * Version: 2026-01-01
 */

/**
 * Core policy version identifier
 */
export const POLICY_VERSION = "2026-01-01" as const;

/**
 * Effect constants for policy statements
 */
export enum PolicyEffect {
  ALLOW = "ALLOW",
  DENY = "DENY",
}

/**
 * Principal type identifiers
 */
export enum PrincipalType {
  USER = "User",
  ROLE = "Role",
  SERVICE = "Service",
}

/**
 * Condition operator types for ABAC evaluation
 */
export enum ConditionOperator {
  // String operators
  STRING_EQUALS = "StringEquals",
  STRING_NOT_EQUALS = "StringNotEquals",
  STRING_LIKE = "StringLike",
  STRING_NOT_LIKE = "StringNotLike",
  STRING_EQUALS_IGNORE_CASE = "StringEqualsIgnoreCase",
  STRING_STARTS_WITH = "StringStartsWith",
  STRING_ENDS_WITH = "StringEndsWith",

  // Numeric operators
  NUMERIC_EQUALS = "NumericEquals",
  NUMERIC_GREATER_THAN = "NumericGreaterThan",
  NUMERIC_GREATER_THAN_EQUALS = "NumericGreaterThanEquals",
  NUMERIC_LESS_THAN = "NumericLessThan",
  NUMERIC_LESS_THAN_EQUALS = "NumericLessThanEquals",

  // Boolean operators
  BOOL = "Bool",

  // Date/Time operators
  DATE_EQUALS = "DateEquals",
  DATE_GREATER_THAN = "DateGreaterThan",
  DATE_LESS_THAN = "DateLessThan",

  // IP address operators
  IP_ADDRESS = "IpAddress",
  NOT_IP_ADDRESS = "NotIpAddress",

  // Null check
  NULL = "Null",

  // Set operators
  SET_IN = "SetIn",
  SET_NOT_IN = "SetNotIn",
}

/**
 * Policy metadata structure
 */
export interface PolicyMetadata {
  description?: string;
  tags?: Record<string, string>;
  deprecated?: boolean;
  createdAt?: string;
  updatedAt?: string;
  createdBy?: string;
  updatedBy?: string;
  version?: number;
}

/**
 * Principal specification for policy statements
 */
export interface PolicyPrincipal {
  type: PrincipalType;
  ids?: string[]; // Specific principal IDs
  wildcard?: boolean; // Apply to all principals of this type
}

/**
 * Condition key-value pair for policy evaluation
 */
export interface ConditionKeyValue<T = string | number | boolean> {
  key: string;
  value: T;
}

/**
 * Policy condition block containing multiple condition operators
 */
export interface PolicyCondition {
  // String conditions
  StringEquals?: Record<string, string>;
  StringNotEquals?: Record<string, string>;
  StringLike?: Record<string, string>;
  StringNotLike?: Record<string, string>;
  StringEqualsIgnoreCase?: Record<string, string>;
  StringStartsWith?: Record<string, string>;
  StringEndsWith?: Record<string, string>;

  // Numeric conditions
  NumericEquals?: Record<string, number>;
  NumericGreaterThan?: Record<string, number>;
  NumericGreaterThanEquals?: Record<string, number>;
  NumericLessThan?: Record<string, number>;
  NumericLessThanEquals?: Record<string, number>;

  // Boolean conditions
  Bool?: Record<string, boolean>;

  // Date/Time conditions (ISO 8601)
  DateEquals?: Record<string, string>;
  DateGreaterThan?: Record<string, string>;
  DateLessThan?: Record<string, string>;

  // IP address conditions (CIDR notation)
  IpAddress?: Record<string, string>;
  NotIpAddress?: Record<string, string>;

  // Null check
  Null?: Record<string, boolean>;

  // Set conditions
  SetIn?: Record<string, string[]>;
  SetNotIn?: Record<string, string[]>;

  // Custom conditions for extensibility
  [key: string]: Record<string, unknown> | undefined;
}

/**
 * Individual policy statement
 */
export interface PolicyStatement {
  sid: string; // Statement ID (unique within policy)
  effect: PolicyEffect; // ALLOW or DENY
  actions: string[]; // Action patterns (e.g., ["INVOICE_*", "PAYMENT_APPROVE"])
  resources: string[]; // Resource patterns (e.g., ["invoice:*", "invoice:123"])
  conditions?: PolicyCondition; // Optional conditions for ABAC
  principal?: PolicyPrincipal; // Optional principal specification
  notActions?: string[]; // Excluded actions (advanced use)
  notResources?: string[]; // Excluded resources (advanced use)
}

/**
 * Complete ABAC policy document
 */
export interface ABACPolicy {
  version: string; // Policy language version
  tenantId: string; // Tenant isolation
  statements: PolicyStatement[]; // Policy statements
  metadata?: PolicyMetadata; // Optional metadata
}

/**
 * Policy reference with attachment information
 */
export interface PolicyAttachment {
  policyId: string;
  policyVersion: number;
  attachedAt: string;
  attachedBy: string;
  scope: {
    principalType: PrincipalType;
    principalIds: string[];
  };
}

/**
 * Policy set (collection of policies)
 */
export interface PolicySet {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  policies: ABACPolicy[];
  attachments: PolicyAttachment[];
  metadata?: PolicyMetadata;
}

/**
 * Policy evaluation context
 */
export interface PolicyEvaluationContext {
  subject: {
    id: string;
    tenantId: string;
    roles: string[];
    attributes: Record<string, unknown>;
  };
  action: string;
  resource: {
    type: string;
    id?: string;
    ownerId?: string;
    tenantId: string;
    attributes: Record<string, unknown>;
  };
  context: {
    timestamp: string;
    ipAddress?: string;
    mfaAuthenticated?: boolean;
    riskScore?: number;
    environment: "production" | "staging" | "development";
    requestId?: string;
    sessionId?: string;
    userAgent?: string;
  };
}

/**
 * Authorization decision result
 */
export interface AuthorizationDecision {
  decision: PolicyEffect.ALLOW | PolicyEffect.DENY;
  matchedPolicies: string[];
  matchedStatements: MatchedStatement[];
  reason: string;
  evaluationTimeMs: number;
  trace: EvaluationTrace;
}

/**
 * Matched statement details
 */
export interface MatchedStatement {
  policyId: string;
  policyName: string;
  statementId: string;
  effect: PolicyEffect;
  matchedConditions: string[];
}

/**
 * Evaluation trace for debugging and auditing
 */
export interface EvaluationTrace {
  statementsEvaluated: number;
  conditionsEvaluated: number;
  conditionsMatched: number;
  denyStatementsMatched: number;
  allowStatementsMatched: number;
  evaluationPath: EvaluationStep[];
}

/**
 * Individual evaluation step for trace
 */
export interface EvaluationStep {
  statementId: string;
  actionMatch: boolean;
  resourceMatch: boolean;
  conditionResult?: boolean;
  matchedConditions: string[];
}

/**
 * Policy validation result
 */
export interface PolicyValidationResult {
  valid: boolean;
  errors: PolicyValidationError[];
  warnings: PolicyValidationWarning[];
}

/**
 * Policy validation error
 */
export interface PolicyValidationError {
  code: string;
  message: string;
  path: string;
  statementId?: string;
}

/**
 * Policy validation warning
 */
export interface PolicyValidationWarning {
  code: string;
  message: string;
  path: string;
  suggestion?: string;
}

/**
 * Request for policy evaluation
 */
export interface EvaluationRequest {
  subject: {
    id: string;
    tenantId: string;
    roles: string[];
    attributes?: Record<string, unknown>;
  };
  action: string;
  resource: {
    type: string;
    id?: string;
    ownerId?: string;
    tenantId: string;
    attributes?: Record<string, unknown>;
  };
  context: {
    timestamp: string;
    ipAddress?: string;
    mfaAuthenticated?: boolean;
    riskScore?: number;
    environment?: "production" | "staging" | "development";
    requestId?: string;
  };
}

/**
 * Audit log entry for authorization decisions
 */
export interface AuthorizationAuditLog {
  id: string;
  tenantId: string;
  timestamp: string;
  requestId: string;
  subjectId: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  decision: PolicyEffect;
  matchedPolicies: string[];
  ipAddress?: string;
  userAgent?: string;
  evaluationTimeMs: number;
  trace?: EvaluationTrace;
}
