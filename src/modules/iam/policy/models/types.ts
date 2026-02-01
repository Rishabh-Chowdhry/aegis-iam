/**
 * ABAC Policy DSL Type Definitions
 *
 * Comprehensive type definitions for the Attribute-Based Access Control
 * policy domain-specific language (DSL).
 *
 * Enterprise-grade ABAC system with multi-tenant support,
 * designed for financial data handling with rigorous tenant isolation.
 */

// ==================== CORE POLICY TYPES ====================

/**
 * Policy version string format (ISO 8601 date)
 * Only versions "2026-01-01" or later are supported
 */
export type PolicyVersion = "2026-01-01";

/**
 * Policy lifecycle status
 */
export type PolicyStatus = "ACTIVE" | "DEPRECATED" | "DISABLED" | "DRAFT";

/**
 * Statement effect - determines authorization decision
 */
export type PolicyEffect = "ALLOW" | "DENY";

/**
 * Principal types for ABAC
 */
export type PrincipalType = "User" | "Role" | "Group" | "Service" | "Anonymous";

// ==================== CONDITION OPERATOR TYPES ====================

/**
 * String condition operators for attribute comparison
 */
export type StringConditionOperator =
  | "StringEquals"
  | "StringNotEquals"
  | "StringLike"
  | "StringNotLike";

/**
 * Numeric condition operators for numeric attribute comparison
 */
export type NumericConditionOperator =
  | "NumericEquals"
  | "NumericNotEquals"
  | "NumericGreaterThan"
  | "NumericGreaterThanOrEquals"
  | "NumericLessThan"
  | "NumericLessThanOrEquals";

/**
 * Boolean condition operator
 */
export type BoolConditionOperator = "Bool";

/**
 * List condition operators for multi-value attribute comparison
 */
export type ListConditionOperator = "ListContains" | "ListNotContains";

/**
 * Union of all condition operators
 */
export type ConditionOperator =
  | StringConditionOperator
  | NumericConditionOperator
  | BoolConditionOperator
  | ListConditionOperator;

// ==================== CONDITION KEYS ====================

/**
 * Condition keys for subject attributes
 * Used to reference subject properties in conditions
 */
export type SubjectConditionKey =
  | "subject.id"
  | "subject.tenantId"
  | "subject.roles"
  | `subject.attributes.${string}`;

/**
 * Condition keys for resource attributes
 * Used to reference resource properties in conditions
 */
export type ResourceConditionKey =
  | "resource.type"
  | "resource.id"
  | "resource.tenantId"
  | `resource.attributes.${string}`;

/**
 * Condition keys for request context attributes
 * Used to reference environmental/contextual properties in conditions
 */
export type ContextConditionKey =
  | "context.time"
  | "context.ip"
  | "context.mfa"
  | "context.riskScore"
  | "context.environment";

/**
 * All valid condition keys
 */
export type ConditionKey =
  | SubjectConditionKey
  | ResourceConditionKey
  | ContextConditionKey;

// ==================== ROOT POLICY TYPES ====================

/**
 * Root ABAC Policy Document
 * Comparable to AWS IAM Policy format
 */
export interface ABACPolicy {
  /** Policy version for future compatibility */
  version: PolicyVersion;

  /** Tenant identifier for multi-tenant isolation */
  tenantId: string;

  /** Unique policy identifier */
  id: string;

  /** Human-readable policy name */
  name: string;

  /** Policy statements defining permissions */
  statements: PolicyStatement[];

  /** Optional metadata for governance */
  metadata?: PolicyMetadata;

  /** Policy status for lifecycle management */
  status?: PolicyStatus;
}

/**
 * Policy metadata for governance and management
 */
export interface PolicyMetadata {
  /** Human-readable description */
  description?: string;

  /** Organizational tags for categorization */
  tags?: Record<string, string>;

  /** Policy version for versioning support */
  version?: number;

  /** Deprecation information */
  deprecated?: {
    deprecatedAt: string;
    sunsetDate?: string;
    replacementPolicyId?: string;
    reason?: string;
  };

  /** Audit trail */
  createdBy?: string;
  createdAt?: string;
  updatedBy?: string;
  updatedAt?: string;

  /** Compliance and regulatory tags */
  compliance?: {
    framework?: string;
    requirement?: string;
    controlId?: string;
  };

  /** Evaluation priority (higher = evaluated first) */
  priority?: number;
}

// ==================== POLICY STATEMENT TYPES ====================

/**
 * Policy Statement - Core permission unit
 */
export interface PolicyStatement {
  /** Statement identifier (unique within policy) */
  sid: string;

  /** Effect - ALLOW or DENY */
  effect: PolicyEffect;

  /** Principal specification - who this applies to */
  principal?: PrincipalSpec;

  /** Actions this statement applies to */
  actions: ActionSpec;

  /** Resources this statement applies to */
  resources: ResourceSpec;

  /** Conditions that must be met */
  conditions?: PolicyCondition;

  /** Optional description */
  description?: string;
}

/**
 * Principal specification
 */
export interface PrincipalSpec {
  /** Principal type */
  type: PrincipalType;

  /** Principal identifiers - supports wildcards */
  ids?: string[];

  /** Principal attributes for ABAC */
  attributes?: Record<string, unknown>;
}

/**
 * Action specification
 */
export interface ActionSpec {
  /** Action names - supports wildcards and prefixes */
  includes: string[];

  /** Actions explicitly excluded */
  excludes?: string[];

  /** Action group membership */
  groups?: string[];
}

/**
 * Resource specification
 */
export interface ResourceSpec {
  /** Resource type patterns */
  types: string[];

  /** Resource ID patterns */
  ids?: string[];

  /** Resource path patterns */
  paths?: string[];

  /** Resource attributes for ABAC */
  attributes?: Record<string, unknown>;
}

// ==================== CONDITION TYPES ====================

/**
 * Policy Condition - Conditional access logic
 */
export interface PolicyCondition {
  // String conditions
  StringEquals?: Record<string, string>;
  StringNotEquals?: Record<string, string>;
  StringEqualsIgnoreCase?: Record<string, string>;
  StringLike?: Record<string, string>;
  StringNotLike?: Record<string, string>;

  // Numeric conditions
  NumericEquals?: Record<string, number>;
  NumericNotEquals?: Record<string, number>;
  NumericGreaterThan?: Record<string, number>;
  NumericGreaterThanEquals?: Record<string, number>;
  NumericLessThan?: Record<string, number>;
  NumericLessThanEquals?: Record<string, number>;

  // Boolean conditions
  Bool?: Record<string, boolean>;

  // Date/Time conditions (ISO 8601)
  DateGreaterThan?: Record<string, string>;
  DateLessThan?: Record<string, string>;
  DateGreaterThanEquals?: Record<string, string>;
  DateLessThanEquals?: Record<string, string>;
  DateEquals?: Record<string, string>;
  DateNotEquals?: Record<string, string>;

  // IP address conditions (CIDR)
  IpAddress?: Record<string, string>;
  NotIpAddress?: Record<string, string>;

  // List conditions
  InList?: Record<string, string | number | boolean>;
  NotInList?: Record<string, string | number | boolean>;

  // Null check
  Null?: Record<string, boolean>;
}

// ==================== AUTHORIZATION REQUEST TYPES ====================

/**
 * Authorization Request
 */
export interface AuthorizationRequest {
  /** Unique request identifier for tracing */
  requestId: string;

  /** Subject (who is making the request) */
  subject: Subject;

  /** Action being performed */
  action: Action;

  /** Resource being accessed */
  resource: Resource;

  /** Contextual information */
  context: RequestContext;

  /** Policy scope */
  policyScope?: PolicyScope;
}

/**
 * Authorization Context - Used internally for evaluation
 * Omits requestId since it's only for tracing
 */
export interface AuthorizationContext {
  /** Subject (who is making the request) */
  subject: Subject;

  /** Action being performed */
  action: Action;

  /** Resource being accessed */
  resource: Resource;

  /** Contextual information */
  context: RequestContext;
}

/**
 * Subject - Who is making the request
 */
export interface Subject {
  /** Unique subject identifier */
  id: string;

  /** Tenant identifier */
  tenantId: string;

  /** Subject type */
  type: PrincipalType;

  /** Roles assigned to the subject */
  roles?: string[];

  /** Groups the subject belongs to */
  groups?: string[];

  /** Additional subject attributes */
  attributes?: SubjectAttributes;
}

/**
 * Subject attributes
 */
export interface SubjectAttributes {
  email?: string;
  department?: string;
  title?: string;
  managerId?: string;
  createdAt?: string;
  lastLoginAt?: string;
  mfaEnabled?: boolean;
  status?: "ACTIVE" | "INACTIVE" | "SUSPENDED" | "PENDING";
  vpnIp?: string;
  officeLocation?: string;
  [key: string]: unknown;
}

/**
 * Action - What operation is being performed
 */
export interface Action {
  /** Unique action identifier */
  id: string;

  /** HTTP method if applicable */
  method?: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD";

  /** Action category for grouping */
  category?: "read" | "write" | "delete" | "admin" | "execute";

  /** Risk level of the action */
  riskLevel?: "low" | "medium" | "high" | "critical";

  /** Human-readable action name */
  displayName?: string;

  /** Description of the action */
  description?: string;
}

/**
 * Resource - What is being accessed
 */
export interface Resource {
  /** Resource type */
  type: string;

  /** Resource identifier */
  id?: string;

  /** Resource owner identifier */
  ownerId?: string;

  /** Tenant identifier */
  tenantId: string;

  /** Parent resource for hierarchical resources */
  parentId?: string;

  /** Resource attributes for ABAC evaluation */
  attributes?: ResourceAttributes;

  /** Resource labels for categorization */
  labels?: Record<string, string>;
}

/**
 * Resource attributes
 */
export interface ResourceAttributes {
  classification?: "public" | "internal" | "confidential" | "restricted";
  sensitivity?: number;
  createdAt?: string;
  updatedAt?: string;
  dueDate?: string;
  amount?: number;
  exportReason?: string;
  [key: string]: unknown;
}

/**
 * Request Context - Environmental information
 */
export interface RequestContext {
  /** Request timestamp (ISO 8601) */
  timestamp: string;

  /** Client IP address */
  ipAddress?: string;

  /** Client user agent */
  userAgent?: string;

  /** HTTP referer header */
  referer?: string;

  /** Whether MFA was used for authentication */
  mfaAuthenticated?: boolean;

  /** Risk score from fraud detection (0-100) */
  riskScore?: number;

  /** Deployment environment */
  environment?: "production" | "staging" | "development" | "test";

  /** Request source */
  source?: "web" | "mobile" | "api" | "cli" | "webhook";

  /** Geographic location derived from IP */
  location?: {
    country?: string;
    region?: string;
    city?: string;
    latitude?: number;
    longitude?: number;
  };

  /** Session identifier */
  sessionId?: string;

  /** Hour of day (0-23) */
  hour?: number;

  /** Day of week (1-7, Monday=1) */
  dayOfWeek?: number;

  [key: string]: unknown;
}

/**
 * Policy Scope
 */
export interface PolicyScope {
  /** Specific policy IDs to evaluate */
  policyIds?: string[];

  /** Policy names to include */
  policyNames?: string[];

  /** Policy tags to filter */
  policyTags?: Record<string, string>;

  /** Include system policies */
  includeSystemPolicies?: boolean;
}

// ============================================================================
// POLICY EVALUATION INPUT (as specified in requirements)
// ============================================================================

/**
 * Policy evaluation input for the PolicyEngine
 * Uses core types from authorization.ts
 */
export interface PolicyEvaluationInput {
  /** Subject (who is making the request) - uses core Subject type */
  subject: {
    id: string;
    tenantId: string;
    roles: string[];
    attributes: Record<string, any>;
  };
  /** Action being performed */
  action: {
    id: string;
  };
  /** Resource being accessed */
  resource: {
    id: string;
    type: string;
    tenantId: string;
    ownerId?: string;
    attributes: Record<string, any>;
  };
  /** Contextual information */
  context: {
    time: Date;
    ip: string;
    mfa: boolean;
    riskScore: number;
    environment: "production" | "staging" | "development";
    [key: string]: any;
  };
  /** Policies to evaluate */
  policies: IAMPolicy[];
}

/**
 * AWS IAM-style policy interface
 */
export interface IAMPolicy {
  /** Policy version */
  version: string;
  /** Tenant identifier for multi-tenant isolation */
  tenantId: string;
  /** Policy statements */
  statements: IAMPolicyStatement[];
}

/**
 * Policy statement for AWS IAM-style policies
 */
export interface IAMPolicyStatement {
  /** Statement identifier */
  sid: string;
  /** Effect - ALLOW or DENY */
  effect: "ALLOW" | "DENY";
  /** Actions this statement applies to (supports wildcards) */
  actions: string[];
  /** Resources this statement applies to (supports wildcards) */
  resources: string[];
  /** Conditions that must be met */
  conditions?: Record<string, Record<string, any>>;
}

// ============================================================================
// AUTHORIZATION RESPONSE TYPES
// ============================================================================

/**
 * Authorization Decision
 */
export interface AuthorizationDecision {
  /** Final decision */
  decision: "ALLOW" | "DENY" | "NO_MATCH" | "INDETERMINATE";

  /** Whether the decision was made */
  determined: boolean;

  /** Policies that matched */
  matchedPolicies: MatchedPolicy[];

  /** Policies that were evaluated */
  evaluatedPolicies: string[];

  /** Human-readable reason */
  reason: string;

  /** Detailed reason code */
  reasonCode: ReasonCode;

  /** Evaluation metrics */
  metrics: EvaluationMetrics;

  /** Detailed trace (optional) */
  trace?: EvaluationTrace;

  /** Obligations */
  obligations?: Obligation[];
}

/**
 * Reason codes for decisions
 */
export type ReasonCode =
  | "ALLOWED_BY_POLICY"
  | "DENIED_BY_POLICY"
  | "DENIED_BY_DEFAULT"
  | "ALLOWED_BY_DEFAULT"
  | "NO_APPLICABLE_POLICY"
  | "TENANT_ISOLATION_VIOLATION"
  | "POLICY_NOT_FOUND"
  | "POLICY_DISABLED"
  | "EVALUATION_ERROR"
  | "MISSING_CONTEXT"
  | "INVALID_REQUEST";

/**
 * Matched policy information
 */
export interface MatchedPolicy {
  /** Policy ID */
  policyId: string;

  /** Policy name */
  policyName: string;

  /** Statement ID that matched */
  statementId: string;

  /** Effect of the matched statement */
  effect: PolicyEffect;

  /** Whether this was an explicit deny */
  isExplicitDeny: boolean;

  /** Conditions that matched */
  matchedConditions: ConditionResult[];

  /** Why this policy matched */
  matchedReason: string;
}

/**
 * Condition evaluation result
 */
export interface ConditionResult {
  /** Condition operator */
  operator: string;

  /** Variable path */
  variablePath: string;

  /** Expected values */
  expectedValues: unknown[];

  /** Actual value */
  actualValue: unknown;

  /** Whether matched */
  matched: boolean;
}

/**
 * Evaluation metrics
 */
export interface EvaluationMetrics {
  /** Total evaluation time in milliseconds */
  evaluationTimeMs: number;

  /** Number of policies evaluated */
  policiesEvaluated: number;

  /** Number of policies matched */
  policiesMatched: number;

  /** Number of conditions evaluated */
  conditionsEvaluated: number;

  /** Number of conditions that matched */
  conditionsMatched: number;

  /** Cache hit indicator */
  cacheHit: boolean;
}

/**
 * Detailed evaluation trace
 */
export interface EvaluationTrace {
  /** Evaluation steps */
  steps: EvaluationStep[];

  /** Policy evaluation order */
  evaluationOrder: string[];

  /** Variables extracted from context */
  extractedVariables: Record<string, unknown>;
}

/**
 * Individual evaluation step
 */
export interface EvaluationStep {
  /** Step number */
  step: number;

  /** Policy evaluated */
  policyId: string;

  /** Statement evaluated */
  statementId: string;

  /** Whether matched */
  matched: boolean;

  /** Effect if matched */
  effect?: PolicyEffect;

  /** Error if any */
  error?: string;
}

/**
 * Obligation - Required action after authorization
 */
export interface Obligation {
  /** Obligation type */
  type:
    | "LOG"
    | "NOTIFY"
    | "APPROVE"
    | "MFA_CHALLENGE"
    | "CAPTCHA"
    | "RATE_LIMIT";

  /** Obligation parameters */
  parameters?: Record<string, unknown>;
}

// ==================== POLICY EVALUATION RESULT ====================

/**
 * Result of evaluating a single policy against an authorization request
 */
export interface PolicyEvaluationResult {
  /** ID of the policy that was evaluated */
  policyId: string;

  /** ID of the statement that matched (if any) */
  statementId?: string;

  /** Whether the policy matched the request */
  matched: boolean;

  /** Effect if matched (ALLOW or DENY) */
  effect: "ALLOW" | "DENY";

  /** Whether all conditions were met */
  conditionsMet: boolean;

  /** Actions that matched the policy */
  matchedActions: string[];

  /** Resources that matched the policy */
  matchedResources: string[];

  /** Detailed reason for the evaluation result */
  reason?: string;

  /** Conditions that were evaluated */
  evaluatedConditions?: ConditionResult[];
}
