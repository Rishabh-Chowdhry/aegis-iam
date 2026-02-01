/**
 * Authorization Types
 * Defines the core types for authorization requests and decisions
 */

// ============================================================================
// CORE ABAC TYPES (as specified in requirements)
// ============================================================================

/**
 * Subject making the authorization request
 */
export interface Subject {
  /** Unique identifier for the subject */
  id: string;
  /** Tenant context */
  tenantId: string;
  /** Roles assigned to the subject */
  roles: string[];
  /** Subject attributes for ABAC evaluation */
  attributes: Record<string, any>;
}

/**
 * Action being performed
 */
export interface Action {
  /** Unique action identifier (e.g., "INVOICE_APPROVE") */
  id: string;
}

/**
 * Resource being accessed
 */
export interface Resource {
  /** Unique identifier for the resource */
  id: string;
  /** Type of resource (e.g., "invoice", "user") */
  type: string;
  /** Tenant context */
  tenantId: string;
  /** Resource owner identifier */
  ownerId?: string;
  /** Resource attributes for ABAC evaluation */
  attributes: Record<string, any>;
}

/**
 * Context surrounding the authorization request
 */
export interface EvaluationContext {
  /** Request timestamp */
  time: Date;
  /** Client IP address */
  ip: string;
  /** Whether MFA was used for authentication */
  mfa: boolean;
  /** Risk score from fraud detection (0-100) */
  riskScore: number;
  /** Deployment environment */
  environment: "production" | "staging" | "development";
  /** Additional context attributes */
  [key: string]: any;
}

/**
 * Authorization decision result
 */
export interface AuthorizationDecision {
  /** The authorization decision */
  decision: "ALLOW" | "DENY";
  /** Array of policy IDs that contributed to the decision */
  matchedPolicies: string[];
  /** Human-readable explanation of the decision */
  reason: string;
}

// ============================================================================
// EXTENDED TYPES (for enterprise features)
// ============================================================================

/**
 * Represents the type of subject making an authorization request
 */
export type SubjectType = "User" | "Role" | "Service" | "APIKey" | "Session";

/**
 * Represents the type of resource being accessed
 */
export type ResourceType =
  | "Document"
  | "Folder"
  | "User"
  | "Role"
  | "Policy"
  | "Tenant"
  | "API"
  | "Function"
  | "Custom";

/**
 * The action being performed on a resource
 */
export type ActionType =
  | "create"
  | "read"
  | "update"
  | "delete"
  | "list"
  | "execute"
  | "admin"
  | "share"
  | "download"
  | "upload"
  | "import"
  | "export";

/**
 * Extended subject interface with enterprise features
 */
export interface ExtendedSubject {
  /** Unique identifier for the subject */
  id: string;
  /** Type of subject */
  type: SubjectType;
  /** Tenant context */
  tenantId: string;
  /** Subject attributes for ABAC evaluation */
  attributes: Record<string, unknown>;
  /** Roles assigned to the subject */
  roles?: string[];
  /** Direct permissions assigned to the subject */
  permissions?: string[];
}

/**
 * Extended resource interface with enterprise features
 */
export interface ExtendedResource {
  /** Unique identifier for the resource */
  id: string;
  /** Type of resource */
  type: ResourceType;
  /** Tenant context */
  tenantId: string;
  /** Resource attributes for ABAC evaluation */
  attributes: Record<string, unknown>;
  /** Ownership information */
  ownerId?: string;
  /** Parent resource if hierarchical */
  parentId?: string;
}

/**
 * Extended action interface with enterprise features
 */
export interface ExtendedAction {
  /** Action being performed */
  type: ActionType;
  /** Custom action name if not standard */
  name?: string;
  /** Additional action metadata */
  metadata?: Record<string, unknown>;
}

/**
 * Extended context surrounding the authorization request
 */
export interface AuthorizationContext {
  /** IP address of the request origin */
  ipAddress?: string;
  /** User agent string */
  userAgent?: string;
  /** Request timestamp */
  timestamp: Date;
  /** Geographic location if available */
  location?: {
    country?: string;
    region?: string;
    city?: string;
  };
  /** Session information */
  session?: {
    id: string;
    createdAt: Date;
    lastActivityAt: Date;
    expiresAt: Date;
  };
  /** Request metadata */
  requestMetadata?: Record<string, unknown>;
  /** Environment variables */
  environment?: Record<string, unknown>;
}

/**
 * Request for authorization decision
 */
export interface AuthorizationRequest {
  /** Subject requesting access */
  subject: Subject;
  /** Resource being accessed */
  resource: Resource;
  /** Action being performed */
  action: Action;
  /** Context of the request */
  context: AuthorizationContext;
}

/**
 * Result of authorization evaluation
 */
export interface AuthorizationDecisionResult {
  /** The authorization decision */
  decision: AuthorizationDecision;
  /** Array of policy IDs that contributed to the decision */
  matchedPolicies: string[];
  /** Human-readable explanation of the decision */
  reason: string;
  /** Detailed trace of evaluation */
  trace?: EvaluationTrace;
  /** Time taken to evaluate in milliseconds */
  evaluationTimeMs: number;
  /** Timestamp of the decision */
  evaluatedAt: Date;
}

/**
 * Individual step in the evaluation trace
 */
export interface EvaluationTraceStep {
  /** Policy ID evaluated */
  policyId: string;
  /** Policy name */
  policyName: string;
  /** Whether the policy matched the request */
  matched: boolean;
  /** Whether the policy resulted in allow or deny */
  effect?: "ALLOW" | "DENY";
  /** Conditions that were evaluated */
  conditions?: {
    name: string;
    operator: string;
    expected: unknown;
    actual: unknown;
    result: boolean;
  }[];
  /** Whether there was an error during evaluation */
  error?: string;
}

/**
 * Detailed trace of the policy evaluation
 */
export interface EvaluationTrace {
  /** All steps in the evaluation */
  steps: EvaluationTraceStep[];
  /** Final decision rationale */
  rationale: string;
  /** Whether short-circuit evaluation was used */
  shortCircuited: boolean;
  /** If short-circuited, which policy caused it */
  shortCircuitPolicy?: string;
}

/**
 * Policy evaluation options
 */
export interface EvaluationOptions {
  /** Whether to include detailed trace in results */
  includeTrace?: boolean;
  /** Whether to use short-circuit evaluation */
  shortCircuit?: boolean;
  /** Whether to log the decision */
  logDecision?: boolean;
  /** Cache key prefix for this evaluation */
  cacheKeyPrefix?: string;
}

/**
 * Batch authorization request
 */
export interface BatchAuthorizationRequest {
  /** The authorization request to evaluate */
  request: AuthorizationRequest;
  /** Additional policies to consider */
  additionalPolicyIds?: string[];
}

/**
 * Batch authorization result
 */
export interface BatchAuthorizationResult {
  /** Request index */
  index: number;
  /** Decision result */
  result: AuthorizationDecisionResult;
}

/**
 * Policy scope for filtering
 */
export interface PolicyScope {
  /** Filter by tenant ID */
  tenantId?: string;
  /** Filter by resource types */
  resourceTypes?: ResourceType[];
  /** Filter by actions */
  actions?: ActionType[];
  /** Filter by policy status */
  isActive?: boolean;
}

/**
 * Map of policy IDs to their contents
 */
export type PolicyMap = Record<
  string,
  {
    /** Policy content */
    content: Record<string, unknown>;
    /** Policy version */
    version: number;
  }
>;
