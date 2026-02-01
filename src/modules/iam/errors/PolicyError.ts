/**
 * Policy Errors
 *
 * Custom error classes for IAM module.
 */

/**
 * Policy Error Codes
 * Enumeration of all possible policy-related error codes
 */
export enum PolicyErrorCode {
  VALIDATION_ERROR = "VALIDATION_ERROR",
  EVALUATION_ERROR = "EVALUATION_ERROR",
  TENANT_ISOLATION_VIOLATION = "TENANT_ISOLATION_VIOLATION",
  POLICY_NOT_FOUND = "POLICY_NOT_FOUND",
  POLICY_DISABLED = "POLICY_DISABLED",
  POLICY_VERSION_NOT_FOUND = "POLICY_VERSION_NOT_FOUND",
  POLICY_VERSION_CONFLICT = "POLICY_VERSION_CONFLICT",
  CONDITION_NOT_SUPPORTED = "CONDITION_NOT_SUPPORTED",
  CONDITION_EVALUATION_FAILED = "CONDITION_EVALUATION_FAILED",
  SUBJECT_NOT_FOUND = "SUBJECT_NOT_FOUND",
  SUBJECT_TYPE_INVALID = "SUBJECT_TYPE_INVALID",
  POLICY_ATTACHMENT_EXISTS = "POLICY_ATTACHMENT_EXISTS",
  POLICY_ATTACHMENT_NOT_FOUND = "POLICY_ATTACHMENT_NOT_FOUND",
  TENANT_NOT_FOUND = "TENANT_NOT_FOUND",
  TENANT_STATUS_INVALID = "TENANT_STATUS_INVALID",
  TENANT_HIERARCHY_VIOLATION = "TENANT_HIERARCHY_VIOLATION",
  DECISION_AUDIT_NOT_FOUND = "DECISION_AUDIT_NOT_FOUND",
  CACHE_ERROR = "CACHE_ERROR",
  OPA_CONNECTION_ERROR = "OPA_CONNECTION_ERROR",
  OPA_EVALUATION_ERROR = "OPA_EVALUATION_ERROR",
  OPA_TIMEOUT = "OPA_TIMEOUT",
}

/**
 * Base Policy Error
 */
export class PolicyError extends Error {
  constructor(
    message: string,
    public code: string,
  ) {
    super(message);
    this.name = "PolicyError";
  }
}

/**
 * Validation Error
 */
export class ValidationError extends PolicyError {
  constructor(message: string) {
    super(message, PolicyErrorCode.VALIDATION_ERROR);
    this.name = "ValidationError";
  }
}

/**
 * Evaluation Error
 */
export class EvaluationError extends PolicyError {
  constructor(message: string) {
    super(message, PolicyErrorCode.EVALUATION_ERROR);
    this.name = "EvaluationError";
  }
}

/**
 * Tenant Isolation Error
 */
export class TenantIsolationError extends PolicyError {
  constructor(message: string) {
    super(message, PolicyErrorCode.TENANT_ISOLATION_VIOLATION);
    this.name = "TenantIsolationError";
  }
}

/**
 * Policy Not Found Error
 */
export class PolicyNotFoundError extends PolicyError {
  constructor(policyId: string) {
    super(`Policy not found: ${policyId}`, PolicyErrorCode.POLICY_NOT_FOUND);
    this.name = "PolicyNotFoundError";
  }
}

/**
 * Policy Disabled Error
 */
export class PolicyDisabledError extends PolicyError {
  constructor(policyId: string) {
    super(`Policy is disabled: ${policyId}`, PolicyErrorCode.POLICY_DISABLED);
    this.name = "PolicyDisabledError";
  }
}
