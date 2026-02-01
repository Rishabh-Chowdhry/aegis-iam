/**
 * IAM Module - Enterprise ABAC Policy Engine
 *
 * This module provides a comprehensive Attribute-Based Access Control (ABAC)
 * policy engine with multi-tenant support, OPA integration, and enterprise-grade
 * security features.
 */

// Re-export types from submodules
export {
  ABACPolicy,
  PolicyStatement,
  PolicyCondition,
  PolicyEffect,
  AuthorizationDecision,
  EvaluationTrace,
  EvaluationStep,
  ConditionOperator,
  PrincipalType,
  PolicyMetadata,
} from "./policy/models/types";

export {
  PolicyEngine,
  PolicyEngineOptions,
  PolicyEvaluationError,
  ValidationError,
} from "./engine/PolicyEngine";

export {
  TenantContext,
  TenantContextManager,
  TenantStatus,
  TenantSettings,
  TenantLimits,
  TenantFeatures,
  TenantConfig,
  TenantLifecycle,
  ValidationResult,
} from "./tenancy/TenantContext";

export {
  ConditionEvaluator,
  ConditionEvaluationResult,
  FailedCondition,
} from "./conditions/ConditionEvaluator";

export {
  ConditionRegistry,
  getConditionRegistry,
  StringEquals,
  StringNotEquals,
  StringLike,
  StringNotLike,
  NumericEquals,
  NumericNotEquals,
  NumericGreaterThan,
  NumericGreaterThanEquals,
  NumericLessThan,
  NumericLessThanEquals,
  Bool,
  Null,
  DateEquals,
  DateGreaterThan,
  DateLessThan,
  IpAddress,
  NotIpAddress,
  ArnEquals,
  ArnLike,
  BinaryEquals,
  getOperator,
  hasOperator,
  getAllOperatorNames,
  validateOperatorValue,
  CONDITION_OPERATORS,
} from "./conditions/ConditionOperators";

export { Guard } from "./enforcement/Guard";

export { PolicyError } from "./errors/PolicyError";
