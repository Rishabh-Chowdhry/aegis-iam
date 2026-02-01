/**
 * IAM Types Index
 * Exports all authorization and IAM-related types
 */

// Authorization types
export * from "./authorization";

// Re-export common types from other modules
export type {
  Subject,
  Resource,
  Action,
  AuthorizationRequest,
  AuthorizationDecision,
  AuthorizationDecisionResult,
  EvaluationContext,
} from "./authorization";
export type { SubjectType, ResourceType, ActionType } from "./authorization";
export type { EvaluationTrace, EvaluationTraceStep } from "./authorization";
export type { EvaluationOptions, PolicyScope } from "./authorization";
export type {
  BatchAuthorizationRequest,
  BatchAuthorizationResult,
} from "./authorization";
