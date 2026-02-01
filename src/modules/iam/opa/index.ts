/**
 * OPA Module Index
 *
 * Exports OPA Engine implementation and related types for
 * Open Policy Agent integration.
 */

// Engine implementations
export { OPAEngine } from "./OPAEngine";
export { NoOpOPAEngine } from "./OPAEngine";

// Engine interface
export { PolicyEngineExtension } from "./OPAEngine";

// Configuration
export type { OPAEngineConfig } from "./OPAEngine";

// Policy types
export type { RegoPolicy } from "./OPAEngine";
export type { InputSpec } from "./OPAEngine";
export type { DecisionSpec } from "./OPAEngine";
export type { RegoPolicyMetadata } from "./OPAEngine";

// Evaluation types
export type { OPAEvaluationResult } from "./OPAEngine";
export type { ExtensionDecision } from "./OPAEngine";
export type { Explanation } from "./OPAEngine";
export type { OPAEvaluationMetrics } from "./OPAEngine";

// Validation types
export type { ValidationResult } from "./OPAEngine";
export type { ValidationError } from "./OPAEngine";

// Decision format
export type { DecisionFormat } from "./OPAEngine";

// Input document
export type { OPAInput } from "./OPAEngine";

// ============================================================================
// Policy Evaluator Interface (Pluggable)
// ============================================================================

export type { PolicyEvaluator } from "./OPAEngine";
export type { OpaDecision } from "./OPAEngine";
export type { OpaEvaluationResult } from "./OPAEngine";
export type { OpaInputDocument } from "./OPAEngine";
export type { PolicyEvaluationResult } from "./OPAEngine";

// ============================================================================
// Rego Mapper
// ============================================================================

export { RegoMapper, createOPAInput } from "./RegoMapper";
export type { RegoMapperConfig } from "./RegoMapper";
