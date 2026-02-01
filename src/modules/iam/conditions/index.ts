/**
 * Conditions Module Index
 *
 * Exports all condition evaluation components for the ABAC policy engine.
 */

export { ConditionEvaluator } from "./ConditionEvaluator";
export type {
  ConditionEvaluationResult,
  FailedCondition,
  PathValue,
} from "./ConditionEvaluator";
export { ConditionRegistry, ConditionOperator } from "./ConditionOperators";
export { PathResolver } from "./PathResolver";
export {
  WildcardPattern,
  WildcardMatcher,
  matchPattern,
  matchAnyPattern,
  matchesAction,
  matchesResource,
  matchesHierarchicalAction,
  matchesHierarchicalResource,
  normalizeAction,
  normalizeResource,
  parseActionParts,
  expandPattern,
} from "./WildcardMatcher";
export type {
  WildcardMatchOptions,
  MatchResult,
  MultiMatchResult,
  MultiValueMatchResult,
} from "./WildcardMatcher";
