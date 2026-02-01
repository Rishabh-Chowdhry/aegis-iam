/**
 * Policy Engine
 *
 * Core orchestrator for ABAC policy evaluation.
 * Handles request validation, policy retrieval, tenant isolation,
 * and authorization decision making with deterministic evaluation order.
 *
 * Enterprise-grade implementation comparable to AWS IAM in rigor and determinism.
 */

import {
  ABACPolicy,
  PolicyStatement,
  Subject,
  Resource,
  Action,
  AuthorizationContext,
  AuthorizationRequest,
  AuthorizationDecision as ExtendedAuthorizationDecision,
  PolicyEffect,
  MatchedPolicy,
  ConditionResult,
  ReasonCode,
  ResourceSpec,
  PolicyStatus,
  ActionSpec,
  PolicyCondition,
  EvaluationMetrics,
  EvaluationTrace,
  EvaluationStep,
  PolicyEvaluationResult as ImportedPolicyEvaluationResult,
  PolicyEvaluationInput,
  IAMPolicy,
  IAMPolicyStatement,
} from "../policy/models/types";
import { AuthorizationDecision } from "../types/authorization";
import { ConditionEvaluator } from "../conditions/ConditionEvaluator";
import {
  WildcardMatcher,
  WildcardPattern,
  MatchResult,
} from "../conditions/WildcardMatcher";

/**
 * Policy Engine Configuration Options
 */
export interface PolicyEngineOptions {
  /** Enable audit logging for all evaluations */
  enableAuditLogging?: boolean;

  /** Maximum evaluation depth for nested conditions */
  maxEvaluationDepth?: number;

  /** Enable partial matches in evaluation trace */
  enablePartialMatches?: boolean;

  /** Default decision when no policies match (default: DENY) */
  defaultDecision?: "ALLOW" | "DENY";

  /** Enable evaluation tracing for debugging */
  enableTracing?: boolean;
}

/**
 * Internal Evaluation Context - Internal state during policy evaluation
 */
interface InternalEvaluationContext {
  /** The original authorization request */
  request: AuthorizationRequest;

  /** Policies being evaluated */
  policies: ABACPolicy[];

  /** Evaluation start time */
  startTime: Date;

  /** Unique evaluation identifier for tracing */
  evaluationId: string;

  /** Current evaluation depth */
  depth: number;

  /** Evaluation trace steps */
  traceSteps: EvaluationStep[];

  /** Policies that matched */
  matchedPolicies: MatchedPolicy[];

  /** Policies that were evaluated */
  evaluatedPolicyIds: string[];

  /** Whether an explicit DENY was found */
  explicitDenyFound: boolean;

  /** Whether tenant isolation is enforced */
  tenantIsolationEnabled: boolean;

  /** Target tenant ID for isolation */
  targetTenantId?: string;
}

/**
 * Statement Match Result - Result of evaluating a single statement
 */
interface StatementMatchResult {
  matched: boolean;
  effect: PolicyEffect;
  statementId: string;
  matchedConditions: ConditionResult[];
  reason: string;
  matchedActions: string[];
  matchedResources: string[];
}

/**
 * Action Match Result
 */
interface ActionMatchResult {
  matches: boolean;
  matchedPatterns: string[];
}

/**
 * Resource Match Result
 */
interface ResourceMatchResult {
  matches: boolean;
  matchedPatterns: string[];
}

/**
 * Policy Evaluation Error - Thrown for unrecoverable evaluation errors
 */
export class PolicyEvaluationError extends Error {
  constructor(
    message: string,
    public readonly evaluationId: string,
    public readonly policyId?: string,
    public readonly statementId?: string,
    public readonly recoverable: boolean = false,
  ) {
    super(message);
    this.name = "PolicyEvaluationError";
  }
}

/**
 * Validation Error - Thrown for request validation errors
 */
export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

/**
 * PolicyEngine - Core ABAC Policy Evaluation Engine
 *
 * Implements deterministic, fail-closed policy evaluation with:
 * - AWS IAM-style evaluation logic
 * - Multi-tenant isolation
 * - Comprehensive audit trail
 * - Explicit DENY short-circuit
 */
export class PolicyEngine {
  private readonly options: Required<PolicyEngineOptions>;
  private readonly wildcardMatcher: WildcardMatcher;
  private evaluationTrace: EvaluationTrace | null = null;

  constructor(
    private readonly conditionEvaluator: ConditionEvaluator,
    private readonly wildcardPattern: WildcardPattern,
    options?: PolicyEngineOptions,
  ) {
    this.options = {
      enableAuditLogging: options?.enableAuditLogging ?? true,
      maxEvaluationDepth: options?.maxEvaluationDepth ?? 10,
      enablePartialMatches: options?.enablePartialMatches ?? true,
      defaultDecision: options?.defaultDecision ?? "DENY",
      enableTracing: options?.enableTracing ?? false,
    };
    this.wildcardMatcher = new WildcardMatcher();
  }

  // =========================================================================
  // EVALUATE METHOD (as specified in requirements)
  // =========================================================================

  /**
   * Evaluate authorization using the PolicyEvaluationInput interface.
   * Implements AWS IAM-style evaluation with:
   * - Default DENY
   * - Explicit DENY short-circuits and wins over ALLOW
   * - Deterministic evaluation order
   * - Tenant isolation
   *
   * @param input - Policy evaluation input containing subject, action, resource, context, and policies
   * @returns AuthorizationDecision with decision, matched policies, and reason
   */
  evaluate(input: PolicyEvaluationInput): AuthorizationDecision {
    const startTime = Date.now();
    const matchedPolicyIds: string[] = [];
    let explicitDenyFound = false;

    // Step 1: Default DENY - will return DENY if no policies match
    let decision: "ALLOW" | "DENY" = "DENY";
    let reason = "Default DENY - no matching policy found";

    // Filter policies by tenant (tenant isolation)
    const tenantPolicies = input.policies.filter(
      (policy) => policy.tenantId === input.subject.tenantId,
    );

    // Sort policies deterministically by SID for consistent evaluation
    const sortedPolicies = this.sortIAMPoliciesBySid(tenantPolicies);

    // Step 2: Evaluate each policy in deterministic order
    for (const policy of sortedPolicies) {
      // Step 3: For each statement, check action, resource, and conditions
      for (const statement of policy.statements) {
        // Check if action matches (with wildcards)
        const actionMatches = this.matchesIAMAction(
          input.action.id,
          statement.actions,
        );
        if (!actionMatches) {
          continue;
        }

        // Check if resource matches (with wildcards)
        const resourceMatches = this.matchesIAMResource(
          input.resource,
          statement.resources,
        );
        if (!resourceMatches) {
          continue;
        }

        // Evaluate conditions if present
        let conditionsMet = true;
        if (statement.conditions) {
          conditionsMet = this.evaluateIAMConditions(
            statement.conditions,
            input,
            input.subject,
            input.resource,
          );
        }

        if (conditionsMet) {
          // Statement matches - record the policy
          matchedPolicyIds.push(
            `${policy.tenantId}:${policy.version}:${statement.sid}`,
          );

          // Step 4: Explicit DENY short-circuits and wins over ALLOW
          if (statement.effect === "DENY") {
            explicitDenyFound = true;
            decision = "DENY";
            reason = `Explicit DENY by policy statement: ${statement.sid}`;
            // Short-circuit: return immediately on explicit DENY
            return {
              decision,
              matchedPolicies: matchedPolicyIds,
              reason,
            };
          }

          // Track ALLOW (but don't return yet - may find explicit DENY later)
          if (statement.effect === "ALLOW") {
            decision = "ALLOW";
            reason = `ALLOW by policy statement: ${statement.sid}`;
          }
        }
      }
    }

    // Step 5: Return decision with matched policies
    return {
      decision,
      matchedPolicies: matchedPolicyIds,
      reason,
    };
  }

  /**
   * Sort IAM policies by SID for deterministic evaluation order
   */
  private sortIAMPoliciesBySid(policies: IAMPolicy[]): IAMPolicy[] {
    return [...policies].sort((a, b) => {
      // Sort by tenantId first, then by statement SIDs
      if (a.tenantId !== b.tenantId) {
        return a.tenantId.localeCompare(b.tenantId);
      }
      // Within same tenant, compare first statement SID
      const aSid = a.statements[0]?.sid || "";
      const bSid = b.statements[0]?.sid || "";
      return aSid.localeCompare(bSid);
    });
  }

  /**
   * Check if action matches statement actions (with wildcard support)
   */
  private matchesIAMAction(
    actionId: string,
    actionPatterns: string[],
  ): boolean {
    return actionPatterns.some(
      (pattern) =>
        this.wildcardMatcher.matches(actionId, pattern, {
          caseInsensitive: true,
        }).matches,
    );
  }

  /**
   * Check if resource matches statement resources (with wildcard support)
   */
  private matchesIAMResource(
    resource: PolicyEvaluationInput["resource"],
    resourcePatterns: string[],
  ): boolean {
    // Check against type pattern (e.g., "invoice:*")
    const resourceIdentifier = `${resource.type}:${resource.id}`;
    return resourcePatterns.some(
      (pattern) =>
        this.wildcardMatcher.matches(resourceIdentifier, pattern, {
          caseInsensitive: false,
        }).matches,
    );
  }

  /**
   * Evaluate IAM policy conditions
   */
  private evaluateIAMConditions(
    conditions: Record<string, Record<string, any>>,
    input: PolicyEvaluationInput,
    subject: PolicyEvaluationInput["subject"],
    resource: PolicyEvaluationInput["resource"],
  ): boolean {
    for (const [operator, conditionValues] of Object.entries(conditions)) {
      for (const [key, expectedValue] of Object.entries(conditionValues)) {
        // Resolve the actual value from context
        const actualValue = this.resolveIAMConditionValue(
          key,
          input,
          subject,
          resource,
        );

        // Evaluate based on operator
        const result = this.applyIAMConditionOperator(
          operator,
          actualValue,
          expectedValue,
        );

        if (!result) {
          return false;
        }
      }
    }
    return true;
  }

  /**
   * Resolve condition key to actual value
   */
  private resolveIAMConditionValue(
    key: string,
    input: PolicyEvaluationInput,
    subject: PolicyEvaluationInput["subject"],
    resource: PolicyEvaluationInput["resource"],
  ): any {
    // Handle different condition key prefixes
    if (key.startsWith("subject.")) {
      const attrKey = key.substring(8);
      return subject.attributes[attrKey];
    }
    if (key.startsWith("resource.")) {
      const attrKey = key.substring(9);
      return resource.attributes[attrKey];
    }
    if (key.startsWith("context.")) {
      const attrKey = key.substring(8);
      return (input.context as any)[attrKey];
    }
    return undefined;
  }

  /**
   * Apply IAM condition operator
   */
  private applyIAMConditionOperator(
    operator: string,
    actualValue: any,
    expectedValue: any,
  ): boolean {
    switch (operator) {
      case "StringEquals":
        return String(actualValue) === String(expectedValue);
      case "StringNotEquals":
        return String(actualValue) !== String(expectedValue);
      case "Bool":
        return Boolean(actualValue) === Boolean(expectedValue);
      case "NumberGreaterThan":
        return Number(actualValue) > Number(expectedValue);
      case "NumberLessThan":
        return Number(actualValue) < Number(expectedValue);
      default:
        // For unknown operators, fail closed
        return false;
    }
  }

  // =========================================================================
  // Public Authorization Methods
  // =========================================================================

  /**
   * Evaluate authorization request against policies
   *
   * @param request - The authorization request to evaluate
   * @param policies - Policies to evaluate against
   * @returns AuthorizationDecision with result and audit information
   */
  authorize(
    request: AuthorizationRequest,
    policies: ABACPolicy[],
  ): ExtendedAuthorizationDecision {
    const evaluationId = this.generateEvaluationId();
    const startTime = new Date();

    try {
      // Validate request
      this.validateRequest(request);

      // Build evaluation context
      const context = this.buildEvaluationContext(
        request,
        policies,
        evaluationId,
        startTime,
      );

      // Pre-flight checks
      const preflightResult = this.preflightChecks(context);
      if (preflightResult) {
        return preflightResult;
      }

      // Evaluate policies
      const decision = this.evaluatePoliciesDeterministic(context);

      // Build and return result
      return this.buildDecision(decision, context, startTime);
    } catch (error) {
      return this.handleEvaluationError(
        error,
        request,
        startTime,
        evaluationId,
      );
    }
  }

  /**
   * Evaluate authorization request with explicit tenant isolation
   *
   * @param request - The authorization request to evaluate
   * @param policies - Policies to evaluate against
   * @param tenantId - Tenant ID to isolate evaluation to
   * @returns AuthorizationDecision with result and audit information
   */
  authorizeWithTenantIsolation(
    request: AuthorizationRequest,
    policies: ABACPolicy[],
    tenantId: string,
  ): ExtendedAuthorizationDecision {
    const evaluationId = this.generateEvaluationId();
    const startTime = new Date();

    try {
      // Validate request
      this.validateRequest(request);

      // Validate tenant isolation
      this.validateTenantIsolation(request, tenantId);

      // Build evaluation context with tenant isolation
      const context = this.buildEvaluationContext(
        request,
        policies,
        evaluationId,
        startTime,
      );
      context.tenantIsolationEnabled = true;
      context.targetTenantId = tenantId;

      // Filter policies by tenant
      const tenantPolicies = this.filterPoliciesByTenant(policies, tenantId);
      context.policies = tenantPolicies;

      // Pre-flight checks
      const preflightResult = this.preflightChecks(context);
      if (preflightResult) {
        return preflightResult;
      }

      // Evaluate policies with tenant isolation
      const decision = this.evaluatePoliciesDeterministic(context);

      // Build and return result
      return this.buildDecision(decision, context, startTime);
    } catch (error) {
      return this.handleEvaluationError(
        error,
        request,
        startTime,
        evaluationId,
      );
    }
  }

  // =========================================================================
  // Policy Evaluation Methods
  // =========================================================================

  /**
   * Evaluate a single policy against a request
   *
   * @param policy - Policy to evaluate
   * @param request - Authorization request
   * @returns Array of evaluation results for each statement
   */
  evaluatePolicy(
    policy: ABACPolicy,
    request: AuthorizationRequest,
  ): ImportedPolicyEvaluationResult[] {
    const results: ImportedPolicyEvaluationResult[] = [];

    for (const statement of policy.statements) {
      const statementResult = this.evaluateStatement(statement, request);

      results.push({
        policyId: policy.id,
        statementId: statement.sid,
        matched: statementResult.matched,
        effect: statementResult.effect,
        conditionsMet:
          statementResult.matchedConditions.length === 0 ||
          statementResult.matchedConditions.every((c) => c.matched),
        matchedActions: statementResult.matchedActions,
        matchedResources: statementResult.matchedResources,
        reason: statementResult.reason,
      });
    }

    return results;
  }

  /**
   * Evaluate a single policy statement
   *
   * @param statement - Policy statement to evaluate
   * @param request - Authorization request
   * @returns Statement match result
   */
  evaluateStatement(
    statement: PolicyStatement,
    request: AuthorizationRequest,
  ): StatementMatchResult {
    // Check if statement is active
    if (!statement || statement.effect === undefined) {
      return {
        matched: false,
        effect: "DENY",
        statementId: statement?.sid || "unknown",
        matchedConditions: [],
        reason: "Invalid statement",
        matchedActions: [],
        matchedResources: [],
      };
    }

    // Check action matches
    const actionMatch = this.matchesActions(
      request.action.id,
      statement.actions.includes,
    );

    if (!actionMatch.matches) {
      return {
        matched: false,
        effect: "DENY",
        statementId: statement.sid,
        matchedConditions: [],
        reason: `Action '${request.action.id}' does not match statement actions`,
        matchedActions: [],
        matchedResources: [],
      };
    }

    // Check resource matches
    const resourceMatch = this.matchesResources(
      request.resource,
      statement.resources,
    );

    if (!resourceMatch.matches) {
      return {
        matched: false,
        effect: "DENY",
        statementId: statement.sid,
        matchedConditions: [],
        reason: `Resource '${request.resource.type}' does not match statement resources`,
        matchedActions: actionMatch.matchedPatterns,
        matchedResources: [],
      };
    }

    // Evaluate conditions if present
    if (statement.conditions) {
      try {
        const conditionResult = this.conditionEvaluator.evaluate(
          statement.conditions,
          request.subject,
          request.resource,
          {
            subject: request.subject,
            action: request.action,
            resource: request.resource,
            context: request.context,
          },
        );

        if (!conditionResult.isMet) {
          return {
            matched: false,
            effect: "DENY",
            statementId: statement.sid,
            matchedConditions: this.convertFailedConditions(
              conditionResult.failedConditions,
            ),
            reason: "Conditions not met",
            matchedActions: actionMatch.matchedPatterns,
            matchedResources: resourceMatch.matchedPatterns,
          };
        }

        return {
          matched: true,
          effect: statement.effect,
          statementId: statement.sid,
          matchedConditions: this.convertFailedConditions(
            conditionResult.failedConditions,
          ),
          reason: `Statement ${statement.sid} matched with conditions`,
          matchedActions: actionMatch.matchedPatterns,
          matchedResources: resourceMatch.matchedPatterns,
        };
      } catch (error) {
        // Fail-closed on condition evaluation error
        return {
          matched: false,
          effect: "DENY",
          statementId: statement.sid,
          matchedConditions: [],
          reason: `Condition evaluation error: ${
            error instanceof Error ? error.message : "Unknown error"
          }`,
          matchedActions: actionMatch.matchedPatterns,
          matchedResources: resourceMatch.matchedPatterns,
        };
      }
    }

    // No conditions - statement matches
    return {
      matched: true,
      effect: statement.effect,
      statementId: statement.sid,
      matchedConditions: [],
      reason: `Statement ${statement.sid} matched (no conditions)`,
      matchedActions: actionMatch.matchedPatterns,
      matchedResources: resourceMatch.matchedPatterns,
    };
  }

  /**
   * Check if an action matches statement actions
   *
   * @param action - Action to check
   * @param statementActions - Actions patterns from statement
   * @returns Match result with matched patterns
   */
  matchesActions(
    action: string,
    statementActions: string[],
  ): ActionMatchResult {
    const matchedPatterns: string[] = [];

    for (const pattern of statementActions) {
      const matchResult = this.wildcardMatcher.matches(action, pattern);
      if (matchResult.matches) {
        matchedPatterns.push(pattern);
      }
    }

    return {
      matches: matchedPatterns.length > 0,
      matchedPatterns,
    };
  }

  /**
   * Check if a resource matches statement resources
   *
   * @param resource - Resource to check
   * @param statementResources - Resource specification from statement
   * @returns Match result with matched patterns
   */
  matchesResources(
    resource: Resource,
    statementResources: ResourceSpec,
  ): ResourceMatchResult {
    const matchedPatterns: string[] = [];

    // Check type matches
    const typeMatches = statementResources.types.some((typePattern) => {
      const typeMatchResult = this.wildcardMatcher.matches(
        resource.type,
        typePattern,
      );
      if (typeMatchResult.matches) {
        matchedPatterns.push(`type:${typePattern}`);
        return true;
      }
      return false;
    });

    if (!typeMatches) {
      return {
        matches: false,
        matchedPatterns: [],
      };
    }

    // Check ID matches if specified
    if (statementResources.ids && resource.id) {
      const idMatches = statementResources.ids.some((idPattern) => {
        const idMatchResult = this.wildcardMatcher.matches(
          resource.id!,
          idPattern,
        );
        if (idMatchResult.matches) {
          matchedPatterns.push(`id:${idPattern}`);
          return true;
        }
        return false;
      });

      if (!idMatches) {
        return {
          matches: false,
          matchedPatterns: [],
        };
      }
    }

    return {
      matches: true,
      matchedPatterns,
    };
  }

  /**
   * Filter policies by tenant
   *
   * @param policies - Policies to filter
   * @param tenantId - Tenant ID to filter by
   * @returns Filtered policies for the tenant
   */
  filterPoliciesByTenant(
    policies: ABACPolicy[],
    tenantId: string,
  ): ABACPolicy[] {
    return policies.filter((policy: ABACPolicy) => {
      // Include policies that belong to the tenant
      if (policy.tenantId === tenantId) {
        return true;
      }

      // Include system policies that are marked for cross-tenant access
      // System policies typically have special handling
      return false;
    });
  }

  /**
   * Get the current evaluation trace for debugging
   *
   * @returns Evaluation trace or null if tracing is disabled
   */
  getEvaluationTrace(): EvaluationTrace | null {
    return this.evaluationTrace;
  }

  // =========================================================================
  // Private Methods
  // =========================================================================

  /**
   * Build internal evaluation context
   */
  private buildEvaluationContext(
    request: AuthorizationRequest,
    policies: ABACPolicy[],
    evaluationId: string,
    startTime: Date,
  ): InternalEvaluationContext {
    return {
      request,
      policies,
      startTime,
      evaluationId,
      depth: 0,
      traceSteps: [],
      matchedPolicies: [],
      evaluatedPolicyIds: [],
      explicitDenyFound: false,
      tenantIsolationEnabled: false,
      targetTenantId: undefined,
    };
  }

  /**
   * Pre-flight validation checks
   */
  private preflightChecks(
    context: InternalEvaluationContext,
  ): ExtendedAuthorizationDecision | null {
    const { evaluationId, startTime } = context;

    // Check for empty policies
    if (context.policies.length === 0) {
      return this.buildDefaultDecision(
        this.options.defaultDecision,
        context,
        startTime,
        "NO_APPLICABLE_POLICY",
        "No policies available for evaluation",
      );
    }

    // Check policy count limit
    if (context.policies.length > 1000) {
      throw new PolicyEvaluationError(
        "Too many policies to evaluate",
        evaluationId,
        undefined,
        undefined,
        false,
      );
    }

    return null;
  }

  /**
   * Validate authorization request
   */
  private validateRequest(request: AuthorizationRequest): void {
    if (!request) {
      throw new ValidationError("Request is required");
    }

    if (!request.subject) {
      throw new ValidationError("Subject is required");
    }

    if (!request.subject.id) {
      throw new ValidationError("Subject ID is required");
    }

    if (!request.subject.tenantId) {
      throw new ValidationError("Subject tenant ID is required");
    }

    if (!request.action) {
      throw new ValidationError("Action is required");
    }

    if (!request.action.id) {
      throw new ValidationError("Action ID is required");
    }

    if (!request.resource) {
      throw new ValidationError("Resource is required");
    }

    if (!request.resource.type) {
      throw new ValidationError("Resource type is required");
    }

    if (!request.resource.tenantId) {
      throw new ValidationError("Resource tenant ID is required");
    }

    if (!request.context) {
      throw new ValidationError("Context is required");
    }

    if (!request.context.timestamp) {
      throw new ValidationError("Context timestamp is required");
    }
  }

  /**
   * Validate tenant isolation requirements
   */
  private validateTenantIsolation(
    request: AuthorizationRequest,
    tenantId: string,
  ): void {
    // Check that request tenant matches target tenant
    if (request.subject.tenantId !== tenantId) {
      throw new PolicyEvaluationError(
        "Subject tenant ID does not match isolation target",
        this.generateEvaluationId(),
        undefined,
        undefined,
        false,
      );
    }

    // Check resource tenant matches target tenant
    if (request.resource.tenantId !== tenantId) {
      throw new PolicyEvaluationError(
        "Resource tenant ID does not match isolation target",
        this.generateEvaluationId(),
        undefined,
        undefined,
        false,
      );
    }
  }

  /**
   * Evaluate policies with deterministic order (policyId ascending)
   */
  private evaluatePoliciesDeterministic(
    context: InternalEvaluationContext,
  ): "ALLOW" | "DENY" {
    const { request, policies } = context;

    // Sort policies deterministically by policyId ascending
    const sortedPolicies = this.sortPoliciesByIdAscending(policies);

    for (const policy of sortedPolicies) {
      // Skip inactive policies
      if (this.isPolicyInactive(policy)) {
        continue;
      }

      context.evaluatedPolicyIds.push(policy.id);

      // Evaluate each statement in the policy
      for (const statement of policy.statements) {
        // Check depth limit
        if (context.depth >= this.options.maxEvaluationDepth) {
          break;
        }

        // Evaluate statement
        const statementResult = this.evaluateStatement(statement, request);

        // Add trace step
        if (this.options.enableTracing) {
          context.traceSteps.push({
            step: context.traceSteps.length + 1,
            policyId: policy.id,
            statementId: statement.sid,
            matched: statementResult.matched,
            effect: statementResult.effect,
          });
        }

        if (statementResult.matched) {
          // Check for explicit DENY - short-circuit evaluation
          if (statementResult.effect === "DENY") {
            context.explicitDenyFound = true;
            context.matchedPolicies.push({
              policyId: policy.id,
              policyName: policy.name,
              statementId: statement.sid,
              effect: "DENY",
              isExplicitDeny: true,
              matchedConditions: statementResult.matchedConditions,
              matchedReason: statementResult.reason,
            });
            // Explicit DENY short-circuits - return immediately
            return "DENY";
          }

          // Track matched ALLOW policy
          if (statementResult.effect === "ALLOW") {
            context.matchedPolicies.push({
              policyId: policy.id,
              policyName: policy.name,
              statementId: statement.sid,
              effect: "ALLOW",
              isExplicitDeny: false,
              matchedConditions: statementResult.matchedConditions,
              matchedReason: statementResult.reason,
            });
          }
        }
      }
    }

    // If any ALLOW matched and no explicit DENY, return ALLOW
    const hasAllowMatch = context.matchedPolicies.some(
      (p: MatchedPolicy) => p.effect === "ALLOW",
    );
    if (hasAllowMatch && !context.explicitDenyFound) {
      return "ALLOW";
    }

    // Default decision
    return this.options.defaultDecision;
  }

  /**
   * Sort policies by ID ascending for deterministic evaluation
   */
  private sortPoliciesByIdAscending(policies: ABACPolicy[]): ABACPolicy[] {
    return [...policies].sort((a, b) => {
      // First, filter by status - ACTIVE policies first
      const statusOrder: Record<PolicyStatus, number> = {
        ACTIVE: 0,
        DRAFT: 1,
        DEPRECATED: 2,
        DISABLED: 3,
      };

      const statusA = statusOrder[a.status ?? "ACTIVE"];
      const statusB = statusOrder[b.status ?? "ACTIVE"];

      if (statusA !== statusB) {
        return statusA - statusB;
      }

      // Then sort by policyId ascending for determinism
      return a.id.localeCompare(b.id);
    });
  }

  /**
   * Check if policy is inactive
   */
  private isPolicyInactive(policy: ABACPolicy): boolean {
    return policy.status === "DISABLED" || policy.status === "DEPRECATED";
  }

  /**
   * Build authorization decision
   */
  private buildDecision(
    decision: "ALLOW" | "DENY",
    context: InternalEvaluationContext,
    startTime: Date,
  ): ExtendedAuthorizationDecision {
    const evaluationTimeMs = Date.now() - context.startTime.getTime();

    // Build reason
    let reason: string;
    let reasonCode: ReasonCode;

    if (decision === "ALLOW") {
      const matchedPolicyIds = context.matchedPolicies
        .filter((p: MatchedPolicy) => p.effect === "ALLOW")
        .map((p: MatchedPolicy) => p.policyId);
      const policyNames = context.matchedPolicies
        .filter((p: MatchedPolicy) => p.effect === "ALLOW")
        .map((p: MatchedPolicy) => p.policyName);

      reason = `Explicit ALLOW by policy ${policyNames.join(", ")}`;
      reasonCode = "ALLOWED_BY_POLICY";
    } else if (context.explicitDenyFound) {
      const matchedPolicyIds = context.matchedPolicies
        .filter((p: MatchedPolicy) => p.effect === "DENY")
        .map((p: MatchedPolicy) => p.policyId);
      const policyNames = context.matchedPolicies
        .filter((p: MatchedPolicy) => p.effect === "DENY")
        .map((p: MatchedPolicy) => p.policyName);

      reason = `Explicit DENY by policy ${policyNames.join(", ")}`;
      reasonCode = "DENIED_BY_POLICY";
    } else {
      reason = `No matching policy, defaulting to ${this.options.defaultDecision}`;
      reasonCode = "DENIED_BY_DEFAULT";
    }

    // Build trace if enabled
    let trace: EvaluationTrace | undefined;
    if (this.options.enableTracing) {
      trace = {
        steps: context.traceSteps,
        evaluationOrder: context.evaluatedPolicyIds,
        extractedVariables: this.extractVariables(context.request),
      };
      this.evaluationTrace = trace;
    }

    return {
      decision,
      determined: true,
      matchedPolicies: context.matchedPolicies,
      evaluatedPolicies: context.evaluatedPolicyIds,
      reason,
      reasonCode,
      metrics: {
        evaluationTimeMs,
        policiesEvaluated: context.evaluatedPolicyIds.length,
        policiesMatched: context.matchedPolicies.length,
        conditionsEvaluated: context.matchedPolicies.reduce(
          (sum: number, p: MatchedPolicy) => sum + p.matchedConditions.length,
          0,
        ),
        conditionsMatched: context.matchedPolicies.reduce(
          (sum: number, p: MatchedPolicy) =>
            sum +
            p.matchedConditions.filter((c: ConditionResult) => c.matched)
              .length,
          0,
        ),
        cacheHit: false,
      },
      trace,
    };
  }

  /**
   * Build default decision
   */
  private buildDefaultDecision(
    defaultDecision: "ALLOW" | "DENY",
    context: InternalEvaluationContext,
    startTime: Date,
    reasonCode: ReasonCode,
    reason: string,
  ): ExtendedAuthorizationDecision {
    const evaluationTimeMs = Date.now() - startTime.getTime();

    return {
      decision: defaultDecision,
      determined: true,
      matchedPolicies: [],
      evaluatedPolicies: context.evaluatedPolicyIds,
      reason,
      reasonCode,
      metrics: {
        evaluationTimeMs,
        policiesEvaluated: 0,
        policiesMatched: 0,
        conditionsEvaluated: 0,
        conditionsMatched: 0,
        cacheHit: false,
      },
    };
  }

  /**
   * Handle evaluation errors - fail closed
   */
  private handleEvaluationError(
    error: unknown,
    request: AuthorizationRequest,
    startTime: Date,
    evaluationId: string,
  ): ExtendedAuthorizationDecision {
    const errorMessage =
      error instanceof Error ? error.message : "Unknown evaluation error";
    const evaluationTimeMs = Date.now() - startTime.getTime();

    // Log error details
    console.error(`Policy evaluation error [${evaluationId}]:`, {
      message: errorMessage,
      requestId: request.requestId,
      subjectId: request.subject?.id,
      action: request.action?.id,
      resourceType: request.resource?.type,
    });

    // Fail-closed: return DENY on any error
    return {
      decision: "DENY",
      determined: false,
      matchedPolicies: [],
      evaluatedPolicies: [],
      reason: `Evaluation error: ${errorMessage}`,
      reasonCode: "EVALUATION_ERROR",
      metrics: {
        evaluationTimeMs,
        policiesEvaluated: 0,
        policiesMatched: 0,
        conditionsEvaluated: 0,
        conditionsMatched: 0,
        cacheHit: false,
      },
    };
  }

  /**
   * Convert failed conditions from ConditionEvaluator to ConditionResult
   */
  private convertFailedConditions(
    failedConditions: Array<{
      operator: string;
      key: string;
      expected: unknown;
      actual: unknown;
    }>,
  ): ConditionResult[] {
    return failedConditions.map((fc) => ({
      operator: fc.operator,
      variablePath: fc.key,
      expectedValues: Array.isArray(fc.expected) ? fc.expected : [fc.expected],
      actualValue: fc.actual,
      matched: false,
    }));
  }

  /**
   * Extract variables from request for trace
   */
  private extractVariables(
    request: AuthorizationRequest,
  ): Record<string, unknown> {
    return {
      "subject.id": request.subject.id,
      "subject.tenantId": request.subject.tenantId,
      "subject.type": request.subject.type,
      "subject.roles": request.subject.roles,
      "action.id": request.action.id,
      "resource.type": request.resource.type,
      "resource.id": request.resource.id,
      "resource.tenantId": request.resource.tenantId,
      "context.timestamp": request.context.timestamp,
      "context.ipAddress": request.context.ipAddress,
      "context.mfaAuthenticated": request.context.mfaAuthenticated,
      "context.riskScore": request.context.riskScore,
      "context.environment": request.context.environment,
    };
  }

  /**
   * Generate unique evaluation ID
   */
  private generateEvaluationId(): string {
    return `eval-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
  }
}

// Re-export MatchResult for convenience
export type { MatchResult } from "../conditions/WildcardMatcher";
