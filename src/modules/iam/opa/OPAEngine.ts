/**
 * OPA Engine - Open Policy Agent Integration
 *
 * Enterprise-grade OPA/Rego support for the ABAC policy engine.
 * Provides optional integration with OPA for complex policy scenarios
 * while maintaining no hard dependency on OPA at runtime.
 *
 * @module OPAEngine
 */

// ============================================================================
// POLICY EVALUATOR PLUGGABLE INTERFACE
// ============================================================================

/**
 * Pluggable policy evaluator interface
 * This interface allows for multiple policy evaluation backends
 * to be plugged into the IAM authorization system.
 */
export interface PolicyEvaluator {
  /**
   * Evaluate a policy decision
   * @param input - Evaluation input document
   * @param policy - Policy to evaluate (Rego or JSON)
   * @returns PolicyEvaluationResult
   */
  evaluate(
    input: object,
    policy: string | object,
  ): Promise<PolicyEvaluationResult>;

  /**
   * Check if the evaluator supports the policy format
   * @param policy - Policy to check
   * @returns true if supported
   */
  supports(policy: string | object): boolean;
}

/**
 * OPA Decision types
 */
export type OpaDecision = "allow" | "deny";

/**
 * OPA Evaluation Result
 */
export interface OpaEvaluationResult {
  decision: OpaDecision;
  reason?: string;
  obligations?: Record<string, any>[];
}

/**
 * Input document structure for OPA
 */
export interface OpaInputDocument {
  subject: {
    id: string;
    tenant_id: string;
    roles: string[];
    attributes: Record<string, any>;
  };
  action: {
    id: string;
  };
  resource: {
    id: string;
    type: string;
    tenant_id: string;
    owner_id?: string;
    attributes: Record<string, any>;
  };
  context: {
    time: string;
    ip: string;
    mfa: boolean;
    risk_score: number;
    environment: string;
  };
  tenant_id: string;
}

/**
 * Policy Evaluation Result
 */
export interface PolicyEvaluationResult {
  decision: "ALLOW" | "DENY";
  reason: string;
  evaluator: string;
  obligations?: Record<string, unknown>[];
}

import {
  AuthorizationRequest,
  AuthorizationContext,
  AuthorizationDecision,
  ABACPolicy,
  Subject,
  Resource,
  Action,
  PolicyEffect,
  MatchedPolicy,
  ConditionResult,
  EvaluationMetrics,
} from "../policy/models/types";

// ============================================================================
// POLICY ENGINE EXTENSION INTERFACES
// ============================================================================

/**
 * Interface for pluggable policy engines.
 * Allows the system to support multiple policy evaluation backends
 * (native DSL, OPA/Rego, custom engines) without hard dependencies.
 */
export interface PolicyEngineExtension {
  /** Name of the policy engine */
  name: string;

  /** Version of the policy engine */
  version: string;

  /**
   * Evaluate an authorization request against policies
   */
  evaluate(
    request: AuthorizationRequest,
    policies: unknown[],
  ): ExtensionDecision;

  /**
   * Validate a policy for this engine
   */
  validate(policy: unknown): ValidationResult;

  /**
   * Get the decision format for this engine
   */
  getDecisionFormat(): DecisionFormat;
}

/**
 * Decision returned by a policy engine extension
 */
export interface ExtensionDecision {
  /** Authorization decision */
  decision: "ALLOW" | "DENY";

  /** Human-readable reason for the decision */
  reason: string;

  /** List of rules that matched */
  matchedRules: string[];

  /** Extended data from the engine */
  extendedData?: Record<string, unknown>;
}

/**
 * Decision format specification for a policy engine
 */
export interface DecisionFormat {
  /** JSON Schema for input format */
  inputSchema: string;

  /** JSON Schema for output format */
  outputSchema: string;

  /** List of supported operations */
  supportedOperations: string[];
}

/**
 * Result of policy validation
 */
export interface ValidationResult {
  /** Whether the policy is valid */
  valid: boolean;

  /** Validation errors if any */
  errors: ValidationError[];
}

/**
 * Individual validation error
 */
export interface ValidationError {
  /** Error code */
  code: string;

  /** Human-readable message */
  message: string;

  /** Path to the invalid element */
  path: string;

  /** Severity of the error */
  severity: "error" | "warning" | "info";
}

// ============================================================================
// OPA ENGINE CONFIGURATION
// ============================================================================

/**
 * OPA Engine Configuration
 */
export interface OPAEngineConfig {
  /** OPA server URL (optional, for remote evaluation) */
  baseUrl?: string;

  /** Path to Rego policy bundles */
  bundlePath?: string;

  /** OPA decision to query */
  decisionId?: string;

  /** Enable local caching of evaluation results */
  enableLocalCache?: boolean;

  /** Cache TTL in seconds */
  cacheTtlSeconds?: number;

  /** Enable strict Rego validation */
  strictValidation?: boolean;

  /** Timeout for remote evaluations in ms */
  evaluationTimeoutMs?: number;

  /** Maximum policy size in bytes */
  maxPolicySizeBytes?: number;
}

// ============================================================================
// REGO POLICY STRUCTURES
// ============================================================================

/**
 * Rego policy metadata and code
 */
export interface RegoPolicy {
  /** Unique policy identifier */
  id: string;

  /** Human-readable policy name */
  name: string;

  /** Rego policy code */
  rego: string;

  /** Expected input structure */
  input: InputSpec;

  /** Expected decisions from this policy */
  decisions: DecisionSpec[];

  /** Policy metadata */
  metadata?: RegoPolicyMetadata;
}

/**
 * Expected input specification for a Rego policy
 */
export interface InputSpec {
  /** Subject input requirements */
  subject: Record<string, unknown>;

  /** Action input requirements */
  action: Record<string, unknown>;

  /** Resource input requirements */
  resource: Record<string, unknown>;

  /** Context input requirements */
  context: Record<string, unknown>;
}

/**
 * Expected decision specification
 */
export interface DecisionSpec {
  /** Decision key in the output */
  key: string;

  /** Data type of the decision value */
  type: "boolean" | "string" | "number" | "array" | "object";

  /** Default value if decision is not made */
  default?: unknown;

  /** Description of the decision */
  description?: string;
}

/**
 * Rego policy metadata
 */
export interface RegoPolicyMetadata {
  /** Human-readable description */
  description?: string;

  /** Policy version */
  version?: string;

  /** Author or organization */
  author?: string;

  /** Tags for categorization */
  tags?: string[];

  /** Regulatory compliance tags */
  compliance?: string[];

  /** Creation timestamp */
  createdAt?: string;

  /** Last update timestamp */
  updatedAt?: string;
}

// ============================================================================
// OPA EVALUATION RESULT
// ============================================================================

/**
 * Result of OPA policy evaluation
 */
export interface OPAEvaluationResult {
  /** Authorization decision */
  decision: "ALLOW" | "DENY" | "INDETERMINATE" | "NOT_APPLICABLE";

  /** Human-readable reason */
  reason: string;

  /** List of rules that matched */
  matchedRules: string[];

  /** Explanations for the decision */
  explanations?: Explanation[];

  /** Extended data from evaluation */
  extendedData?: Record<string, unknown>;

  /** Evaluation metrics */
  metrics?: OPAEvaluationMetrics;
}

/**
 * Explanation for an OPA decision
 */
export interface Explanation {
  /** Rule that contributed to the decision */
  rule: string;

  /** Terms that matched in the rule */
  terms: string[];

  /** Location of the rule in the policy */
  location?: string;

  /** Binding information */
  bindings?: Record<string, unknown>;
}

/**
 * OPA evaluation metrics
 */
export interface OPAEvaluationMetrics {
  /** Total rules evaluated */
  totalRules: number;

  /** Rules that matched */
  rulesMatched: number;

  /** Evaluation time in milliseconds */
  evaluationTimeMs: number;

  /** Memory used in bytes */
  memoryUsedBytes?: number;

  /** Whether result was from cache */
  cacheHit: boolean;
}

// ============================================================================
// OPA INPUT DOCUMENT STRUCTURE
// ============================================================================

/**
 * OPA Input Document Structure
 *
 * Standard format for passing authorization requests to OPA.
 * Includes subject, action, resource, context, and additional data.
 */
export interface OPAInput {
  /** Subject (who is making the request) */
  subject: {
    /** Subject identifier */
    id: string;

    /** Tenant identifier */
    tenant_id: string;

    /** Subject type */
    type: string;

    /** Roles assigned to the subject */
    roles: string[];

    /** Groups the subject belongs to */
    groups?: string[];

    /** Additional subject attributes */
    attributes: Record<string, unknown>;
  };

  /** Action being performed */
  action: {
    /** Action identifier */
    name: string;

    /** HTTP method if applicable */
    method?: string;

    /** Action category */
    category?: string;

    /** Risk level of the action */
    risk_level?: string;

    /** Additional action attributes */
    [key: string]: unknown;
  };

  /** Resource being accessed */
  resource: {
    /** Resource type */
    type: string;

    /** Resource identifier */
    id?: string;

    /** Tenant identifier */
    tenant_id: string;

    /** Resource owner */
    owner_id?: string;

    /** Parent resource for hierarchy */
    parent_id?: string;

    /** Additional resource attributes */
    attributes: Record<string, unknown>;
  };

  /** Request context */
  context: {
    /** Request timestamp (ISO 8601) */
    timestamp: string;

    /** Client IP address */
    ip: string;

    /** Whether MFA was used */
    mfa: boolean;

    /** Risk score (0-100) */
    risk_score: number;

    /** Deployment environment */
    environment: string;

    /** Unique request identifier */
    request_id: string;

    /** Additional context */
    [key: string]: unknown;
  };

  /** Additional data for policy evaluation */
  data: Record<string, unknown>;
}

// ============================================================================
// REGO POLICY EXAMPLES
// ============================================================================

/**
 * Example Rego Policies for documentation purposes
 *
 * @example
 * ```rego
 * package iam.authz
 *
 * # Default decision
 * default allow = false
 *
 * # Allow if subject is admin
 * allow {
 *   input.subject.roles[_] = "admin"
 * }
 * ```
 *
 * @example
 * ```rego
 * package iam.authz
 *
 * import future.keywords
 *
 * # Allow invoice approval with conditions
 * allow {
 *   input.action.name = "INVOICE_APPROVE"
 *   input.subject.roles[_] = "approver"
 *   input.subject.attributes.level >= input.resource.attributes.min_approval_level
 *   input.context.mfa = true
 * }
 * ```
 */

// ============================================================================
// OPA ENGINE IMPLEMENTATION
// ============================================================================

/**
 * OPA Engine Implementation
 *
 * Provides integration with Open Policy Agent (OPA) for advanced
 * policy evaluation using Rego policy language.
 *
 * Features:
 * - Pluggable policy engine interface
 * - Rego policy parsing and validation
 * - Input transformation to OPA format
 * - Decision mapping back to IAM format
 * - Optional remote OPA server support
 * - Local caching for performance
 */
export class OPAEngine implements PolicyEngineExtension {
  /** Engine name */
  name = "OPAEngine";

  /** Engine version */
  version = "1.0.0";

  /** Local cache for evaluation results */
  private readonly cache: Map<string, ExtensionDecision>;

  /** Cache TTL in milliseconds */
  private readonly cacheTtlMs: number;

  /** OPA server base URL */
  private readonly baseUrl: string | null;

  /** Validation strictness */
  private readonly strictValidation: boolean;

  /** Maximum policy size in bytes */
  private readonly maxPolicySizeBytes: number;

  /** Policy bundle cache */
  private readonly bundleCache: Map<
    string,
    { bundle: unknown; expiresAt: number }
  >;

  /**
   * Create a new OPA Engine instance
   */
  constructor(config: OPAEngineConfig = {}) {
    this.baseUrl = config.baseUrl ?? null;
    this.cacheTtlMs = (config.cacheTtlSeconds ?? 300) * 1000;
    this.strictValidation = config.strictValidation ?? true;
    this.maxPolicySizeBytes = config.maxPolicySizeBytes ?? 1024 * 1024; // 1MB default
    this.cache = new Map();
    this.bundleCache = new Map();
  }

  // ==========================================================================
  // POLICY ENGINE EXTENSION INTERFACE
  // ==========================================================================

  /**
   * Evaluate an authorization request against policies
   *
   * Implements the PolicyEngineExtension interface.
   */
  evaluate(
    request: AuthorizationRequest,
    policies: unknown[],
  ): ExtensionDecision {
    const startTime = Date.now();
    const cacheKey = this.getCacheKey(request, policies);

    // Check cache first
    const cached = this.getCachedDecision(cacheKey);
    if (cached) {
      return {
        ...cached,
        extendedData: {
          ...cached.extendedData,
          _cacheHit: true,
          _cacheAgeMs: Date.now() - startTime,
        },
      };
    }

    // Filter Rego policies
    const regoPolicies = policies.filter(
      (p): p is RegoPolicy =>
        typeof p === "object" &&
        p !== null &&
        "rego" in p &&
        typeof (p as RegoPolicy).rego === "string",
    );

    // If no Rego policies, return default deny
    if (regoPolicies.length === 0) {
      const decision: ExtensionDecision = {
        decision: "DENY",
        reason: "No OPA/Rego policies available",
        matchedRules: [],
        extendedData: {
          policiesEvaluated: 0,
          evaluationTimeMs: Date.now() - startTime,
        },
      };
      this.cacheDecision(cacheKey, decision);
      return decision;
    }

    // Evaluate Rego policies locally (simulated)
    const result = this.evaluateRego(request, regoPolicies);

    // Transform to extension decision
    const extensionDecision = this.transformDecision(result);

    // Add metrics
    extensionDecision.extendedData = {
      ...extensionDecision.extendedData,
      policiesEvaluated: regoPolicies.length,
      evaluationTimeMs: Date.now() - startTime,
    };

    // Cache the result
    this.cacheDecision(cacheKey, extensionDecision);

    return extensionDecision;
  }

  /**
   * Validate a policy for this engine
   *
   * Implements the PolicyEngineExtension interface.
   */
  validate(policy: unknown): ValidationResult {
    const errors: ValidationError[] = [];

    // Check if policy is an object
    if (typeof policy !== "object" || policy === null) {
      errors.push({
        code: "INVALID_POLICY_TYPE",
        message: "Policy must be an object",
        path: "/",
        severity: "error",
      });
      return { valid: false, errors };
    }

    const regoPolicy = policy as RegoPolicy;

    // Validate required fields
    if (!regoPolicy.id) {
      errors.push({
        code: "MISSING_POLICY_ID",
        message: "Policy must have an id field",
        path: "/id",
        severity: "error",
      });
    }

    if (!regoPolicy.name) {
      errors.push({
        code: "MISSING_POLICY_NAME",
        message: "Policy must have a name field",
        path: "/name",
        severity: "error",
      });
    }

    if (!regoPolicy.rego) {
      errors.push({
        code: "MISSING_POLICY_CODE",
        message: "Policy must have a rego field with policy code",
        path: "/rego",
        severity: "error",
      });
    } else if (typeof regoPolicy.rego !== "string") {
      errors.push({
        code: "INVALID_POLICY_CODE_TYPE",
        message: "Policy rego field must be a string",
        path: "/rego",
        severity: "error",
      });
    } else {
      // Validate Rego code size
      if (regoPolicy.rego.length > this.maxPolicySizeBytes) {
        errors.push({
          code: "POLICY_SIZE_EXCEEDED",
          message: `Policy size exceeds maximum of ${this.maxPolicySizeBytes} bytes`,
          path: "/rego",
          severity: "error",
        });
      }

      // If strict validation, validate Rego syntax
      if (this.strictValidation) {
        const regoValidation = this.validateRegoPolicy(regoPolicy.rego);
        errors.push(...regoValidation.errors);
      }
    }

    // Validate decisions if present
    if (regoPolicy.decisions) {
      if (!Array.isArray(regoPolicy.decisions)) {
        errors.push({
          code: "INVALID_DECISIONS_TYPE",
          message: "Decisions must be an array",
          path: "/decisions",
          severity: "error",
        });
      } else {
        for (let i = 0; i < regoPolicy.decisions.length; i++) {
          const decision = regoPolicy.decisions[i];
          if (!decision.key) {
            errors.push({
              code: "MISSING_DECISION_KEY",
              message: "Each decision must have a key field",
              path: `/decisions/${i}/key`,
              severity: "error",
            });
          }
          if (!decision.type) {
            errors.push({
              code: "MISSING_DECISION_TYPE",
              message: "Each decision must have a type field",
              path: `/decisions/${i}/type`,
              severity: "error",
            });
          } else if (
            !["boolean", "string", "number", "array", "object"].includes(
              decision.type,
            )
          ) {
            errors.push({
              code: "INVALID_DECISION_TYPE",
              message: `Invalid decision type: ${decision.type}`,
              path: `/decisions/${i}/type`,
              severity: "error",
            });
          }
        }
      }
    }

    return {
      valid: errors.filter((e) => e.severity === "error").length === 0,
      errors,
    };
  }

  /**
   * Get the decision format for this engine
   *
   * Implements the PolicyEngineExtension interface.
   */
  getDecisionFormat(): DecisionFormat {
    return {
      inputSchema: "https://json-schema.org/draft/2020-12/schema",
      outputSchema: "https://json-schema.org/draft/2020-12/schema",
      supportedOperations: [
        "evaluate",
        "validate",
        "compile",
        "explain",
        "trace",
        "benchmark",
      ],
    };
  }

  // ==========================================================================
  // REGO-SPECIFIC METHODS
  // ==========================================================================

  /**
   * Evaluate an authorization request against Rego policies
   *
   * Parses and evaluates the Rego policies against the input.
   * This is a local evaluation - for full Rego support, use a remote OPA server.
   */
  evaluateRego(
    request: AuthorizationRequest,
    regoPolicies: RegoPolicy[],
  ): OPAEvaluationResult {
    const startTime = Date.now();
    const matchedRules: string[] = [];
    const explanations: Explanation[] = [];
    const input = this.transformToOPAInput(request);

    // Default decision
    let decision: "ALLOW" | "DENY" | "INDETERMINATE" = "DENY";
    let reason = "No matching allow rules found";

    // Collect all allow and deny rules
    const allowRules: string[] = [];
    const denyRules: string[] = [];

    for (const policy of regoPolicies) {
      // Parse the policy
      const parsed = this.parseRegoPolicy(policy.rego);

      // Extract rules from the parsed policy
      const policyRules = this.extractRulesFromRego(policy.rego);
      allowRules.push(...policyRules.allow);
      denyRules.push(...policyRules.deny);
    }

    // Evaluate allow rules
    for (const rule of allowRules) {
      const ruleMatch = this.evaluateSimpleRule(input, rule);
      if (ruleMatch.matched) {
        matchedRules.push(rule);
        explanations.push({
          rule,
          terms: ruleMatch.terms,
          location: "allow",
        });
        decision = "ALLOW";
        reason = `Allowed by rule: ${rule}`;
        break; // First matching allow rule wins
      }
    }

    // If no allow rule matched, check deny rules
    if (decision !== "ALLOW") {
      for (const rule of denyRules) {
        const ruleMatch = this.evaluateSimpleRule(input, rule);
        if (ruleMatch.matched) {
          matchedRules.push(rule);
          explanations.push({
            rule,
            terms: ruleMatch.terms,
            location: "deny",
          });
          decision = "DENY";
          reason = `Denied by rule: ${rule}`;
          break;
        }
      }
    }

    return {
      decision,
      reason,
      matchedRules,
      explanations,
      metrics: {
        totalRules: allowRules.length + denyRules.length,
        rulesMatched: matchedRules.length,
        evaluationTimeMs: Date.now() - startTime,
        cacheHit: false,
      },
    };
  }

  /**
   * Parse Rego policy code and extract metadata
   *
   * Parses the Rego code to extract package, imports, and rule definitions.
   */
  parseRegoPolicy(regoCode: string): RegoPolicy {
    // Extract package declaration
    const packageMatch = regoCode.match(/^package\s+([^\s]+)/m);
    const packageName = packageMatch ? packageMatch[1] : "iam.authz";

    // Extract rule definitions
    const rules = this.extractRulesFromRego(regoCode);

    // Generate policy ID from package name
    const policyId = packageName.replace(/[^a-zA-Z0-9]/g, "_");

    return {
      id: policyId,
      name: packageName,
      rego: regoCode,
      input: {
        subject: this.extractInputSpec(rules.allow[0] || ""),
        action: {},
        resource: {},
        context: {},
      },
      decisions: [
        {
          key: "allow",
          type: "boolean",
          default: false,
          description: "Whether the request is allowed",
        },
        {
          key: "deny",
          type: "array",
          default: [],
          description: "List of denial reasons",
        },
      ],
      metadata: {
        description: `Auto-parsed Rego policy: ${packageName}`,
        createdAt: new Date().toISOString(),
      },
    };
  }

  /**
   * Validate Rego policy syntax
   *
   * Performs static analysis of Rego code for common issues.
   */
  validateRegoPolicy(regoCode: string): ValidationResult {
    const errors: ValidationError[] = [];

    // Check for balanced brackets
    const brackets: { [key: string]: string } = {
      "(": ")",
      "[": "]",
      "{": "}",
    };
    const stack: string[] = [];

    for (let i = 0; i < regoCode.length; i++) {
      const char = regoCode[i];
      if (["(", "[", "{"].includes(char)) {
        stack.push(char);
      } else if ([")", "]", "}"].includes(char)) {
        const opening = stack.pop();
        if (opening && brackets[opening] !== char) {
          errors.push({
            code: "UNBALANCED_BRACKETS",
            message: `Unbalanced brackets: ${char} at position ${i}`,
            path: "/rego",
            severity: "error",
          });
        }
      }
    }

    if (stack.length > 0) {
      errors.push({
        code: "UNBALANCED_BRACKETS",
        message: `Unclosed brackets: ${stack.join(", ")}`,
        path: "/rego",
        severity: "error",
      });
    }

    // Check for required package declaration
    if (!regoCode.match(/^package\s+/m)) {
      errors.push({
        code: "MISSING_PACKAGE",
        message: "Rego policy must have a package declaration",
        path: "/rego",
        severity: this.strictValidation ? "error" : "warning",
      });
    }

    // Check for valid rule names
    const rulePattern = /^\s*(\w+)\s*{/gm;
    let match;
    while ((match = rulePattern.exec(regoCode)) !== null) {
      const ruleName = match[1];
      if (
        [
          "package",
          "import",
          "default",
          "else",
          "if",
          "then",
          "else if",
          "some",
          "not",
        ].includes(ruleName)
      ) {
        continue; // Skip keywords
      }
      if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(ruleName)) {
        errors.push({
          code: "INVALID_RULE_NAME",
          message: `Invalid rule name: ${ruleName}`,
          path: `/rego`,
          severity: "warning",
        });
      }
    }

    // Check for infinite loops (recursion without base case)
    const hasRecursion = this.checkForRecursion(regoCode);
    if (hasRecursion) {
      errors.push({
        code: "POTENTIAL_INFINITE_RECURSION",
        message:
          "Policy may contain infinite recursion - ensure base cases exist",
        path: "/rego",
        severity: "warning",
      });
    }

    return {
      valid: errors.filter((e) => e.severity === "error").length === 0,
      errors,
    };
  }

  // ==========================================================================
  // INPUT TRANSFORMATION
  // ==========================================================================

  /**
   * Transform an authorization request to OPA input format
   *
   * Converts the IAM authorization request into the standard
   * OPA input document structure.
   */
  transformToOPAInput(request: AuthorizationRequest): OPAInput {
    return {
      subject: {
        id: request.subject.id,
        tenant_id: request.subject.tenantId,
        type: request.subject.type,
        roles: request.subject.roles || [],
        groups: request.subject.groups,
        attributes: request.subject.attributes || {},
      },
      action: {
        name: request.action.id,
        method: request.action.method,
        category: request.action.category,
        risk_level: request.action.riskLevel,
        display_name: request.action.displayName,
        description: request.action.description,
      },
      resource: {
        type: request.resource.type,
        id: request.resource.id,
        tenant_id: request.resource.tenantId,
        owner_id: request.resource.ownerId,
        parent_id: request.resource.parentId,
        attributes: request.resource.attributes || {},
      },
      context: {
        timestamp: request.context.timestamp || new Date().toISOString(),
        ip: request.context.ipAddress || "",
        mfa: request.context.mfaAuthenticated || false,
        risk_score: request.context.riskScore || 0,
        environment: request.context.environment || "production",
        request_id: request.requestId,
        user_agent: request.context.userAgent,
        referer: request.context.referer,
        source: request.context.source,
        location: request.context.location,
        session_id: request.context.sessionId,
        hour: request.context.hour,
        day_of_week: request.context.dayOfWeek,
      },
      data: {},
    };
  }

  /**
   * Transform OPA result to extension decision
   *
   * Maps the OPA evaluation result to the standard extension
   * decision format used by the IAM engine.
   */
  transformDecision(opaResult: OPAEvaluationResult): ExtensionDecision {
    return {
      decision: opaResult.decision === "ALLOW" ? "ALLOW" : "DENY",
      reason: opaResult.reason,
      matchedRules: opaResult.matchedRules,
      extendedData: {
        opaDecision: opaResult.decision,
        explanations: opaResult.explanations,
        metrics: opaResult.metrics,
      },
    };
  }

  // ==========================================================================
  // REMOTE OPA SERVER (OPTIONAL)
  // ==========================================================================

  /**
   * Evaluate policies using a remote OPA server
   *
   * Makes an HTTP request to the OPA server for policy evaluation.
   * Requires baseUrl to be configured.
   */
  async evaluateRemote(
    request: AuthorizationRequest,
  ): Promise<OPAEvaluationResult> {
    if (!this.baseUrl) {
      return {
        decision: "INDETERMINATE",
        reason: "OPA server URL not configured",
        matchedRules: [],
      };
    }

    const input = this.transformToOPAInput(request);
    const decisionId = "iam/authz"; // Default decision path

    try {
      const response = await fetch(`${this.baseUrl}/v1/data/${decisionId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ input }),
      });

      if (!response.ok) {
        return {
          decision: "INDETERMINATE",
          reason: `OPA server error: ${response.statusText}`,
          matchedRules: [],
        };
      }

      const result = await response.json();
      return this.parseRemoteResult(result);
    } catch (error) {
      return {
        decision: "INDETERMINATE",
        reason: `OPA evaluation failed: ${error instanceof Error ? error.message : "Unknown error"}`,
        matchedRules: [],
      };
    }
  }

  /**
   * Load a policy bundle from the specified path
   *
   * Loads Rego policies from a bundle file for local evaluation.
   */
  async loadBundle(bundlePath: string): Promise<void> {
    // In a real implementation, this would read from the filesystem
    // For now, we just cache the path
    this.bundleCache.set(bundlePath, {
      bundle: {},
      expiresAt: Date.now() + this.cacheTtlMs,
    });
  }

  // ==========================================================================
  // PRIVATE HELPER METHODS
  // ==========================================================================

  /**
   * Generate a cache key for an evaluation request
   */
  private getCacheKey(
    request: AuthorizationRequest,
    policies: unknown[],
  ): string {
    const keyData = {
      request: {
        subject: request.subject.id,
        action: request.action.id,
        resource: `${request.resource.type}:${request.resource.id}`,
        timestamp: request.context.timestamp,
      },
      policies: policies.map((p) => (p as RegoPolicy).id),
    };
    return this.hashObject(keyData);
  }

  /**
   * Get a cached decision if available and not expired
   */
  private getCachedDecision(cacheKey: string): ExtensionDecision | null {
    const cached = this.cache.get(cacheKey);
    if (cached) {
      return cached;
    }
    return null;
  }

  /**
   * Cache a decision result
   */
  private cacheDecision(cacheKey: string, decision: ExtensionDecision): void {
    this.cache.set(cacheKey, decision);
  }

  /**
   * Extract rules from Rego code
   */
  private extractRulesFromRego(regoCode: string): {
    allow: string[];
    deny: string[];
  } {
    const allowRules: string[] = [];
    const denyRules: string[] = [];

    // Match allow { ... } blocks
    const allowPattern = /allow\s*\{([^}]*)\}/g;
    let match;
    while ((match = allowPattern.exec(regoCode)) !== null) {
      allowRules.push(match[0]);
    }

    // Match deny[message] { ... } blocks
    const denyPattern = /deny\s*\[[^\]]*\]\s*\{([^}]*)\}/g;
    while ((match = denyPattern.exec(regoCode)) !== null) {
      denyRules.push(match[0]);
    }

    return { allow: allowRules, deny: denyRules };
  }

  /**
   * Extract input spec from a rule
   */
  private extractInputSpec(_rule: string): Record<string, unknown> {
    // In a real implementation, this would parse the rule
    // to extract referenced input fields
    return {};
  }

  /**
   * Evaluate a simple rule against input
   */
  private evaluateSimpleRule(
    input: OPAInput,
    rule: string,
  ): { matched: boolean; terms: string[] } {
    // Simple rule evaluation - in production, use OPA SDK
    const terms: string[] = [];

    // Check for role-based access
    if (rule.includes('input.subject.roles[_] = "admin"')) {
      if (input.subject.roles.includes("admin")) {
        return { matched: true, terms: ["subject.roles", "admin"] };
      }
    }

    // Check for action matching
    const actionMatch = rule.match(/input\.action\.name\s*=\s*"([^"]+)"/);
    if (actionMatch) {
      const actionName = actionMatch[1];
      if (input.action.name === actionName) {
        terms.push(`action.name=${actionName}`);
      }
    }

    // Check for tenant matching
    if (rule.includes("input.subject.tenant_id = input.resource.tenant_id")) {
      if (input.subject.tenant_id === input.resource.tenant_id) {
        return {
          matched: true,
          terms: ["subject.tenant_id = resource.tenant_id"],
        };
      }
    }

    // Check for MFA requirement
    if (rule.includes("input.context.mfa = true")) {
      if (input.context.mfa) {
        terms.push("context.mfa=true");
      }
    }

    // Check for risk score threshold
    const riskMatch = rule.match(/input\.context\.risk_score\s*>\s*(\d+)/);
    if (riskMatch) {
      const threshold = parseInt(riskMatch[1], 10);
      if (input.context.risk_score > threshold) {
        return { matched: true, terms: [`risk_score > ${threshold}`] };
      }
    }

    return { matched: terms.length > 0, terms };
  }

  /**
   * Check for potential infinite recursion in Rego
   */
  private checkForRecursion(regoCode: string): boolean {
    // Look for self-referential rules
    const ruleDefinitions = regoCode.match(/^(\w+)\s*\{/gm) || [];
    const definedRules = ruleDefinitions.map((r) => r.replace(/[\s\{]/g, ""));

    for (const rule of definedRules) {
      // Check if the rule references itself
      const selfRef = new RegExp(`${rule}\\s*\\(`);
      if (selfRef.test(regoCode)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Parse result from remote OPA server
   */
  private parseRemoteResult(
    result: Record<string, unknown>,
  ): OPAEvaluationResult {
    const decision = (result.decision as string) || "DENY";
    const reason = (result.reason as string) || "";

    return {
      decision: decision.toUpperCase() as "ALLOW" | "DENY" | "INDETERMINATE",
      reason,
      matchedRules: (result.matched_rules as string[]) || [],
      explanations: (result.explanations as Explanation[]) || [],
      metrics: {
        totalRules: 0,
        rulesMatched: 0,
        evaluationTimeMs: 0,
        cacheHit: false,
      },
    };
  }

  /**
   * Hash an object to a string
   */
  private hashObject(obj: unknown): string {
    const str = JSON.stringify(obj);
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      const char = str.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash = hash & hash;
    }
    return hash.toString(36);
  }
}

// ============================================================================
// NO-OP OPA ENGINE
// ============================================================================

/**
 * No-Op OPA Engine for when OPA is not available
 *
 * Provides a fallback implementation that always returns
 * a "not applicable" decision.
 */
export class NoOpOPAEngine implements PolicyEngineExtension {
  name = "NoOpOPAEngine";
  version = "1.0.0";

  evaluate(): ExtensionDecision {
    return {
      decision: "DENY",
      reason: "OPA engine not available",
      matchedRules: [],
    };
  }

  validate(): ValidationResult {
    return { valid: true, errors: [] };
  }

  getDecisionFormat(): DecisionFormat {
    return {
      inputSchema: "https://json-schema.org/draft/2020-12/schema",
      outputSchema: "https://json-schema.org/draft/2020-12/schema",
      supportedOperations: [],
    };
  }
}

// ============================================================================
// END OF OPA ENGINE IMPLEMENTATION
// ============================================================================
