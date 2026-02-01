/**
 * Rego Mapper
 *
 * Maps IAM types to OPA input documents and transforms OPA decisions
 * back to IAM authorization decisions.
 *
 * @module RegoMapper
 */

import {
  AuthorizationRequest,
  RequestContext,
  Subject,
  Resource,
  Action,
  PrincipalType,
} from "../policy/models/types";
import {
  OPAInput,
  OpaInputDocument,
  OpaEvaluationResult,
  OpaDecision,
  PolicyEvaluationResult,
} from "./OPAEngine";

/**
 * Mapper configuration options
 */
export interface RegoMapperConfig {
  /** Default decision when OPA returns no decision */
  defaultDecision?: "ALLOW" | "DENY";

  /** Enable strict tenant isolation checks */
  strictTenantIsolation?: boolean;

  /** Include debug information in mappings */
  includeDebugInfo?: boolean;
}

/**
 * Default mapper configuration
 */
const DEFAULT_CONFIG: RegoMapperConfig = {
  defaultDecision: "DENY",
  strictTenantIsolation: true,
  includeDebugInfo: false,
};

/**
 * RegoMapper - Maps between IAM and OPA/Rego formats
 *
 * Handles bidirectional mapping between the IAM authorization
 * request/response format and the OPA input document format.
 *
 * @example
 * ```typescript
 * const mapper = new RegoMapper();
 * const opaInput = mapper.toOPAInput(request);
 * const decision = mapper.toIAMDecision(opaResult);
 * ```
 */
export class RegoMapper {
  /** Mapper configuration */
  private config: RegoMapperConfig;

  /**
   * Create a new RegoMapper instance
   */
  constructor(config: RegoMapperConfig = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  // ==========================================================================
  // IAM to OPA Mapping
  // ==========================================================================

  /**
   * Transform an IAM AuthorizationRequest to an OPA Input Document
   *
   * @param request - The IAM authorization request
   * @returns OPA input document
   */
  toOPAInput(request: AuthorizationRequest): OPAInput {
    const { subject, action, resource, context } = request;

    return {
      subject: this.mapSubject(subject),
      action: this.mapAction(action),
      resource: this.mapResource(resource),
      context: this.mapContext(context),
      data: {},
    };
  }

  /**
   * Transform to the simplified OpaInputDocument format
   *
   * @param request - The IAM authorization request
   * @returns Simplified OPA input document
   */
  toOpaInputDocument(request: AuthorizationRequest): OpaInputDocument {
    const { subject, action, resource, context } = request;

    return {
      subject: {
        id: subject.id,
        tenant_id: subject.tenantId,
        roles: subject.roles || [],
        attributes: subject.attributes || {},
      },
      action: {
        id: action.id,
      },
      resource: {
        id: resource.id || "",
        type: resource.type,
        tenant_id: resource.tenantId,
        owner_id: resource.ownerId,
        attributes: resource.attributes || {},
      },
      context: {
        time: context.timestamp,
        ip: context.ipAddress || "0.0.0.0",
        mfa: context.mfaAuthenticated || false,
        risk_score: context.riskScore || 0,
        environment: context.environment || "production",
      },
      tenant_id: subject.tenantId,
    };
  }

  /**
   * Map IAM Subject to OPA subject format
   */
  private mapSubject(subject: Subject): OPAInput["subject"] {
    return {
      id: subject.id,
      tenant_id: subject.tenantId,
      type: subject.type,
      roles: subject.roles || [],
      groups: subject.groups,
      attributes: subject.attributes || {},
    };
  }

  /**
   * Map IAM Action to OPA action format
   */
  private mapAction(action: Action): OPAInput["action"] {
    return {
      name: action.id,
      method: action.method,
      category: action.category,
      risk_level: action.riskLevel,
      displayName: action.displayName,
      description: action.description,
    };
  }

  /**
   * Map IAM Resource to OPA resource format
   */
  private mapResource(resource: Resource): OPAInput["resource"] {
    return {
      type: resource.type,
      id: resource.id,
      tenant_id: resource.tenantId,
      owner_id: resource.ownerId,
      parent_id: resource.parentId,
      attributes: resource.attributes || {},
    };
  }

  /**
   * Map IAM RequestContext to OPA context format
   */
  private mapContext(context: RequestContext): OPAInput["context"] {
    return {
      timestamp: context.timestamp,
      ip: context.ipAddress || "0.0.0.0",
      mfa: context.mfaAuthenticated || false,
      risk_score: context.riskScore || 0,
      environment: context.environment || "production",
      request_id: context.sessionId || "unknown",
      user_agent: context.userAgent,
      referer: context.referer,
      source: context.source,
      hour: context.hour,
      day_of_week: context.dayOfWeek,
      location: context.location,
    };
  }

  // ==========================================================================
  // OPA to IAM Mapping
  // ==========================================================================

  /**
   * Transform an OPA evaluation result to an IAM PolicyEvaluationResult
   *
   * @param opaResult - The OPA evaluation result
   * @returns IAM policy evaluation result
   */
  toIAMDecision(opaResult: OpaEvaluationResult): PolicyEvaluationResult {
    const decision = this.mapOpaDecision(opaResult.decision);

    return {
      decision,
      reason: opaResult.reason || this.getDefaultReason(decision),
      evaluator: "OPA",
      obligations: opaResult.obligations,
    };
  }

  /**
   * Transform OPA decision to IAM decision
   */
  private mapOpaDecision(opaDecision: OpaDecision): "ALLOW" | "DENY" {
    return opaDecision === "allow" ? "ALLOW" : "DENY";
  }

  /**
   * Get a default reason message for a decision
   */
  private getDefaultReason(decision: "ALLOW" | "DENY"): string {
    switch (decision) {
      case "ALLOW":
        return "Access granted by OPA policy";
      case "DENY":
        return "Access denied by OPA policy";
    }
  }

  /**
   * Transform detailed OPA result to IAM format with explanations
   */
  toIAMDecisionWithDetails(
    opaResult: OpaEvaluationResult,
    matchedRules?: string[],
  ): PolicyEvaluationResult & { matchedRules?: string[] } {
    const baseDecision = this.toIAMDecision(opaResult);

    return {
      ...baseDecision,
      matchedRules,
    };
  }

  // ==========================================================================
  // Decision Transformation
  // ==========================================================================

  /**
   * Transform OPA bundle decision to IAM format
   *
   * @param bundleResult - Result from OPA bundle evaluation
   * @returns IAM decision
   */
  transformBundleDecision(bundleResult: {
    result: unknown;
    metrics?: Record<string, number>;
  }): PolicyEvaluationResult {
    // Handle OPA bundle API response format
    const decision = bundleResult.result as { allow?: boolean };

    const opaResult: OpaEvaluationResult = {
      decision: decision.allow ? "allow" : "deny",
      reason: decision.allow ? "Bundle policy allowed" : "Bundle policy denied",
    };

    return this.toIAMDecision(opaResult);
  }

  /**
   * Transform multiple policy decisions using OPA's multi-decision support
   */
  transformMultiDecision(
    opaResults: Record<string, OpaEvaluationResult>,
  ): Record<string, PolicyEvaluationResult> {
    const decisions: Record<string, PolicyEvaluationResult> = {};

    for (const [decisionKey, opaResult] of Object.entries(opaResults)) {
      decisions[decisionKey] = this.toIAMDecision(opaResult);
    }

    return decisions;
  }

  // ==========================================================================
  // Validation and Utility
  // ==========================================================================

  /**
   * Validate that an OPA input document has required fields
   */
  validateOPAInput(input: OPAInput): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    // Validate subject
    if (!input.subject?.id) {
      errors.push("Subject ID is required");
    }
    if (!input.subject?.tenant_id) {
      errors.push("Subject tenant_id is required");
    }

    // Validate action
    if (!input.action?.name) {
      errors.push("Action name is required");
    }

    // Validate resource
    if (!input.resource?.type) {
      errors.push("Resource type is required");
    }
    if (!input.resource?.tenant_id) {
      errors.push("Resource tenant_id is required");
    }

    // Validate context
    if (!input.context?.timestamp) {
      errors.push("Context timestamp is required");
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }

  /**
   * Check tenant isolation compliance
   *
   * Ensures that the subject's tenant matches the resource's tenant
   * to prevent cross-tenant access.
   */
  checkTenantIsolation(request: AuthorizationRequest): {
    compliant: boolean;
    reason?: string;
  } {
    if (!this.config.strictTenantIsolation) {
      return { compliant: true };
    }

    const { subject, resource } = request;

    // System requests bypass tenant isolation
    const systemTypes: PrincipalType[] = ["Service", "Anonymous"];
    if (systemTypes.includes(subject.type) || resource.type === "system") {
      return { compliant: true };
    }

    // Check tenant isolation
    if (subject.tenantId !== resource.tenantId) {
      return {
        compliant: false,
        reason: `Tenant isolation violation: Subject tenant (${subject.tenantId}) does not match resource tenant (${resource.tenantId})`,
      };
    }

    return { compliant: true };
  }

  /**
   * Get debug information for the mapping
   */
  getDebugInfo(request: AuthorizationRequest): Record<string, unknown> {
    if (!this.config.includeDebugInfo) {
      return {};
    }

    return {
      originalRequest: {
        subjectId: request.subject.id,
        actionId: request.action.id,
        resourceType: request.resource.type,
        resourceId: request.resource.id,
      },
      tenantIsolation: this.checkTenantIsolation(request),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Update mapper configuration
   */
  configure(config: Partial<RegoMapperConfig>): void {
    this.config = { ...this.config, ...config };
  }

  /**
   * Get current configuration
   */
  getConfig(): RegoMapperConfig {
    return { ...this.config };
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Quick helper to create an OPA input from common parameters
 */
export function createOPAInput(
  subjectId: string,
  subjectTenantId: string,
  subjectType: PrincipalType,
  actionId: string,
  resourceType: string,
  resourceId: string,
  resourceTenantId: string,
  additionalContext?: Partial<RequestContext>,
): OPAInput {
  const mapper = new RegoMapper();
  const request: AuthorizationRequest = {
    requestId: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(),
    subject: {
      id: subjectId,
      tenantId: subjectTenantId,
      type: subjectType,
      attributes: {},
    },
    action: {
      id: actionId,
    },
    resource: {
      id: resourceId,
      type: resourceType,
      tenantId: resourceTenantId,
      attributes: {},
    },
    context: {
      timestamp: new Date().toISOString(),
      ipAddress: additionalContext?.ipAddress || "0.0.0.0",
      mfaAuthenticated: additionalContext?.mfaAuthenticated || false,
      riskScore: additionalContext?.riskScore || 0,
      environment: additionalContext?.environment || "production",
    },
  };

  return mapper.toOPAInput(request);
}
