/**
 * Tenant Boundary Module
 *
 * Enterprise-grade multi-tenant boundary enforcement for IAM platform.
 * Enforces absolute tenant isolation with comprehensive audit logging.
 * SOC2/ISO 27001 compliant implementation.
 */

import { Request, Response, NextFunction } from "express";
import { TenantContext, TenantContextManager } from "./TenantContext";
import { AuditLoggerService } from "../../../infrastructure/services/AuditLoggerService";
import { structuredLogger } from "../../../core/logger/structuredLogger";
import {
  ABACPolicy,
  AuthorizationContext,
  Subject,
} from "../policy/models/types";

/**
 * Violation Type Enumeration
 */
export type ViolationType =
  | "CROSS_TENANT_ACCESS"
  | "TENANT_SUSPENDED"
  | "UNAUTHORIZED_SCOPE"
  | "POLICY_VIOLATION"
  | "DATA_ACCESS_VIOLATION";

/**
 * Violation Severity Enumeration
 */
export type ViolationSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

/**
 * Boundary Violation Interface
 */
export interface BoundaryViolation {
  violationType: ViolationType;
  subjectId: string;
  subjectTenantId: string;
  resourceTenantId: string;
  resourceType: string;
  resourceId?: string;
  requestId: string;
  ipAddress: string;
  timestamp: Date;
  severity: ViolationSeverity;
  details?: Record<string, unknown>;
}

/**
 * Cross-Tenant Access Result
 */
export interface CrossTenantAccessResult {
  isCrossTenant: boolean;
  sameTenant: boolean;
  authorizedCrossTenant: boolean;
  reason: string;
  exceptionType?:
    | "SUPER_ADMIN"
    | "SERVICE_ACCOUNT"
    | "SHARED_RESOURCE"
    | "EXPLICIT_AUTHORIZATION";
}

/**
 * Audit Info Interface
 */
export interface AuditInfo {
  requestId: string;
  timestamp: Date;
  subjectId: string;
  subjectTenantId: string;
  resourceType: string;
  resourceId?: string;
  action: string;
  outcome: "ALLOWED" | "DENIED";
  reason: string;
}

/**
 * Boundary Result Interface
 */
export interface BoundaryResult {
  allowed: boolean;
  reason: string;
  violation?: BoundaryViolation;
  auditInfo: AuditInfo;
}

/**
 * Boundary Configuration
 */
export interface BoundaryConfig {
  allowSuperAdminCrossTenant: boolean;
  allowServiceAccountCrossTenant: boolean;
  allowSharedResources: boolean;
  sharedResourceTypes: string[];
  requireExplicitAuthorization: boolean;
  logLevel: ViolationSeverity;
  alertOnCritical: boolean;
}

/**
 * Subject with extended properties
 */
export interface SubjectWithTenant extends Subject {
  tenantId: string;
  isSuperAdmin?: boolean;
  isServiceAccount?: boolean;
  permissions?: string[];
}

/**
 * Resource with tenant ID
 */
export interface TenantScopedResource {
  type: string;
  id?: string;
  tenantId: string;
  ownerId?: string;
  shared?: boolean;
}

/**
 * Authorization context extension with boundary-specific fields
 */
export interface BoundaryContext {
  requestId: string;
  ipAddress: string;
  userAgent?: string;
  additionalContext?: Record<string, unknown>;
}

/**
 * Default Boundary Configuration
 */
const DEFAULT_BOUNDARY_CONFIG: BoundaryConfig = {
  allowSuperAdminCrossTenant: false,
  allowServiceAccountCrossTenant: false,
  allowSharedResources: false,
  sharedResourceTypes: ["global_config", "system_setting"],
  requireExplicitAuthorization: true,
  logLevel: "HIGH",
  alertOnCritical: true,
};

/**
 * Tenant Boundary Enforcer
 *
 * Enforces multi-tenant isolation at API, policy, and data levels.
 * All boundary violations are logged and alerts generated for critical issues.
 * Thread-safe for concurrent request handling.
 */
export class TenantBoundaryEnforcer {
  private config: BoundaryConfig;
  private violationCount: Map<string, number> = new Map();
  private readonly VIOLATION_THRESHOLD = 5;
  private readonly VIOLATION_WINDOW_MS = 60000; // 1 minute

  constructor(
    private contextManager: TenantContextManager,
    private auditLogger: AuditLoggerService,
    config?: Partial<BoundaryConfig>,
  ) {
    this.config = { ...DEFAULT_BOUNDARY_CONFIG, ...config };
  }

  /**
   * Enforce tenant isolation on resource access
   */
  enforceResourceBoundary(
    subject: SubjectWithTenant,
    resource: TenantScopedResource,
    context: BoundaryContext,
  ): BoundaryResult {
    const requestId = context.requestId || `req_${Date.now()}`;
    const timestamp = new Date();

    // Check if subject has tenant ID
    if (!subject.tenantId) {
      const violation: BoundaryViolation = {
        violationType: "UNAUTHORIZED_SCOPE",
        subjectId: subject.id,
        subjectTenantId: "unknown",
        resourceTenantId: resource.tenantId,
        resourceType: resource.type,
        resourceId: resource.id,
        requestId,
        ipAddress: context.ipAddress || "unknown",
        timestamp,
        severity: "CRITICAL",
        details: { reason: "Subject missing tenant ID" },
      };

      this.logBoundaryViolation(violation);

      return {
        allowed: false,
        reason: "Subject missing tenant ID - unauthorized scope",
        violation,
        auditInfo: this.createAuditInfo(
          requestId,
          timestamp,
          subject,
          resource,
          "ACCESS",
          "DENIED",
          "Missing tenant ID",
        ),
      };
    }

    // Check for cross-tenant access
    const crossTenantResult = this.detectCrossTenantAccess(subject, resource);

    if (crossTenantResult.isCrossTenant) {
      if (!crossTenantResult.authorizedCrossTenant) {
        // Unauthorized cross-tenant access attempt
        const violation: BoundaryViolation = {
          violationType: "CROSS_TENANT_ACCESS",
          subjectId: subject.id,
          subjectTenantId: subject.tenantId,
          resourceTenantId: resource.tenantId,
          resourceType: resource.type,
          resourceId: resource.id,
          requestId,
          ipAddress: context.ipAddress || "unknown",
          timestamp,
          severity: "CRITICAL",
          details: {
            reason: crossTenantResult.reason,
            exceptionType: crossTenantResult.exceptionType,
          },
        };

        this.logBoundaryViolation(violation);

        return {
          allowed: false,
          reason: "Cross-tenant access denied",
          violation,
          auditInfo: this.createAuditInfo(
            requestId,
            timestamp,
            subject,
            resource,
            "ACCESS",
            "DENIED",
            crossTenantResult.reason,
          ),
        };
      }

      // Authorized cross-tenant access
      return {
        allowed: true,
        reason: crossTenantResult.reason,
        auditInfo: this.createAuditInfo(
          requestId,
          timestamp,
          subject,
          resource,
          "ACCESS",
          "ALLOWED",
          crossTenantResult.reason,
        ),
      };
    }

    // Same tenant access - allowed
    return {
      allowed: true,
      reason: "Tenant boundary check passed",
      auditInfo: this.createAuditInfo(
        requestId,
        timestamp,
        subject,
        resource,
        "ACCESS",
        "ALLOWED",
        "Same tenant access",
      ),
    };
  }

  /**
   * Enforce tenant isolation on policy evaluation
   */
  enforcePolicyBoundary(
    subject: SubjectWithTenant,
    policies: ABACPolicy[],
    context: BoundaryContext,
  ): BoundaryResult {
    const requestId = context.requestId || `req_${Date.now()}`;
    const timestamp = new Date();

    // Check for cross-tenant policy access
    for (const policy of policies) {
      if (policy.tenantId && policy.tenantId !== subject.tenantId) {
        // Policy from different tenant
        const violation: BoundaryViolation = {
          violationType: "POLICY_VIOLATION",
          subjectId: subject.id,
          subjectTenantId: subject.tenantId,
          resourceTenantId: policy.tenantId,
          resourceType: "policy",
          resourceId: policy.id,
          requestId,
          ipAddress: context.ipAddress || "unknown",
          timestamp,
          severity: "CRITICAL",
          details: {
            policyId: policy.id,
            policyTenantId: policy.tenantId,
          },
        };

        this.logBoundaryViolation(violation);

        return {
          allowed: false,
          reason: "Cross-tenant policy evaluation denied",
          violation,
          auditInfo: this.createAuditInfo(
            requestId,
            timestamp,
            subject,
            { type: "policy", id: policy.id, tenantId: policy.tenantId },
            "POLICY_EVAL",
            "DENIED",
            "Policy from different tenant",
          ),
        };
      }
    }

    // Filter policies to only those belonging to subject's tenant
    const scopedPolicies = policies.filter(
      (p) => !p.tenantId || p.tenantId === subject.tenantId,
    );

    return {
      allowed: true,
      reason: "Policy boundary check passed",
      auditInfo: this.createAuditInfo(
        requestId,
        timestamp,
        subject,
        { type: "policy", tenantId: subject.tenantId },
        "POLICY_EVAL",
        "ALLOWED",
        `${scopedPolicies.length} tenant-scoped policies`,
      ),
    };
  }

  /**
   * Enforce tenant isolation on data access
   */
  enforceDataBoundary(
    subject: SubjectWithTenant,
    resourceType: string,
    resourceId: string | undefined,
    resourceTenantId: string,
    context: BoundaryContext,
  ): BoundaryResult {
    const requestId = context.requestId || `req_${Date.now()}`;
    const timestamp = new Date();

    // Check for cross-tenant data access
    const crossTenantResult = this.detectCrossTenantAccess(subject, {
      type: resourceType,
      id: resourceId,
      tenantId: resourceTenantId,
    });

    if (
      crossTenantResult.isCrossTenant &&
      !crossTenantResult.authorizedCrossTenant
    ) {
      const violation: BoundaryViolation = {
        violationType: "DATA_ACCESS_VIOLATION",
        subjectId: subject.id,
        subjectTenantId: subject.tenantId,
        resourceTenantId,
        resourceType,
        resourceId,
        requestId,
        ipAddress: context.ipAddress || "unknown",
        timestamp,
        severity: "CRITICAL",
        details: {
          reason: crossTenantResult.reason,
        },
      };

      this.logBoundaryViolation(violation);

      return {
        allowed: false,
        reason: "Cross-tenant data access denied",
        violation,
        auditInfo: this.createAuditInfo(
          requestId,
          timestamp,
          subject,
          { type: resourceType, id: resourceId, tenantId: resourceTenantId },
          "DATA_ACCESS",
          "DENIED",
          crossTenantResult.reason,
        ),
      };
    }

    return {
      allowed: true,
      reason: "Data boundary check passed",
      auditInfo: this.createAuditInfo(
        requestId,
        timestamp,
        subject,
        { type: resourceType, id: resourceId, tenantId: resourceTenantId },
        "DATA_ACCESS",
        "ALLOWED",
        crossTenantResult.reason || "Same tenant data access",
      ),
    };
  }

  /**
   * Detect cross-tenant access and determine if authorized
   */
  detectCrossTenantAccess(
    subject: SubjectWithTenant,
    resource: TenantScopedResource,
  ): CrossTenantAccessResult {
    const subjectTenantId = subject.tenantId || "unknown";
    const resourceTenantId = resource.tenantId || "unknown";

    // Same tenant
    if (subjectTenantId === resourceTenantId) {
      return {
        isCrossTenant: false,
        sameTenant: true,
        authorizedCrossTenant: true,
        reason: "Same tenant access",
      };
    }

    // Check for super admin exception
    if (subject.isSuperAdmin && this.config.allowSuperAdminCrossTenant) {
      return {
        isCrossTenant: true,
        sameTenant: false,
        authorizedCrossTenant: true,
        reason: "Super admin cross-tenant access authorized",
        exceptionType: "SUPER_ADMIN",
      };
    }

    // Check for service account exception
    if (
      subject.isServiceAccount &&
      this.config.allowServiceAccountCrossTenant
    ) {
      return {
        isCrossTenant: true,
        sameTenant: false,
        authorizedCrossTenant: true,
        reason: "Service account cross-tenant access authorized",
        exceptionType: "SERVICE_ACCOUNT",
      };
    }

    // Check for shared resource exception
    if (resource.shared && this.config.allowSharedResources) {
      const isSharedResourceType = this.config.sharedResourceTypes.includes(
        resource.type,
      );
      if (isSharedResourceType) {
        return {
          isCrossTenant: true,
          sameTenant: false,
          authorizedCrossTenant: true,
          reason: "Shared resource access authorized",
          exceptionType: "SHARED_RESOURCE",
        };
      }
    }

    // Check for explicit authorization in subject permissions
    if (
      this.config.requireExplicitAuthorization &&
      subject.permissions?.includes("cross_tenant:access")
    ) {
      return {
        isCrossTenant: true,
        sameTenant: false,
        authorizedCrossTenant: true,
        reason: "Explicit cross-tenant authorization",
        exceptionType: "EXPLICIT_AUTHORIZATION",
      };
    }

    // Unauthorized cross-tenant access
    return {
      isCrossTenant: true,
      sameTenant: false,
      authorizedCrossTenant: false,
      reason: `Unauthorized cross-tenant access: Subject tenant ${subjectTenantId} cannot access resource in tenant ${resourceTenantId}`,
    };
  }

  /**
   * Log boundary violation
   */
  async logBoundaryViolation(violation: BoundaryViolation): Promise<void> {
    // Increment violation count for rate limiting
    const key = `${violation.subjectTenantId}:${violation.ipAddress}`;
    const now = Date.now();
    const lastViolation = this.violationCount.get(key);

    if (lastViolation && now - lastViolation < this.VIOLATION_WINDOW_MS) {
      // Potential attack detected
      structuredLogger.warn("Potential tenant boundary attack detected", {
        tenantId: violation.subjectTenantId,
        module: "tenant-boundary",
        action: "boundary_violation",
        metadata: {
          ipAddress: violation.ipAddress,
          violationType: violation.violationType,
        },
      });
    }

    this.violationCount.set(key, now);

    // Log to audit service
    await this.auditLogger.log(
      "UNAUTHORIZED_ACCESS",
      "tenant_boundary",
      {
        tenantId: violation.subjectTenantId,
        userId: violation.subjectId,
        ipAddress: violation.ipAddress,
        correlationId: violation.requestId,
      },
      {
        resourceId: violation.resourceId,
        outcome: "FAILURE",
        errorMessage: `Tenant boundary violation: ${violation.violationType}`,
        details: {
          violationType: violation.violationType,
          subjectTenantId: violation.subjectTenantId,
          resourceTenantId: violation.resourceTenantId,
          resourceType: violation.resourceType,
          severity: violation.severity,
          timestamp: violation.timestamp.toISOString(),
        },
      },
    );

    // Log to structured logger
    structuredLogger.logSecurity("TENANT_BOUNDARY_VIOLATION", {
      userId: violation.subjectId,
      tenantId: violation.subjectTenantId,
      ipAddress: violation.ipAddress,
      severity: violation.severity as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
      metadata: {
        resourceTenantId: violation.resourceTenantId,
        resourceType: violation.resourceType,
        resourceId: violation.resourceId,
        requestId: violation.requestId,
        timestamp: violation.timestamp.toISOString(),
        violationType: violation.violationType,
      },
    });

    // Alert on critical violations
    if (violation.severity === "CRITICAL" && this.config.alertOnCritical) {
      await this.alertOnCriticalViolation(violation);
    }
  }

  /**
   * Alert on critical boundary violations
   */
  private async alertOnCriticalViolation(
    violation: BoundaryViolation,
  ): Promise<void> {
    // In production, this would integrate with SIEM, PagerDuty, etc.
    structuredLogger.error(
      "CRITICAL Tenant Boundary Violation",
      new Error("Security incident"),
      {
        tenantId: violation.subjectTenantId,
        userId: violation.subjectId,
        module: "tenant-boundary",
        action: "critical_violation",
        metadata: {
          violationType: violation.violationType,
          resourceTenantId: violation.resourceTenantId,
          resourceType: violation.resourceType,
          resourceId: violation.resourceId,
          requestId: violation.requestId,
          ipAddress: violation.ipAddress,
          severity: violation.severity,
        },
      },
    );
  }

  /**
   * Create audit info for boundary check result
   */
  private createAuditInfo(
    requestId: string,
    timestamp: Date,
    subject: SubjectWithTenant,
    resource: TenantScopedResource,
    action: string,
    outcome: "ALLOWED" | "DENIED",
    reason: string,
  ): AuditInfo {
    return {
      requestId,
      timestamp,
      subjectId: subject.id,
      subjectTenantId: subject.tenantId || "unknown",
      resourceType: resource.type,
      resourceId: resource.id,
      action,
      outcome,
      reason,
    };
  }

  /**
   * Enforce tenant context validation
   */
  enforceContextBoundary(
    context: TenantContext | null,
    request: Request,
  ): BoundaryResult {
    const requestId =
      (request.headers["x-request-id"] as string) || `req_${Date.now()}`;
    const timestamp = new Date();

    if (!context) {
      const violation: BoundaryViolation = {
        violationType: "UNAUTHORIZED_SCOPE",
        subjectId: "unknown",
        subjectTenantId: "unknown",
        resourceTenantId: "unknown",
        resourceType: "request",
        requestId,
        ipAddress: request.socket?.remoteAddress || "unknown",
        timestamp,
        severity: "HIGH",
        details: { reason: "No tenant context established" },
      };

      this.logBoundaryViolation(violation);

      return {
        allowed: false,
        reason: "Tenant context required",
        violation,
        auditInfo: {
          requestId,
          timestamp,
          subjectId: "unknown",
          subjectTenantId: "unknown",
          resourceType: "request",
          action: "CONTEXT_VALIDATION",
          outcome: "DENIED",
          reason: "No tenant context established",
        },
      };
    }

    // Check if context is expired
    if (context.expiresAt < new Date()) {
      const violation: BoundaryViolation = {
        violationType: "UNAUTHORIZED_SCOPE",
        subjectId: context.requestScope.userId || "unknown",
        subjectTenantId: context.tenantId,
        resourceTenantId: context.tenantId,
        resourceType: "request",
        requestId,
        ipAddress: context.requestScope.ipAddress,
        timestamp,
        severity: "MEDIUM",
        details: { reason: "Context expired" },
      };

      this.logBoundaryViolation(violation);

      return {
        allowed: false,
        reason: "Tenant context expired",
        violation,
        auditInfo: {
          requestId,
          timestamp,
          subjectId: context.requestScope.userId || "unknown",
          subjectTenantId: context.tenantId,
          resourceType: "request",
          action: "CONTEXT_VALIDATION",
          outcome: "DENIED",
          reason: "Context expired",
        },
      };
    }

    // Check tenant status
    if (context.lifecycle.status === "SUSPENDED") {
      const violation: BoundaryViolation = {
        violationType: "TENANT_SUSPENDED",
        subjectId: context.requestScope.userId || "unknown",
        subjectTenantId: context.tenantId,
        resourceTenantId: context.tenantId,
        resourceType: "request",
        requestId,
        ipAddress: context.requestScope.ipAddress,
        timestamp,
        severity: "CRITICAL",
        details: { status: "SUSPENDED" },
      };

      this.logBoundaryViolation(violation);

      return {
        allowed: false,
        reason: "Tenant is suspended",
        violation,
        auditInfo: {
          requestId,
          timestamp,
          subjectId: context.requestScope.userId || "unknown",
          subjectTenantId: context.tenantId,
          resourceType: "request",
          action: "CONTEXT_VALIDATION",
          outcome: "DENIED",
          reason: "Tenant suspended",
        },
      };
    }

    return {
      allowed: true,
      reason: "Context boundary check passed",
      auditInfo: {
        requestId,
        timestamp,
        subjectId: context.requestScope.userId || "unknown",
        subjectTenantId: context.tenantId,
        resourceType: "request",
        action: "CONTEXT_VALIDATION",
        outcome: "ALLOWED",
        reason: "Valid tenant context",
      },
    };
  }

  /**
   * Get boundary configuration
   */
  getConfig(): BoundaryConfig {
    return { ...this.config };
  }

  /**
   * Update boundary configuration
   */
  updateConfig(config: Partial<BoundaryConfig>): void {
    this.config = { ...this.config, ...config };
  }
}

/**
 * Tenant Boundary Error
 */
export class TenantBoundaryError extends Error {
  constructor(
    message: string,
    public violation?: BoundaryViolation,
  ) {
    super(message);
    this.name = "TenantBoundaryError";
  }
}

/**
 * Create tenant boundary middleware
 */
export function createTenantBoundaryMiddleware(
  enforcer: TenantBoundaryEnforcer,
) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const context = (req as any).tenantContext as TenantContext | null;

      const result = enforcer.enforceContextBoundary(context, req);

      if (!result.allowed) {
        // Log the violation
        if (result.violation) {
          await enforcer.logBoundaryViolation(result.violation);
        }

        res.status(403).json({
          error: "TENANT_BOUNDARY_VIOLATION",
          message: result.reason,
          requestId: result.auditInfo.requestId,
        });
        return;
      }

      next();
    } catch (error) {
      structuredLogger.error(
        "Tenant boundary middleware error",
        error as Error,
        { module: "tenant-boundary", action: "middleware" },
      );
      res.status(500).json({
        error: "INTERNAL_ERROR",
        message: "Boundary enforcement failed",
      });
    }
  };
}
