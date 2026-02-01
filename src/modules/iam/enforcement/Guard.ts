/**
 * Authorization Guard and Permission Checker
 *
 * Class-based authorization guard for method-level access control
 * and ad-hoc permission checking for ABAC policies.
 */

import { Request, Response, NextFunction, RequestHandler } from "express";
import {
  Subject,
  Resource,
  Action,
  AuthorizationContext,
  AuthorizationDecision,
  AuthorizationRequest,
  ABACPolicy,
  PrincipalType,
  RequestContext,
} from "../policy/models/types";
import { PolicyEngine } from "../engine/PolicyEngine";
import { DecisionLogger } from "../audit/DecisionLogger";
import { PolicyCache } from "../cache/PolicyCache";
import { logger } from "../../../shared/logger";

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate unique ID
 */
function generateId(): string {
  return `${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
}

// ============================================================================
// Guard Options
// ============================================================================

/**
 * Guard configuration options
 */
export interface GuardOptions {
  /** Action(s) to check - single action or array of actions (any must match) */
  action: string | string[];
  /** Resource(s) to check - single resource or array of resources */
  resource: string | string[];
  /** Param name for resource ID extraction (default: 'id') */
  resourceIdParam?: string;
  /** Param name for resource tenant ID extraction */
  resourceTenantParam?: string;
  /** Param name for owner ID comparison */
  ownerParam?: string;
  /** Custom handler for deny response */
  onDeny?: (request: Request, decision: AuthorizationDecision) => void;
  /** Custom handler for errors */
  onError?: (error: Error, request: Request) => void;
  /** Skip policy cache */
  skipCache?: boolean;
  /** Override resource type */
  resourceType?: string;
  /** Fall through on denial instead of returning 403 */
  softFailure?: boolean;
  /** Custom subject extractor */
  getSubject?: (request: Request) => Subject | null;
}

// ============================================================================
// Guard Options Interface
// ============================================================================

/**
 * Guard options with defaults
 */
interface ResolvedGuardOptions {
  actions: string[];
  resources: string[];
  resourceIdParam: string;
  resourceTenantParam: string | null;
  ownerParam: string | null;
  onDeny: ((request: Request, decision: AuthorizationDecision) => void) | null;
  onError: ((error: Error, request: Request) => void) | null;
  skipCache: boolean;
  resourceType: string | null;
  softFailure: boolean;
  getSubject: (request: Request) => Subject | null;
}

// ============================================================================
// Authorization Guard Class
// ============================================================================

/**
 * Authorization Guard - Class-based route protection decorator
 *
 * Responsibilities:
 * - Resource-level protection via decorator pattern
 * - Fine-grained control with custom options
 * - Ownership-based protection
 * - Error handling and custom responses
 */
export class AuthorizationGuard {
  private readonly defaultOptions: Partial<ResolvedGuardOptions> = {
    resourceIdParam: "id",
    resourceTenantParam: null,
    ownerParam: null,
    onDeny: null,
    onError: null,
    skipCache: false,
    resourceType: null,
    softFailure: false,
    getSubject: this.defaultGetSubject.bind(this),
  };

  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly decisionLogger?: DecisionLogger | null,
    private readonly policyCache?: PolicyCache | null,
  ) {}

  /**
   * Protect a route handler with authorization
   */
  protect(options: GuardOptions): (handler: RequestHandler) => RequestHandler {
    const resolvedOptions = this.resolveOptions(options);

    return (handler: RequestHandler): RequestHandler => {
      return async (
        req: Request,
        res: Response,
        next: NextFunction,
      ): Promise<void> => {
        try {
          // Get subject from request
          const subject = resolvedOptions.getSubject(req);
          if (!subject) {
            this.sendUnauthorized(res, "No subject found in request");
            return;
          }

          // Extract resource from request
          const resource = this.extractResource(req, resolvedOptions);

          // Check ownership if required
          if (resolvedOptions.ownerParam && resource.ownerId) {
            const ownerId = (req.params as any)[resolvedOptions.ownerParam];
            if (ownerId && ownerId !== subject.id) {
              this.sendForbidden(
                res,
                "You do not have permission to access this resource",
                "OWNERSHIP_REQUIRED",
              );
              return;
            }
          }

          // Check permissions
          const hasPermission = await this.checkAnyPermission(
            subject,
            resolvedOptions.actions,
            resource,
          );

          if (!hasPermission) {
            const decision = await this.evaluatePermission(
              subject,
              resolvedOptions.actions[0],
              resource,
            );

            if (resolvedOptions.onDeny) {
              resolvedOptions.onDeny(req, decision);
            } else if (!resolvedOptions.softFailure) {
              this.sendForbidden(res, decision.reason, decision.reasonCode);
            } else {
              next();
            }
            return;
          }

          // Permission granted - continue to handler
          (req as any).subject = subject;
          (req as any).resource = resource;
          handler(req, res, next);
        } catch (error) {
          const err = error as Error;
          logger.error("Guard error", {
            error: err,
            module: "authorization-guard",
          });

          if (resolvedOptions.onError) {
            resolvedOptions.onError(err, req);
          } else {
            res.status(500).json({
              error: "Internal Server Error",
              message: "Authorization check failed",
            });
          }
        }
      };
    };
  }

  /**
   * Protect with custom subject extractor
   */
  protectWithSubject(
    getSubject: (request: Request) => Subject | null,
  ): (
    options: Omit<GuardOptions, "getSubject">,
  ) => (handler: RequestHandler) => RequestHandler {
    return (options: Omit<GuardOptions, "getSubject">) => {
      return this.protect({ ...options, getSubject });
    };
  }

  /**
   * Protect based on resource ownership
   */
  protectOwnership(
    options: Omit<GuardOptions, "ownerParam"> & { ownerParam: string },
  ): (handler: RequestHandler) => RequestHandler {
    return this.protect(options);
  }

  /**
   * Check permission without middleware
   */
  async checkPermission(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<AuthorizationDecision> {
    const request = this.buildRequest(subject, action, resource, context);
    const policies = await this.resolvePolicies(subject.tenantId);
    return this.policyEngine.authorize(request, policies);
  }

  /**
   * Check multiple permissions
   */
  async checkPermissions(
    subject: Subject,
    requests: Array<{ action: string; resource: Resource }>,
    context?: Partial<AuthorizationContext>,
  ): Promise<Map<string, AuthorizationDecision>> {
    const results = new Map<string, AuthorizationDecision>();

    for (const req of requests) {
      const decision = await this.checkPermission(
        subject,
        req.action,
        req.resource,
        context,
      );
      results.set(
        `${req.action}:${req.resource.type}:${req.resource.id || ""}`,
        decision,
      );
    }

    return results;
  }

  /**
   * Resolve options with defaults
   */
  private resolveOptions(options: GuardOptions): ResolvedGuardOptions {
    const actions = Array.isArray(options.action)
      ? options.action
      : [options.action];
    const resources = Array.isArray(options.resource)
      ? options.resource
      : [options.resource];

    return {
      actions,
      resources,
      resourceIdParam:
        options.resourceIdParam || this.defaultOptions.resourceIdParam!,
      resourceTenantParam:
        options.resourceTenantParam ??
        this.defaultOptions.resourceTenantParam ??
        null,
      ownerParam: options.ownerParam ?? this.defaultOptions.ownerParam ?? null,
      onDeny: options.onDeny ?? this.defaultOptions.onDeny ?? null,
      onError: options.onError ?? this.defaultOptions.onError ?? null,
      skipCache: options.skipCache || this.defaultOptions.skipCache!,
      resourceType:
        options.resourceType ?? this.defaultOptions.resourceType ?? null,
      softFailure: options.softFailure || this.defaultOptions.softFailure!,
      getSubject: options.getSubject || this.defaultOptions.getSubject!,
    };
  }

  /**
   * Default subject extractor
   */
  private defaultGetSubject(request: Request): Subject | null {
    const user = (request as any).user;
    if (user) {
      return {
        id: user.id,
        tenantId: user.tenantId,
        type: (user.type as PrincipalType) || "User",
        roles: user.roles ?? [],
        groups: user.groups ?? [],
        attributes: user.attributes ?? {},
      };
    }

    // Check for service auth
    const serviceId = request.headers["x-service-id"] as string | undefined;
    const tenantId = request.headers["x-tenant-id"] as string | undefined;
    if (serviceId && tenantId) {
      return {
        id: serviceId,
        tenantId,
        type: "Service" as PrincipalType,
        roles: [],
        attributes: {},
      };
    }

    return null;
  }

  /**
   * Extract resource from request
   */
  private extractResource(
    request: Request,
    options: ResolvedGuardOptions,
  ): Resource {
    const resourceType =
      options.resourceType ||
      request.path.split("/").filter(Boolean)[0] ||
      "unknown";
    const resourceId = (request.params as any)[options.resourceIdParam];
    const tenantId = options.resourceTenantParam
      ? (request.params as any)[options.resourceTenantParam]
      : (request as any).user?.tenantId ||
        (request.headers["x-tenant-id"] as string) ||
        "unknown";

    return {
      type: resourceType,
      id: resourceId,
      tenantId,
      ownerId: (request as any).ownerId,
    };
  }

  /**
   * Check if subject has any of the specified permissions
   */
  private async checkAnyPermission(
    subject: Subject,
    actions: string[],
    resource: Resource,
  ): Promise<boolean> {
    for (const action of actions) {
      const decision = await this.checkPermission(subject, action, resource);
      if (decision.decision === "ALLOW") {
        return true;
      }
    }
    return false;
  }

  /**
   * Evaluate permission for logging/debugging
   */
  private async evaluatePermission(
    subject: Subject,
    action: string,
    resource: Resource,
  ): Promise<AuthorizationDecision> {
    return this.checkPermission(subject, action, resource);
  }

  /**
   * Build authorization request
   */
  private buildRequest(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): AuthorizationRequest {
    const now = new Date();
    const requestContext: RequestContext = {
      timestamp: now.toISOString(),
      ipAddress: "",
      userAgent: "",
      ...context?.context,
    };

    const authContext: AuthorizationContext = {
      subject,
      action: { id: action },
      resource,
      context: requestContext,
    };

    return {
      requestId: generateId(),
      subject,
      action: { id: action },
      resource,
      context: authContext,
    } as unknown as AuthorizationRequest;
  }

  /**
   * Resolve policies for tenant
   */
  private async resolvePolicies(tenantId: string): Promise<ABACPolicy[]> {
    if (this.policyCache && !this.defaultOptions.skipCache) {
      try {
        const cached = await this.policyCache.getPolicies(tenantId);
        if (cached && cached.length > 0) {
          return cached;
        }
      } catch (error) {
        logger.warn("Policy cache error in guard", {
          error,
          module: "authorization-guard",
        });
      }
    }

    return [];
  }

  /**
   * Send unauthorized response
   */
  private sendUnauthorized(response: Response, message: string): void {
    response.status(401).json({
      error: "Unauthorized",
      message,
    });
  }

  /**
   * Send forbidden response
   */
  private sendForbidden(
    response: Response,
    message: string,
    reasonCode: string,
  ): void {
    response.status(403).json({
      error: "Forbidden",
      message,
      reasonCode,
    });
  }
}

// ============================================================================
// Permission Checker Class
// ============================================================================

/**
 * Permission Checker - Ad-hoc permission verification
 *
 * Provides convenient methods for checking permissions
 * outside of middleware/guard context.
 */
export class PermissionChecker {
  constructor(
    private readonly policyEngine: PolicyEngine,
    private readonly policyCache?: PolicyCache | null,
  ) {}

  /**
   * Check if subject can perform action on resource
   */
  async can(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<boolean> {
    const decision = await this.check(subject, action, resource, context);
    return decision.decision === "ALLOW";
  }

  /**
   * Check if subject can perform any of the actions
   */
  async canAny(
    subject: Subject,
    actions: string[],
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<boolean> {
    for (const action of actions) {
      if (await this.can(subject, action, resource, context)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Check if subject can perform all actions
   */
  async canAll(
    subject: Subject,
    actions: string[],
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<boolean> {
    for (const action of actions) {
      if (!(await this.can(subject, action, resource, context))) {
        return false;
      }
    }
    return true;
  }

  /**
   * Get allowed actions for subject on resource
   */
  async getAllowedActions(
    subject: Subject,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<string[]> {
    const allowedActions: string[] = [];
    const commonActions = [
      "READ",
      "WRITE",
      "DELETE",
      "UPDATE",
      "CREATE",
      "LIST",
      "EXPORT",
      "IMPORT",
      "ADMIN",
      "EXECUTE",
    ];

    for (const action of commonActions) {
      if (await this.can(subject, action, resource, context)) {
        allowedActions.push(action);
      }
    }

    return allowedActions;
  }

  /**
   * Get denied actions for subject on resource
   */
  async getDeniedActions(
    subject: Subject,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<string[]> {
    const deniedActions: string[] = [];
    const commonActions = [
      "READ",
      "WRITE",
      "DELETE",
      "UPDATE",
      "CREATE",
      "LIST",
      "EXPORT",
      "IMPORT",
      "ADMIN",
      "EXECUTE",
    ];

    for (const action of commonActions) {
      if (!(await this.can(subject, action, resource, context))) {
        deniedActions.push(action);
      }
    }

    return deniedActions;
  }

  /**
   * Get authorization decision
   */
  async getDecision(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<AuthorizationDecision> {
    return this.check(subject, action, resource, context);
  }

  /**
   * Internal check method
   */
  private async check(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): Promise<AuthorizationDecision> {
    const request = this.buildRequest(subject, action, resource, context);
    const policies = await this.resolvePolicies(subject.tenantId);
    return this.policyEngine.authorize(request, policies);
  }

  /**
   * Build authorization request
   */
  private buildRequest(
    subject: Subject,
    action: string,
    resource: Resource,
    context?: Partial<AuthorizationContext>,
  ): AuthorizationRequest {
    const now = new Date();
    const requestContext: RequestContext = {
      timestamp: now.toISOString(),
      ipAddress: "",
      userAgent: "",
      ...context?.context,
    };

    const authContext: AuthorizationContext = {
      subject,
      action: { id: action },
      resource,
      context: requestContext,
    };

    return {
      requestId: generateId(),
      subject,
      action: { id: action },
      resource,
      context: authContext,
    } as unknown as AuthorizationRequest;
  }

  /**
   * Resolve policies for tenant
   */
  private async resolvePolicies(tenantId: string): Promise<ABACPolicy[]> {
    if (this.policyCache) {
      try {
        const cached = await this.policyCache.getPolicies(tenantId);
        if (cached && cached.length > 0) {
          return cached;
        }
      } catch (error) {
        logger.warn("Policy cache error in permission checker", {
          error,
          module: "permission-checker",
        });
      }
    }

    return [];
  }
}

// ============================================================================
// Authorization Denied Error
// ============================================================================

/**
 * Authorization denied error
 */
export class AuthorizationDeniedError extends Error {
  constructor(
    message: string,
    public readonly reason: string,
    public readonly decision?: AuthorizationDecision,
  ) {
    super(message);
    this.name = "AuthorizationDeniedError";
  }
}

// ============================================================================
// Guard Factory
// ============================================================================

/**
 * Create a guard instance with common configuration
 */
export function createGuard(
  policyEngine: PolicyEngine,
  decisionLogger?: DecisionLogger,
  policyCache?: PolicyCache,
): AuthorizationGuard {
  return new AuthorizationGuard(policyEngine, decisionLogger, policyCache);
}

/**
 * Create a permission checker instance
 */
export function createPermissionChecker(
  policyEngine: PolicyEngine,
  policyCache?: PolicyCache,
): PermissionChecker {
  return new PermissionChecker(policyEngine, policyCache);
}

// ============================================================================
// Legacy Exports for Backward Compatibility
// ============================================================================

/**
 * Guard configuration (legacy)
 */
export interface GuardConfig {
  action: string;
  resourceType: string;
  resourceId?: string;
  silent?: boolean;
}

/**
 * Legacy Guard class for backward compatibility
 */
export class Guard {
  constructor(private policyEngine: PolicyEngine) {}

  /**
   * Check if subject can perform action on resource
   */
  async can(
    subject: Subject,
    action: string,
    resourceType: string,
    resourceId?: string,
  ): Promise<boolean> {
    const resource: Resource = {
      type: resourceType,
      id: resourceId,
      tenantId: subject.tenantId,
    };

    const decision = await this.checkPermission(subject, action, resource);
    return decision.decision === "ALLOW";
  }

  /**
   * Check if subject can perform action (throws on denial)
   */
  async check(
    subject: Subject,
    action: string,
    resourceType: string,
    resourceId?: string,
  ): Promise<void> {
    const resource: Resource = {
      type: resourceType,
      id: resourceId,
      tenantId: subject.tenantId,
    };

    const decision = await this.checkPermission(subject, action, resource);

    if (decision.decision !== "ALLOW") {
      throw new AuthorizationDeniedError(
        `Access denied: Cannot perform ${action} on ${resourceType}`,
        decision.reason,
        decision,
      );
    }
  }

  /**
   * Get authorization decision without throwing
   */
  async evaluate(
    subject: Subject,
    action: string,
    resourceType: string,
    resourceId?: string,
  ): Promise<AuthorizationDecision> {
    const resource: Resource = {
      type: resourceType,
      id: resourceId,
      tenantId: subject.tenantId,
    };

    return this.checkPermission(subject, action, resource);
  }

  /**
   * Create a configured guard check function
   */
  for(config: GuardConfig): (subject: Subject) => Promise<void> {
    return async (subject: Subject) => {
      const resource: Resource = {
        type: config.resourceType,
        id: config.resourceId,
        tenantId: subject.tenantId,
      };

      const decision = await this.checkPermission(
        subject,
        config.action,
        resource,
      );

      if (decision.decision !== "ALLOW") {
        if (config.silent) {
          return;
        }
        throw new AuthorizationDeniedError(
          `Access denied: Cannot perform ${config.action} on ${config.resourceType}`,
          decision.reason,
          decision,
        );
      }
    };
  }

  /**
   * Check permission with full context
   */
  private async checkPermission(
    subject: Subject,
    action: string,
    resource: Resource,
  ): Promise<AuthorizationDecision> {
    const requestContext: RequestContext = {
      timestamp: new Date().toISOString(),
    };

    const authContext: AuthorizationContext = {
      subject,
      action: { id: action },
      resource,
      context: requestContext,
    };

    const request: AuthorizationRequest = {
      requestId: generateId(),
      subject,
      action: { id: action },
      resource,
      context: authContext,
    } as unknown as AuthorizationRequest;

    return this.policyEngine.authorize(request, []);
  }
}
