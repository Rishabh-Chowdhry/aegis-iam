/**
 * IAM Enforcement Middleware
 *
 * Express middleware for enterprise-grade ABAC authorization.
 * Intercepts requests, extracts context, resolves policies, and enforces decisions.
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
import { TenantContextManager, TenantContext } from "../tenancy/TenantContext";
import { DecisionLogger } from "../audit/DecisionLogger";
import { PolicyCache } from "../cache/PolicyCache";
import { logger } from "../../../shared/logger";

// ============================================================================
// Express Request Extension
// ============================================================================

declare global {
  namespace Express {
    interface Request {
      iamContext?: IAMRequestContext;
      tenantContext?: TenantContext;
      authorizationDecision?: AuthorizationDecision;
    }
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Generate unique ID
 */
function generateId(): string {
  return `${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
}

/**
 * Check if subject has role
 */
export function hasRole(subject: Subject, role: string): boolean {
  return subject.roles?.includes(role) ?? false;
}

/**
 * Check if subject has any of the roles
 */
export function hasAnyRole(subject: Subject, roles: string[]): boolean {
  return roles.some((role) => hasRole(subject, role));
}

/**
 * Check if subject has all of the roles
 */
export function hasAllRoles(subject: Subject, roles: string[]): boolean {
  return roles.every((role) => hasRole(subject, role));
}

/**
 * Extract tenant ID from request
 */
export function extractTenantId(request: Request): string | null {
  return (
    (request.headers["x-tenant-id"] as string) ||
    (request as any).user?.tenantId ||
    (request as any).tenantId ||
    null
  );
}

// ============================================================================
// IAM Request Context
// ============================================================================

/**
 * IAM Request Context - Complete authorization context for a request
 */
export interface IAMRequestContext {
  requestId: string;
  subject: Subject;
  action: Action;
  resource: Resource;
  context: AuthorizationContext;
  evaluationId: string;
}

// ============================================================================
// Middleware Configuration
// ============================================================================

/**
 * IAM Middleware Configuration
 */
export interface IAMMiddlewareConfig {
  /** Policy engine instance */
  policyEngine: PolicyEngine;
  /** Tenant context manager */
  tenantContextManager: TenantContextManager;
  /** Decision logger instance */
  decisionLogger?: DecisionLogger | null;
  /** Policy cache instance */
  policyCache?: PolicyCache | null;
  /** Paths to skip authorization entirely */
  skipPaths?: string[];
  /** Public paths (authenticated but no policy check) */
  publicPaths?: string[];
  /** Enable audit logging */
  enableAudit?: boolean;
  /** Header name for decision response */
  decisionHeader?: string;
  /** Header name for evaluation ID */
  evaluationIdHeader?: string;
  /** Default policy TTL in seconds */
  policyTTL?: number;
}

// ============================================================================
// Context Extractors
// ============================================================================

/**
 * Custom context extractors for middleware customization
 */
export interface ContextExtractors {
  extractSubject: (request: Request) => Subject;
  extractAction: (request: Request) => Action;
  extractResource: (request: Request) => Resource;
  extractContext: (request: Request) => AuthorizationContext;
}

// ============================================================================
// IAM Middleware Class
// ============================================================================

/**
 * IAM Middleware - Enterprise-grade authorization middleware for Express
 *
 * Responsibilities:
 * - Request interception and context extraction
 * - Policy resolution and caching
 * - Authorization decision enforcement
 * - Response header enrichment
 */
export class IAMMiddleware {
  private readonly config: {
    policyEngine: PolicyEngine;
    tenantContextManager: TenantContextManager;
    decisionLogger: DecisionLogger | null;
    policyCache: PolicyCache | null;
    skipPaths: string[];
    publicPaths: string[];
    enableAudit: boolean;
    decisionHeader: string;
    evaluationIdHeader: string;
    policyTTL: number;
  };
  private readonly defaultTTL: number = 300; // 5 minutes

  constructor(config: IAMMiddlewareConfig) {
    this.config = {
      policyEngine: config.policyEngine,
      tenantContextManager: config.tenantContextManager,
      decisionLogger: config.decisionLogger ?? null,
      policyCache: config.policyCache ?? null,
      skipPaths: config.skipPaths ?? [],
      publicPaths: config.publicPaths ?? [],
      enableAudit: config.enableAudit ?? false,
      decisionHeader: config.decisionHeader ?? "X-Authorization-Decision",
      evaluationIdHeader: config.evaluationIdHeader ?? "X-Evaluation-ID",
      policyTTL: config.policyTTL ?? this.defaultTTL,
    };
  }

  /**
   * Create Express middleware for authorization
   */
  createMiddleware(): RequestHandler {
    return this.createCustomMiddleware({
      extractSubject: this.extractSubject.bind(this),
      extractAction: this.extractAction.bind(this),
      extractResource: this.extractResource.bind(this),
      extractContext: this.extractContext.bind(this),
    });
  }

  /**
   * Create middleware with custom action/resource extractors
   */
  createCustomMiddleware(extractors: ContextExtractors): RequestHandler {
    return async (
      req: Request,
      res: Response,
      next: NextFunction,
    ): Promise<void> => {
      const startTime = Date.now();
      let evaluationId = "";

      try {
        // Check if path should be skipped
        if (this.shouldSkipAuthorization(req)) {
          next();
          return;
        }

        evaluationId = generateId();
        req.headers[this.config.evaluationIdHeader.toLowerCase()] =
          evaluationId;

        // Extract subject from request
        const subject = extractors.extractSubject(req);
        if (!subject) {
          this.sendUnauthorized(
            res,
            "No subject found in request",
            evaluationId,
          );
          return;
        }

        // Extract tenant context
        const tenantContext = await this.extractTenantContext(
          req,
          subject.tenantId,
        );
        req.tenantContext = tenantContext;

        // Extract action from request
        const action = extractors.extractAction(req);

        // Extract resource from request
        const resource = extractors.extractResource(req);

        // Extract context from request
        const context = extractors.extractContext(req);

        // Build IAM request context
        const iamContext: IAMRequestContext = {
          requestId: this.getRequestId(req),
          subject,
          action,
          resource,
          context,
          evaluationId,
        };
        req.iamContext = iamContext;

        // Check if path is public (authenticated but no policy check)
        if (this.isPublicPath(req)) {
          res.setHeader(this.config.decisionHeader, "PUBLIC");
          res.setHeader(this.config.evaluationIdHeader, evaluationId);
          next();
          return;
        }

        // Resolve applicable policies
        const policies = await this.resolvePolicies(subject.tenantId, req);

        // Build authorization request
        const authRequest = this.buildAuthorizationRequest(
          subject,
          action,
          resource,
          context,
          iamContext.requestId,
        );

        // Evaluate authorization
        const decision = this.config.policyEngine.authorize(
          authRequest,
          policies,
        );
        req.authorizationDecision = decision;

        // Handle decision
        this.handleDecision(req, res, decision, evaluationId, startTime);

        // Log decision if enabled
        if (this.config.enableAudit && this.config.decisionLogger) {
          await this.logDecision(iamContext, decision);
        }
      } catch (error) {
        const err = error as Error;
        logger.error("IAM middleware error", {
          error: err,
          module: "iam-middleware",
          evaluationId,
        });

        // Fail-closed: return 500 for system errors
        res.status(500).json({
          error: "Internal Server Error",
          message: "Authorization evaluation failed",
          evaluationId,
        });
      }
    };
  }

  /**
   * Extract subject from request
   */
  extractSubject(request: Request): Subject {
    // Check if subject is already attached to request
    if ((request as any).user) {
      const user = (request as any).user;
      return {
        id: user.id,
        tenantId: user.tenantId,
        type: (user.type as PrincipalType) || "User",
        roles: user.roles ?? [],
        groups: user.groups ?? [],
        attributes: this.extractUserAttributes(user),
      };
    }

    // Check for service authentication
    const serviceId = request.headers["x-service-id"] as string | undefined;
    const apiKey = request.headers["x-api-key"] as string | undefined;
    const tenantId = request.headers["x-tenant-id"] as string | undefined;

    if (serviceId && apiKey && tenantId) {
      return {
        id: serviceId,
        tenantId,
        type: "Service" as PrincipalType,
        roles: [],
        attributes: {
          apiKey: true,
        },
      };
    }

    // Return anonymous subject
    return {
      id: "anonymous",
      tenantId: extractTenantId(request) || "unknown",
      type: "Anonymous" as PrincipalType,
      roles: [],
      attributes: {},
    };
  }

  /**
   * Extract user attributes from user object
   */
  private extractUserAttributes(user: any): Record<string, unknown> {
    return {
      email: user.email,
      department: user.department,
      title: user.title,
      managerId: user.managerId,
      mfaEnabled: user.mfaEnabled,
      status: user.status,
      officeLocation: user.officeLocation,
      ...user.attributes,
    };
  }

  /**
   * Extract action from request
   */
  extractAction(request: Request): Action {
    const method = request.method.toUpperCase() as Action["method"];
    const validMethod = method || "GET";
    const pathParts = request.path.split("/").filter(Boolean);
    const resourceType = pathParts[0] || "unknown";
    const actionId = `${validMethod}_${resourceType.toUpperCase()}`;

    return {
      id: actionId,
      method: validMethod,
      category: this.getActionCategory(validMethod),
      riskLevel: this.getActionRiskLevel(validMethod),
    };
  }

  /**
   * Get action category from HTTP method
   */
  private getActionCategory(method: string): Action["category"] {
    switch (method) {
      case "GET":
      case "HEAD":
        return "read";
      case "POST":
      case "PUT":
      case "PATCH":
        return "write";
      case "DELETE":
        return "delete";
      default:
        return "execute";
    }
  }

  /**
   * Get action risk level from HTTP method
   */
  private getActionRiskLevel(method: string): Action["riskLevel"] {
    switch (method) {
      case "DELETE":
        return "high";
      case "PUT":
      case "PATCH":
        return "medium";
      default:
        return "low";
    }
  }

  /**
   * Extract resource from request
   */
  extractResource(request: Request): Resource {
    const pathParts = request.path.split("/").filter(Boolean);
    const resourceType = pathParts[0] || "unknown";
    const resourceId = request.params.id || request.params.resourceId;

    const tenantId =
      (request as any).user?.tenantId ||
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
   * Extract context from request
   */
  extractContext(request: Request): AuthorizationContext {
    const now = new Date();
    const ipAddress = this.getClientIp(request) || "unknown";
    const userAgent = (request.headers["user-agent"] as string) || "unknown";

    const requestContext: RequestContext = {
      timestamp: now.toISOString(),
      ipAddress,
      userAgent,
      mfaAuthenticated: (request as any).mfaAuthenticated ?? false,
      riskScore: (request as any).riskScore ?? 0,
      environment: this.getEnvironment(),
      source: this.getRequestSource(request),
    };

    return {
      subject: { id: "", tenantId: "", type: "Anonymous" },
      action: { id: "" },
      resource: { type: "", tenantId: "" },
      context: requestContext,
    };
  }

  /**
   * Extract additional context from request
   */
  private extractAdditionalContext(request: Request): Partial<RequestContext> {
    const additionalContext: Partial<RequestContext> = {};

    if (request.headers["x-forwarded-for"]) {
      additionalContext.location = {
        country: request.headers["x-country"] as string | undefined,
        region: request.headers["x-region"] as string | undefined,
        city: request.headers["x-city"] as string | undefined,
      };
    }

    return additionalContext;
  }

  /**
   * Get client IP address
   */
  private getClientIp(request: Request): string {
    return (
      (request.headers["x-forwarded-for"] as string | undefined)
        ?.split(",")[0]
        ?.trim() ||
      (request.headers["x-real-ip"] as string | undefined) ||
      request.ip ||
      request.socket.remoteAddress ||
      "unknown"
    );
  }

  /**
   * Get current environment
   */
  private getEnvironment(): RequestContext["environment"] {
    const env = process.env.NODE_ENV;
    if (env === "production") return "production";
    if (env === "staging") return "staging";
    if (env === "development") return "development";
    return "test";
  }

  /**
   * Get request source
   */
  private getRequestSource(request: Request): RequestContext["source"] {
    const userAgent = request.headers["user-agent"] || "";

    if (userAgent.includes("Mozilla") || userAgent.includes("Chrome")) {
      return "web";
    }
    if (userAgent.includes("Mobile")) {
      return "mobile";
    }
    if (userAgent.includes("okhttp") || userAgent.includes("axios")) {
      return "api";
    }
    if (userAgent.includes("curl") || userAgent.includes("wget")) {
      return "cli";
    }

    return "api";
  }

  /**
   * Build complete authorization request
   */
  buildAuthorizationRequest(
    subject: Subject,
    action: Action,
    resource: Resource,
    context: AuthorizationContext,
    requestId?: string,
  ): AuthorizationRequest {
    // Ensure timestamp is set
    const contextWithTimestamp = {
      ...context,
      context: {
        ...context.context,
        timestamp: context.context.timestamp || new Date().toISOString(),
      },
    };

    return {
      requestId: requestId || generateId(),
      subject,
      action,
      resource,
      context: contextWithTimestamp,
    } as unknown as AuthorizationRequest;
  }

  /**
   * Resolve policies for request
   */
  async resolvePolicies(
    tenantId: string,
    request: Request,
  ): Promise<ABACPolicy[]> {
    if (this.config.policyCache) {
      try {
        const cachedPolicies =
          await this.config.policyCache.getPolicies(tenantId);
        if (cachedPolicies && cachedPolicies.length > 0) {
          return cachedPolicies;
        }
      } catch (error) {
        logger.warn("Policy cache error, continuing without cache", {
          error,
          module: "iam-middleware",
        });
      }
    }

    return [];
  }

  /**
   * Handle authorization decision
   */
  private handleDecision(
    request: Request,
    response: Response,
    decision: AuthorizationDecision,
    evaluationId: string,
    startTime: number,
  ): void {
    response.setHeader(this.config.decisionHeader, decision.decision);
    response.setHeader(this.config.evaluationIdHeader, evaluationId);
    response.setHeader("X-Evaluation-Time-Ms", Date.now() - startTime);

    request.authorizationDecision = decision;

    switch (decision.decision) {
      case "ALLOW":
        break;

      case "DENY":
      case "NO_MATCH":
        this.sendForbidden(
          response,
          decision.reason,
          decision.reasonCode,
          evaluationId,
        );
        break;

      case "INDETERMINATE":
        this.sendForbidden(
          response,
          decision.reason,
          decision.reasonCode,
          evaluationId,
        );
        break;

      default:
        this.sendForbidden(
          response,
          "Unknown authorization decision",
          "UNKNOWN",
          evaluationId,
        );
    }
  }

  /**
   * Send unauthorized response
   */
  private sendUnauthorized(
    response: Response,
    message: string,
    evaluationId: string,
  ): void {
    response.status(401).json({
      error: "Unauthorized",
      message,
      evaluationId,
    });
  }

  /**
   * Send forbidden response
   */
  private sendForbidden(
    response: Response,
    message: string,
    reasonCode: string,
    evaluationId: string,
  ): void {
    response.status(403).json({
      error: "Forbidden",
      message,
      reasonCode,
      evaluationId,
    });
  }

  /**
   * Log authorization decision
   */
  private async logDecision(
    context: IAMRequestContext,
    decision: AuthorizationDecision,
  ): Promise<void> {
    if (!this.config.decisionLogger) return;

    try {
      await this.config.decisionLogger.logDecision(
        decision,
        context.subject,
        context.action,
        context.resource,
        context.context,
        { async: true },
      );
    } catch (error) {
      logger.error("Failed to log authorization decision", {
        error,
        module: "iam-middleware",
      });
    }
  }

  /**
   * Check if authorization should be skipped for this request
   */
  private shouldSkipAuthorization(request: Request): boolean {
    const path = request.path;

    for (const skipPath of this.config.skipPaths) {
      if (this.matchPath(path, skipPath)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if path is public (authenticated but no policy check)
   */
  private isPublicPath(request: Request): boolean {
    const path = request.path;

    for (const publicPath of this.config.publicPaths) {
      if (this.matchPath(path, publicPath)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Match path against pattern (supports wildcards)
   */
  private matchPath(path: string, pattern: string): boolean {
    if (pattern === path) return true;

    if (pattern.endsWith("/*")) {
      const basePath = pattern.slice(0, -2);
      return path.startsWith(basePath);
    }

    if (pattern.endsWith("/**")) {
      const basePath = pattern.slice(0, -3);
      return path.startsWith(basePath);
    }

    if (pattern.includes("*")) {
      const regex = new RegExp("^" + pattern.replace(/\*/g, ".*") + "$");
      return regex.test(path);
    }

    return false;
  }

  /**
   * Extract tenant context from request
   */
  private async extractTenantContext(
    request: Request,
    tenantId: string,
  ): Promise<TenantContext> {
    try {
      return await this.config.tenantContextManager.extractTenantContext(
        request,
      );
    } catch (error) {
      logger.warn("Failed to extract tenant context", {
        error,
        module: "iam-middleware",
        tenantId,
      });

      return {
        tenantId,
        tenantConfig: {
          id: tenantId,
          name: tenantId,
          displayName: tenantId,
          settings: {
            mfaRequired: false,
            sessionTimeout: 60,
            passwordPolicy: {
              minLength: 8,
              requireUppercase: true,
              requireLowercase: true,
              requireNumbers: true,
              requireSpecialChars: true,
              maxAge: 90,
              historyCount: 12,
            },
            ssoEnabled: false,
          },
          limits: {
            maxUsers: 100,
            maxApiKeys: 50,
            maxStorage: 10737418240,
            rateLimit: 1000,
          },
          features: {
            advancedAuditing: false,
            customBranding: false,
            apiAccessLogging: true,
            extendedRetention: false,
          },
        },
        lifecycle: {
          status: "ACTIVE",
          createdAt: new Date(),
        },
        requestScope: {
          requestId: this.getRequestId(request),
          ipAddress: this.getClientIp(request),
          userAgent: request.headers["user-agent"] || "unknown",
          tenantId,
        },
        validatedAt: new Date(),
        expiresAt: new Date(Date.now() + 30 * 60 * 1000),
      };
    }
  }

  /**
   * Get request ID from request
   */
  private getRequestId(request: Request): string {
    return (
      (request.headers["x-request-id"] as string) ||
      (request as any).requestId ||
      generateId()
    );
  }
}

// ============================================================================
// Legacy Exports for Backward Compatibility
// ============================================================================

/**
 * Extended Express Request with authorization context (legacy)
 */
export interface AuthorizationRequestExt extends Request {
  authContext?: {
    subject: Subject;
    requestId: string;
  };
}

/**
 * Middleware options (legacy)
 */
export interface AuthorizationMiddlewareOptions {
  action: string;
  resourceType: string;
  resourceIdExtractor?: (req: Request) => string | undefined;
  condition?: (req: Request) => boolean;
  softFailure?: boolean;
  denyMessage?: string;
}

/**
 * Authorization middleware factory (legacy)
 */
export function createAuthorizationMiddleware(
  policyEngine: PolicyEngine,
  options: AuthorizationMiddlewareOptions,
) {
  return async (
    req: AuthorizationRequestExt,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      if (options.condition && !options.condition(req)) {
        next();
        return;
      }

      const subject = await getSubjectFromRequest(req);
      if (!subject) {
        res.status(401).json({
          error: "Unauthorized",
          message: "No subject found in request",
        });
        return;
      }

      const authRequest = buildAuthorizationRequestLegacy(
        req,
        subject,
        options,
      );
      const decision = policyEngine.authorize(authRequest, []);

      if (decision.decision === "ALLOW") {
        (req as any).authDecision = decision;
        next();
      } else {
        if (options.softFailure) {
          next();
        } else {
          res.status(403).json({
            error: "Forbidden",
            message: options.denyMessage ?? "Access denied",
            decision: decision.reason,
          });
        }
      }
    } catch (error) {
      next(error);
    }
  };
}

/**
 * Require all permissions middleware (legacy)
 */
export function requireAll(
  policyEngine: PolicyEngine,
  permissions: Array<{ action: string; resourceType: string }>,
) {
  return async (
    req: AuthorizationRequestExt,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const subject = await getSubjectFromRequest(req);
    if (!subject) {
      res.status(401).json({
        error: "Unauthorized",
        message: "No subject found in request",
      });
      return;
    }

    for (const permission of permissions) {
      const authRequest = buildAuthorizationRequestLegacy(req, subject, {
        action: permission.action,
        resourceType: permission.resourceType,
      });

      const decision = policyEngine.authorize(authRequest, []);
      if (decision.decision !== "ALLOW") {
        res.status(403).json({
          error: "Forbidden",
          message: `Missing permission: ${permission.action}:${permission.resourceType}`,
        });
        return;
      }
    }

    next();
  };
}

/**
 * Require any permission middleware (legacy)
 */
export function requireAny(
  policyEngine: PolicyEngine,
  permissions: Array<{ action: string; resourceType: string }>,
) {
  return async (
    req: AuthorizationRequestExt,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const subject = await getSubjectFromRequest(req);
    if (!subject) {
      res.status(401).json({
        error: "Unauthorized",
        message: "No subject found in request",
      });
      return;
    }

    let hasPermission = false;
    for (const permission of permissions) {
      const authRequest = buildAuthorizationRequestLegacy(req, subject, {
        action: permission.action,
        resourceType: permission.resourceType,
      });

      const decision = policyEngine.authorize(authRequest, []);
      if (decision.decision === "ALLOW") {
        hasPermission = true;
        break;
      }
    }

    if (!hasPermission) {
      res.status(403).json({
        error: "Forbidden",
        message: "Insufficient permissions",
      });
      return;
    }

    next();
  };
}

/**
 * Get subject from request (legacy)
 */
async function getSubjectFromRequest(
  req: AuthorizationRequestExt,
): Promise<Subject | null> {
  if (req.authContext?.subject) {
    return req.authContext.subject;
  }

  const user = (req as any).user;
  if (user) {
    return {
      id: user.id,
      tenantId: user.tenantId,
      type: (user.type as PrincipalType) || "User",
      roles: user.roles ?? [],
      attributes: user.attributes ?? {},
    };
  }

  const serviceId = req.headers["x-service-id"] as string | undefined;
  const apiKey = req.headers["x-api-key"] as string | undefined;
  const tenantId = req.headers["x-tenant-id"] as string | undefined;

  if (serviceId && apiKey) {
    return {
      id: serviceId,
      tenantId: tenantId ?? "",
      type: "Service" as PrincipalType,
      roles: [],
    };
  }

  return null;
}

/**
 * Build authorization request (legacy)
 */
function buildAuthorizationRequestLegacy(
  req: Request,
  subject: Subject,
  options: AuthorizationMiddlewareOptions,
): AuthorizationRequest {
  const resourceId = options.resourceIdExtractor
    ? options.resourceIdExtractor(req)
    : req.params.id;

  const requestContext: RequestContext = {
    timestamp: new Date().toISOString(),
    ipAddress: req.ip ?? req.socket.remoteAddress ?? "",
    userAgent: (req.headers["user-agent"] as string) ?? "",
    sessionId: req.headers["x-session-id"] as string | undefined,
  };

  const authContext: AuthorizationContext = {
    subject,
    action: { id: options.action },
    resource: {
      type: options.resourceType,
      id: resourceId,
      tenantId: subject.tenantId,
    },
    context: requestContext,
  };

  return {
    requestId: generateId(),
    subject,
    action: {
      id: options.action,
      method: req.method as Action["method"],
    },
    resource: {
      type: options.resourceType,
      id: resourceId,
      tenantId: subject.tenantId,
    },
    context: authContext,
  } as unknown as AuthorizationRequest;
}
