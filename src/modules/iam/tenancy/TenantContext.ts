/**
 * Tenant Context Module
 *
 * Enterprise-grade multi-tenant context management for IAM platform.
 * Provides tenant ID extraction, validation, and request scoping.
 * SOC2/ISO 27001 compliant implementation.
 */

import { Request, Response, NextFunction } from "express";
import { randomUUID } from "crypto";
import { ITenantRepository } from "../repositories/ITenantRepository";
import { AuditLoggerService } from "../../../infrastructure/services/AuditLoggerService";
import { structuredLogger } from "../../../core/logger/structuredLogger";

/**
 * Tenant Status Enumeration
 * Represents the lifecycle state of a tenant
 */
export type TenantStatus =
  | "ACTIVE"
  | "SUSPENDED"
  | "PENDING"
  | "OFFBOARDING"
  | "DELETED";

/**
 * Password Policy Configuration
 */
export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  maxAge: number; // days
  historyCount: number;
}

/**
 * Tenant Settings
 * Configuration options for tenant-specific behavior
 */
export interface TenantSettings {
  mfaRequired: boolean;
  ipWhitelist?: string[];
  sessionTimeout: number; // minutes
  passwordPolicy: PasswordPolicy;
  ssoEnabled: boolean;
  ssoProvider?: string;
}

/**
 * Tenant Limits
 * Resource and rate limits for the tenant
 */
export interface TenantLimits {
  maxUsers: number;
  maxApiKeys: number;
  maxStorage: number; // bytes
  rateLimit: number; // requests per minute
}

/**
 * Tenant Features
 * Feature flags enabled for the tenant
 */
export interface TenantFeatures {
  advancedAuditing: boolean;
  customBranding: boolean;
  apiAccessLogging: boolean;
  extendedRetention: boolean;
}

/**
 * Tenant Configuration
 * Complete tenant configuration interface
 */
export interface TenantConfig {
  id: string;
  name: string;
  displayName: string;
  domain?: string;
  settings: TenantSettings;
  limits: TenantLimits;
  features: TenantFeatures;
}

/**
 * Tenant Lifecycle
 * Tracks tenant status and important timestamps
 */
export interface TenantLifecycle {
  status: TenantStatus;
  createdAt: Date;
  activatedAt?: Date;
  suspendedAt?: Date;
  offboardedAt?: Date;
  lastActivityAt?: Date;
  renewalDate?: Date;
}

/**
 * Request Scope
 * Context information for the current request
 */
export interface RequestScope {
  requestId: string;
  userId?: string;
  serviceId?: string;
  ipAddress: string;
  userAgent: string;
  tenantId: string;
}

/**
 * Tenant Context
 * Complete tenant context for authorization
 */
export interface TenantContext {
  tenantId: string;
  tenantConfig: TenantConfig;
  lifecycle: TenantLifecycle;
  requestScope: RequestScope;
  validatedAt: Date;
  expiresAt: Date;
}

/**
 * Validation Result
 * Result of tenant validation check
 */
export interface ValidationResult {
  valid: boolean;
  status?: TenantStatus;
  error?: string;
  details?: Record<string, unknown>;
}

/**
 * Tenant Cache Service Interface
 */
export interface TenantCacheService {
  get(key: string): Promise<TenantContext | null>;
  set(key: string, value: TenantContext, ttlSeconds: number): Promise<void>;
  delete(key: string): Promise<void>;
  invalidate(tenantId: string): Promise<void>;
}

/**
 * In-memory tenant cache for development
 */
class InMemoryTenantCache implements TenantCacheService {
  private cache: Map<string, { value: TenantContext; expiresAt: number }> =
    new Map();

  async get(key: string): Promise<TenantContext | null> {
    const entry = this.cache.get(key);
    if (!entry || Date.now() > entry.expiresAt) {
      if (entry) this.cache.delete(key);
      return null;
    }
    return entry.value;
  }

  async set(
    key: string,
    value: TenantContext,
    ttlSeconds: number,
  ): Promise<void> {
    this.cache.set(key, {
      value,
      expiresAt: Date.now() + ttlSeconds * 1000,
    });
  }

  async delete(key: string): Promise<void> {
    this.cache.delete(key);
  }

  async invalidate(tenantId: string): Promise<void> {
    const keysToDelete: string[] = [];
    this.cache.forEach((_, key) => {
      if (key.startsWith(tenantId)) {
        keysToDelete.push(key);
      }
    });
    keysToDelete.forEach((key) => this.cache.delete(key));
  }
}

/**
 * Tenant Context Manager
 *
 * Manages tenant context extraction, validation, and request scoping.
 * Thread-safe for concurrent request handling.
 */
export class TenantContextManager {
  private static readonly TENANT_ID_REGEX = /^[a-zA-Z0-9_-]{3,64}$/;
  private static readonly CONTEXT_TTL_MINUTES = 30;
  private static readonly CACHE_TTL_SECONDS = 300; // 5 minutes

  private contextStorage: Map<string, TenantContext> = new Map();
  private cache: TenantCacheService;

  constructor(
    private tenantRepository: ITenantRepository,
    private auditLogger: AuditLoggerService,
    cache?: TenantCacheService,
  ) {
    this.cache = cache || new InMemoryTenantCache();
  }

  /**
   * Extract and validate tenant context from request
   */
  async extractTenantContext(request: Request): Promise<TenantContext> {
    const requestId = this.getRequestId(request);
    const tenantId = await this.extractTenantId(request);

    // Check cache first
    const cacheKey = `${tenantId}:${requestId}`;
    const cached = await this.cache.get(cacheKey);
    if (cached) {
      return cached;
    }

    // Create request scope
    const requestScope = this.createRequestScope(request, tenantId);

    // Validate tenant
    const validation = await this.validateTenantStatus(tenantId);
    if (!validation.valid) {
      await this.logTenantValidationFailure(request, tenantId, validation);
      throw new TenantContextError(
        `Tenant validation failed: ${validation.error}`,
        tenantId,
        requestId,
      );
    }

    // Get tenant configuration
    const tenantConfig = await this.getTenantConfig(tenantId);
    if (!tenantConfig) {
      await this.logTenantNotFound(request, tenantId);
      throw new TenantContextError(
        `Tenant not found: ${tenantId}`,
        tenantId,
        requestId,
      );
    }

    // Build lifecycle from tenant data
    const lifecycle: TenantLifecycle = {
      status: validation.status || "ACTIVE",
      createdAt: new Date(),
      lastActivityAt: new Date(),
    };

    // Create context
    const context: TenantContext = {
      tenantId,
      tenantConfig,
      lifecycle,
      requestScope,
      validatedAt: new Date(),
      expiresAt: new Date(
        Date.now() + TenantContextManager.CONTEXT_TTL_MINUTES * 60 * 1000,
      ),
    };

    // Cache the context
    await this.cache.set(
      cacheKey,
      context,
      TenantContextManager.CACHE_TTL_SECONDS,
    );

    return context;
  }

  /**
   * Validate tenant status
   */
  async validateTenantStatus(tenantId: string): Promise<ValidationResult> {
    try {
      const tenant = await this.tenantRepository.findById(tenantId);

      if (!tenant) {
        return {
          valid: false,
          error: "Tenant not found",
        };
      }

      const status = tenant.status as TenantStatus;

      switch (status) {
        case "ACTIVE":
          return { valid: true, status };

        case "PENDING":
          return {
            valid: false,
            status,
            error: "Tenant is pending activation",
          };

        case "SUSPENDED":
          return {
            valid: false,
            status,
            error: "Tenant is suspended",
          };

        case "OFFBOARDING":
          return {
            valid: false,
            status,
            error: "Tenant is being offboarded",
          };

        case "DELETED":
          return {
            valid: false,
            status,
            error: "Tenant has been deleted",
          };

        default:
          return {
            valid: false,
            status: "PENDING",
            error: "Unknown tenant status",
          };
      }
    } catch (error) {
      structuredLogger.error("Tenant validation error", error as Error, {
        module: "tenant-context",
        action: "validateTenantStatus",
        tenantId,
      });

      return {
        valid: false,
        error: "Validation service unavailable",
      };
    }
  }

  /**
   * Get tenant configuration
   */
  async getTenantConfig(tenantId: string): Promise<TenantConfig | null> {
    try {
      const tenant = await this.tenantRepository.findById(tenantId);
      if (!tenant) return null;

      // Build config from tenant data
      return {
        id: tenant.id,
        name: tenant.name,
        displayName: tenant.name,
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
          maxStorage: 10737418240, // 10GB
          rateLimit: 1000,
        },
        features: {
          advancedAuditing: false,
          customBranding: false,
          apiAccessLogging: true,
          extendedRetention: false,
        },
      };
    } catch (error) {
      structuredLogger.error("Failed to get tenant config", error as Error, {
        module: "tenant-context",
        action: "getTenantConfig",
        tenantId,
      });
      return null;
    }
  }

  /**
   * Create scoped context for request
   */
  createRequestScope(request: Request, tenantId: string): RequestScope {
    return {
      requestId: this.getRequestId(request),
      userId: (request as any).user?.id,
      serviceId: (request as any).service?.id,
      ipAddress: this.getClientIp(request),
      userAgent: request.headers["user-agent"] || "unknown",
      tenantId,
    };
  }

  /**
   * Clear context after request
   */
  clearContext(requestId: string): void {
    const keysToDelete: string[] = [];
    this.contextStorage.forEach((_, key) => {
      if (key.includes(requestId)) {
        keysToDelete.push(key);
      }
    });
    keysToDelete.forEach((key) => this.contextStorage.delete(key));
  }

  /**
   * Get context for current request scope
   */
  getCurrentContext(requestId: string): TenantContext | null {
    let context: TenantContext | null = null;
    this.contextStorage.forEach((value, key) => {
      if (key.includes(requestId)) {
        // Check expiration
        if (value.expiresAt > new Date()) {
          context = value;
        } else {
          this.contextStorage.delete(key);
        }
      }
    });
    return context;
  }

  /**
   * Set context for request scope
   */
  setContext(requestId: string, context: TenantContext): void {
    this.contextStorage.set(requestId, context);
  }

  /**
   * Extract tenant ID from request
   */
  private async extractTenantId(request: Request): Promise<string> {
    // Priority 1: X-Tenant-ID header
    const headerTenant = request.headers["x-tenant-id"];
    if (typeof headerTenant === "string" && headerTenant.trim()) {
      const tenantId = headerTenant.trim();
      if (this.isValidTenantIdFormat(tenantId)) {
        return tenantId;
      }
    }

    // Priority 2: JWT token (decoded user object)
    const tokenTenant = (request as any).user?.tenantId;
    if (tokenTenant && this.isValidTenantIdFormat(tokenTenant)) {
      return tokenTenant;
    }

    // Priority 3: API Key header
    const apiKeyTenant = request.headers["x-api-key-tenant"];
    if (typeof apiKeyTenant === "string" && apiKeyTenant.trim()) {
      const tenantId = apiKeyTenant.trim();
      if (this.isValidTenantIdFormat(tenantId)) {
        return tenantId;
      }
    }

    // Priority 4: Query parameter (for specific use cases)
    const queryTenant = request.query.tenantId;
    if (typeof queryTenant === "string" && queryTenant.trim()) {
      const tenantId = queryTenant.trim();
      if (this.isValidTenantIdFormat(tenantId)) {
        return tenantId;
      }
    }

    throw new TenantContextError(
      "Tenant ID not found in request",
      "unknown",
      this.getRequestId(request),
    );
  }

  /**
   * Validate tenant ID format
   */
  private isValidTenantIdFormat(tenantId: string): boolean {
    return TenantContextManager.TENANT_ID_REGEX.test(tenantId);
  }

  /**
   * Get request ID from request
   */
  private getRequestId(request: Request): string {
    const headerRequestId = request.headers["x-request-id"];
    if (typeof headerRequestId === "string" && headerRequestId.trim()) {
      return headerRequestId.trim();
    }
    return `req_${randomUUID()}`;
  }

  /**
   * Get client IP address
   */
  private getClientIp(request: Request): string {
    const forwarded = request.headers["x-forwarded-for"];
    if (typeof forwarded === "string") {
      return forwarded.split(",")[0].trim();
    }
    const realIp = request.headers["x-real-ip"];
    if (typeof realIp === "string") {
      return realIp.trim();
    }
    return request.socket?.remoteAddress || "unknown";
  }

  /**
   * Log tenant validation failure
   */
  private async logTenantValidationFailure(
    request: Request,
    tenantId: string,
    validation: ValidationResult,
  ): Promise<void> {
    await this.auditLogger.log(
      "UNAUTHORIZED_ACCESS",
      "tenant_context",
      {
        tenantId,
        userId: (request as any).user?.id,
        ipAddress: this.getClientIp(request),
        userAgent: request.headers["user-agent"],
        correlationId: this.getRequestId(request),
      },
      {
        resourceId: tenantId,
        outcome: "FAILURE",
        errorMessage: validation.error,
        details: {
          validationStatus: validation.status,
        },
      },
    );
  }

  /**
   * Log tenant not found
   */
  private async logTenantNotFound(
    request: Request,
    tenantId: string,
  ): Promise<void> {
    await this.auditLogger.log(
      "UNAUTHORIZED_ACCESS",
      "tenant_context",
      {
        tenantId,
        userId: (request as any).user?.id,
        ipAddress: this.getClientIp(request),
        userAgent: request.headers["user-agent"],
        correlationId: this.getRequestId(request),
      },
      {
        resourceId: tenantId,
        outcome: "FAILURE",
        errorMessage: "Tenant not found",
      },
    );
  }
}

/**
 * Tenant Context Error
 */
export class TenantContextError extends Error {
  constructor(
    message: string,
    public tenantId: string,
    public requestId: string,
  ) {
    super(message);
    this.name = "TenantContextError";
  }
}

/**
 * Tenant Context Middleware
 * Express middleware to extract and validate tenant context
 */
export function createTenantContextMiddleware(
  contextManager: TenantContextManager,
) {
  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    try {
      const context = await contextManager.extractTenantContext(req);
      (req as any).tenantContext = context;
      (req as any).tenantId = context.tenantId;
      next();
    } catch (error) {
      if (error instanceof TenantContextError) {
        res.status(403).json({
          error: "TENANT_CONTEXT_ERROR",
          message: error.message,
          tenantId: error.tenantId,
          requestId: error.requestId,
        });
      } else {
        structuredLogger.error(
          "Tenant context middleware error",
          error as Error,
          { module: "tenant-context", action: "middleware" },
        );
        res.status(500).json({
          error: "INTERNAL_ERROR",
          message: "Failed to establish tenant context",
        });
      }
    }
  };
}

/**
 * Get current tenant context from request
 */
export function getTenantContext(req: Request): TenantContext | null {
  return (req as any).tenantContext || null;
}

/**
 * Get current tenant ID from request
 */
export function getTenantId(req: Request): string | null {
  return (req as any).tenantId || null;
}

// Re-export for backward compatibility
export { TenantContextFactory, ITenantContext } from "./TenantContext.legacy";
