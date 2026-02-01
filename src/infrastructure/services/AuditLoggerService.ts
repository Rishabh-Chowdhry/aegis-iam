/**
 * Audit Logger Service - Records security-sensitive actions for compliance and forensics
 * Provides immutable audit trail for authentication, authorization, and data access events
 */

import crypto from "crypto";
import prisma from "../database/prisma";
import { structuredLogger, LogLevel } from "../../core/logger/structuredLogger";

// Audit event types
export type AuditAction =
  // Authentication events
  | "LOGIN"
  | "LOGOUT"
  | "LOGIN_FAILED"
  | "TOKEN_REFRESH"
  | "PASSWORD_CHANGE"
  | "PASSWORD_RESET"
  | "MFA_ENABLED"
  | "MFA_DISABLED"
  | "ACCOUNT_LOCKED"
  | "ACCOUNT_UNLOCKED"
  // Authorization events
  | "PERMISSION_DENIED"
  | "POLICY_VIOLATION"
  | "UNAUTHORIZED_ACCESS"
  // User management
  | "USER_CREATED"
  | "USER_UPDATED"
  | "USER_DELETED"
  | "USER_ROLE_ASSIGNED"
  | "USER_ROLE_REVOKED"
  | "USER_STATUS_CHANGED"
  // Permission management
  | "PERMISSION_CREATED"
  | "PERMISSION_UPDATED"
  | "PERMISSION_DELETED"
  | "PERMISSION_GRANTED"
  | "PERMISSION_REVOKED"
  // Role management
  | "ROLE_CREATED"
  | "ROLE_UPDATED"
  | "ROLE_DELETED"
  | "ROLE_HIERARCHY_CHANGED"
  // Policy management
  | "POLICY_CREATED"
  | "POLICY_UPDATED"
  | "POLICY_DELETED"
  // Sensitive data access
  | "SENSITIVE_DATA_ACCESS"
  | "DATA_EXPORT"
  | "DATA_DELETE"
  // Session events
  | "SESSION_CREATED"
  | "SESSION_TERMINATED"
  | "SESSION_EXPIRED";

export type AuditOutcome = "SUCCESS" | "FAILURE";

export interface AuditLogEntry {
  id: string;
  timestamp: Date;
  userId: string;
  tenantId: string;
  action: AuditAction;
  resource: string;
  resourceId?: string;
  details?: Record<string, unknown>;
  ipAddress: string;
  userAgent: string;
  outcome: AuditOutcome;
  errorMessage?: string;
  correlationId?: string;
}

export interface AuditLoggerConfig {
  enabled: boolean;
  retentionDays: number;
  sensitiveFields: string[];
}

export interface AuditLogContext {
  userId?: string;
  tenantId: string;
  ipAddress?: string;
  userAgent?: string;
  correlationId?: string;
}

/**
 * Sanitize sensitive data from audit logs
 * Never log passwords, tokens, PII, or other sensitive information
 */
function sanitizeDetails(
  details: Record<string, unknown> | undefined,
  sensitiveFields: string[],
): Record<string, unknown> | undefined {
  if (!details) return undefined;

  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(details)) {
    const lowerKey = key.toLowerCase();

    // Check if field is sensitive
    const isSensitive = sensitiveFields.some((field) =>
      lowerKey.includes(field.toLowerCase()),
    );

    if (isSensitive) {
      sanitized[key] = "[REDACTED]";
    } else if (
      typeof value === "object" &&
      value !== null &&
      !Array.isArray(value)
    ) {
      // Recursively sanitize nested objects
      sanitized[key] = sanitizeDetails(
        value as Record<string, unknown>,
        sensitiveFields,
      );
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

export class AuditLoggerService {
  private static instance: AuditLoggerService;
  private config: AuditLoggerConfig;
  private sensitiveFields: string[] = [
    "password",
    "token",
    "secret",
    "key",
    "credential",
    "authorization",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "ssn",
    "socialsecurity",
    "creditcard",
    "cvv",
    "pin",
    "biometric",
  ];

  private constructor(config?: Partial<AuditLoggerConfig>) {
    this.config = {
      enabled: config?.enabled ?? true,
      retentionDays: config?.retentionDays ?? 90,
      sensitiveFields: config?.sensitiveFields ?? this.sensitiveFields,
    };
  }

  /**
   * Get singleton instance of the audit logger
   */
  static getInstance(config?: Partial<AuditLoggerConfig>): AuditLoggerService {
    if (!AuditLoggerService.instance) {
      AuditLoggerService.instance = new AuditLoggerService(config);
    }
    return AuditLoggerService.instance;
  }

  /**
   * Log an audit event
   */
  async log(
    action: AuditAction,
    resource: string,
    context: AuditLogContext,
    options?: {
      resourceId?: string;
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    if (!this.config.enabled) return;

    try {
      // Sanitize details to remove sensitive information
      const sanitizedDetails = sanitizeDetails(
        options?.details,
        this.config.sensitiveFields,
      );

      const entry: AuditLogEntry = {
        id: crypto.randomUUID(),
        timestamp: new Date(),
        userId: context.userId || "system",
        tenantId: context.tenantId,
        action,
        resource,
        resourceId: options?.resourceId,
        details: sanitizedDetails,
        ipAddress: context.ipAddress || "unknown",
        userAgent: context.userAgent || "unknown",
        outcome: options?.outcome || "SUCCESS",
        errorMessage: options?.errorMessage,
        correlationId: context.correlationId,
      };

      // Persist to database
      await prisma.auditLog.create({
        data: {
          id: entry.id,
          eventType: entry.action,
          subjectId: entry.userId,
          subjectType: "user",
          subjectTenantId: entry.tenantId,
          actionName: entry.action,
          resourceType: entry.resource,
          resourceId: entry.resourceId,
          context: entry.details as any,
          ipAddress: entry.ipAddress,
          userAgent: entry.userAgent,
          createdAt: entry.timestamp,
          tenantId: entry.tenantId,
          decision: entry.outcome === "SUCCESS" ? "ALLOW" : "DENY",
          reason: entry.errorMessage || "",
          reasonCode: entry.errorMessage ? "ERROR" : "OK",
          evaluationId: entry.correlationId || entry.id,
          requestId: entry.correlationId || entry.id,
          mfaVerified: false,
          riskScore: 0,
          environment: "development",
        } as any,
      });

      // Also log to structured logger for immediate visibility
      structuredLogger.logAuditEvent(entry);
    } catch (error) {
      // Log failure should not break the application
      structuredLogger.error("Failed to persist audit log", error as Error, {
        module: "audit",
        action: "persist",
        metadata: {
          action,
          resource,
          userId: context.userId,
        },
      });
    }
  }

  /**
   * Log authentication event
   */
  async logAuth(
    action: AuditAction,
    context: AuditLogContext,
    options?: {
      resourceId?: string;
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, "authentication", context, options);
  }

  /**
   * Log authorization event
   */
  async logAuthorization(
    action: AuditAction,
    resource: string,
    context: AuditLogContext,
    options?: {
      resourceId?: string;
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, resource, context, options);
  }

  /**
   * Log user management event
   */
  async logUserManagement(
    action: AuditAction,
    userId: string,
    context: AuditLogContext,
    options?: {
      resourceId?: string;
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, "user_management", context, {
      ...options,
      resourceId: userId,
    });
  }

  /**
   * Log permission management event
   */
  async logPermissionManagement(
    action: AuditAction,
    permissionId: string,
    context: AuditLogContext,
    options?: {
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, "permission_management", context, {
      ...options,
      resourceId: permissionId,
    });
  }

  /**
   * Log role management event
   */
  async logRoleManagement(
    action: AuditAction,
    roleId: string,
    context: AuditLogContext,
    options?: {
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, "role_management", context, {
      ...options,
      resourceId: roleId,
    });
  }

  /**
   * Log policy management event
   */
  async logPolicyManagement(
    action: AuditAction,
    policyId: string,
    context: AuditLogContext,
    options?: {
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log(action, "policy_management", context, {
      ...options,
      resourceId: policyId,
    });
  }

  /**
   * Log sensitive data access
   */
  async logSensitiveDataAccess(
    resource: string,
    resourceId: string,
    context: AuditLogContext,
    options?: {
      details?: Record<string, unknown>;
      outcome?: AuditOutcome;
      errorMessage?: string;
    },
  ): Promise<void> {
    return this.log("SENSITIVE_DATA_ACCESS", resource, context, {
      ...options,
      resourceId,
    });
  }

  /**
   * Query audit logs by user
   */
  async findByUserId(
    userId: string,
    tenantId: string,
    limit = 100,
  ): Promise<AuditLogEntry[]> {
    const logs = await prisma.auditLog.findMany({
      where: {
        subjectId: userId,
        tenantId,
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });

    return logs.map((log) => ({
      id: log.id,
      timestamp: log.createdAt,
      userId: log.subjectId || "system",
      tenantId: log.tenantId,
      action: log.actionName as AuditAction,
      resource: log.resourceType,
      resourceId: log.resourceId || undefined,
      details: (log.context || {}) as Record<string, unknown>,
      ipAddress: log.ipAddress || "unknown",
      userAgent: log.userAgent || "unknown",
      outcome:
        log.decision === "ALLOW" ? "SUCCESS" : ("FAILURE" as AuditOutcome),
    }));
  }

  /**
   * Query audit logs by action
   */
  async findByAction(
    action: AuditAction,
    tenantId: string,
    limit = 100,
  ): Promise<AuditLogEntry[]> {
    const logs = await prisma.auditLog.findMany({
      where: {
        actionName: action as string,
        tenantId,
      },
      orderBy: {
        createdAt: "desc",
      },
      take: limit,
    });

    return logs.map((log) => ({
      id: log.id,
      timestamp: log.createdAt,
      userId: log.subjectId || "system",
      tenantId: log.tenantId,
      action: log.actionName as AuditAction,
      resource: log.resourceType,
      resourceId: log.resourceId || undefined,
      details: (log.context || {}) as Record<string, unknown>,
      ipAddress: log.ipAddress || "unknown",
      userAgent: log.userAgent || "unknown",
      outcome:
        log.decision === "ALLOW" ? "SUCCESS" : ("FAILURE" as AuditOutcome),
    }));
  }

  /**
   * Clean up old audit logs based on retention policy
   */
  async cleanup(): Promise<number> {
    if (this.config.retentionDays <= 0) return 0;

    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - this.config.retentionDays);

    const result = await prisma.auditLog.deleteMany({
      where: {
        createdAt: {
          lt: cutoffDate,
        },
      },
    });

    structuredLogger.info(
      `Cleaned up ${result.count} audit logs older than ${this.config.retentionDays} days`,
      {
        module: "audit",
        action: "cleanup",
        metadata: {
          deletedCount: result.count,
          retentionDays: this.config.retentionDays,
        },
      },
    );

    return result.count;
  }
}

// Export singleton instance
export const auditLogger = AuditLoggerService.getInstance();
