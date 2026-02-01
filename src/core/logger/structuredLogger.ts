/**
 * Structured Logger - Enterprise-grade JSON logging for production observability
 * Supports correlation IDs, log levels, and context-aware logging
 */

import crypto from "crypto";

export type LogLevel = "INFO" | "WARN" | "ERROR" | "DEBUG";

export interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  correlationId?: string;
  userId?: string;
  tenantId?: string;
  module?: string;
  action?: string;
  metadata?: Record<string, unknown>;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

export interface LoggerConfig {
  level: LogLevel;
  jsonFormat: boolean;
  correlationIdHeader?: string;
}

export class StructuredLogger {
  private config: LoggerConfig;
  private static instance: StructuredLogger;
  private correlationId: string | null = null;

  private constructor(config?: Partial<LoggerConfig>) {
    this.config = {
      level: config?.level || ("INFO" as LogLevel),
      jsonFormat: config?.jsonFormat ?? true,
      correlationIdHeader: config?.correlationIdHeader || "x-correlation-id",
    };
  }

  /**
   * Get singleton instance of the structured logger
   */
  static getInstance(config?: Partial<LoggerConfig>): StructuredLogger {
    if (!StructuredLogger.instance) {
      StructuredLogger.instance = new StructuredLogger(config);
    }
    return StructuredLogger.instance;
  }

  /**
   * Set correlation ID for the current context
   */
  setCorrelationId(correlationId: string): void {
    this.correlationId = correlationId;
  }

  /**
   * Get current correlation ID
   */
  getCorrelationId(): string | null {
    return this.correlationId;
  }

  /**
   * Generate a new unique correlation ID
   */
  generateCorrelationId(): string {
    const id = `corr_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
    this.correlationId = id;
    return id;
  }

  /**
   * Clear correlation ID
   */
  clearCorrelationId(): void {
    this.correlationId = null;
  }

  /**
   * Get numeric log level for comparison
   */
  private getLevelValue(level: LogLevel): number {
    switch (level) {
      case "DEBUG":
        return 0;
      case "INFO":
        return 1;
      case "WARN":
        return 2;
      case "ERROR":
        return 3;
      default:
        return 1;
    }
  }

  /**
   * Check if the given level should be logged
   */
  private shouldLog(level: LogLevel): boolean {
    return this.getLevelValue(level) >= this.getLevelValue(this.config.level);
  }

  /**
   * Create a log entry with all context
   */
  private createLogEntry(
    level: LogLevel,
    message: string,
    context?: {
      userId?: string;
      tenantId?: string;
      module?: string;
      action?: string;
      metadata?: Record<string, unknown>;
      error?: Error;
    },
  ): LogEntry {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      correlationId: this.correlationId || undefined,
    };

    if (context) {
      if (context.userId) entry.userId = context.userId;
      if (context.tenantId) entry.tenantId = context.tenantId;
      if (context.module) entry.module = context.module;
      if (context.action) entry.action = context.action;
      if (context.metadata) entry.metadata = context.metadata;

      if (context.error) {
        entry.error = {
          name: context.error.name,
          message: context.error.message,
          stack: context.error.stack,
        };
      }
    }

    return entry;
  }

  /**
   * Format log entry for output
   */
  private formatLogEntry(entry: LogEntry): string {
    if (this.config.jsonFormat) {
      return JSON.stringify(entry);
    }

    const { timestamp, level, message, ...rest } = entry;
    const restStr =
      Object.keys(rest).length > 0 ? ` ${JSON.stringify(rest)}` : "";
    return `[${timestamp}] ${level}: ${message}${restStr}`;
  }

  /**
   * Log at INFO level
   */
  info(
    message: string,
    context?: {
      userId?: string;
      tenantId?: string;
      module?: string;
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    if (this.shouldLog("INFO")) {
      const entry = this.createLogEntry("INFO", message, context);
      console.log(this.formatLogEntry(entry));
    }
  }

  /**
   * Log at WARN level
   */
  warn(
    message: string,
    context?: {
      userId?: string;
      tenantId?: string;
      module?: string;
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    if (this.shouldLog("WARN")) {
      const entry = this.createLogEntry("WARN", message, context);
      console.warn(this.formatLogEntry(entry));
    }
  }

  /**
   * Log at ERROR level
   */
  error(
    message: string,
    error?: Error,
    context?: {
      userId?: string;
      tenantId?: string;
      module?: string;
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    if (this.shouldLog("ERROR")) {
      const entry = this.createLogEntry("ERROR", message, {
        ...context,
        error,
      });
      console.error(this.formatLogEntry(entry));
    }
  }

  /**
   * Log at DEBUG level
   */
  debug(
    message: string,
    context?: {
      userId?: string;
      tenantId?: string;
      module?: string;
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    if (this.shouldLog("DEBUG")) {
      const entry = this.createLogEntry("DEBUG", message, context);
      console.debug(this.formatLogEntry(entry));
    }
  }

  /**
   * Log request details
   */
  logRequest(
    req: {
      method: string;
      url: string;
      ip?: string;
      userAgent?: string;
      correlationId?: string;
    },
    res: {
      statusCode: number;
    },
    responseTime: number,
    userId?: string,
    tenantId?: string,
  ): void {
    this.info("Request completed", {
      userId,
      tenantId,
      module: "http",
      action: "request",
      metadata: {
        method: req.method,
        url: req.url,
        statusCode: res.statusCode,
        responseTime: `${responseTime}ms`,
        ip: req.ip,
        userAgent: req.userAgent,
        correlationId: req.correlationId || this.correlationId,
      },
    });
  }

  /**
   * Log authentication event
   */
  logAuth(
    action: string,
    outcome: "SUCCESS" | "FAILURE",
    details?: {
      userId?: string;
      tenantId?: string;
      ipAddress?: string;
      userAgent?: string;
      errorMessage?: string;
      correlationId?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.info(`Auth ${action}: ${outcome}`, {
      userId: details?.userId,
      tenantId: details?.tenantId,
      module: "authentication",
      action,
      metadata: {
        outcome,
        ipAddress: details?.ipAddress,
        userAgent: details?.userAgent,
        errorMessage: details?.errorMessage,
        correlationId: details?.correlationId,
        ...details?.metadata,
      },
    });
  }

  /**
   * Log authorization event
   */
  logAuthorization(
    action: string,
    resource: string,
    outcome: "SUCCESS" | "FAILURE",
    details?: {
      userId?: string;
      tenantId?: string;
      ipAddress?: string;
      userAgent?: string;
      reason?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.warn(`Authorization ${action} on ${resource}: ${outcome}`, {
      userId: details?.userId,
      tenantId: details?.tenantId,
      module: "authorization",
      action,
      metadata: {
        resource,
        outcome,
        ipAddress: details?.ipAddress,
        userAgent: details?.userAgent,
        reason: details?.reason,
        ...details?.metadata,
      },
    });
  }

  /**
   * Log security event
   */
  logSecurity(
    event: string,
    details?: {
      userId?: string;
      tenantId?: string;
      ipAddress?: string;
      userAgent?: string;
      severity?: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.warn(`Security Event: ${event}`, {
      userId: details?.userId,
      tenantId: details?.tenantId,
      module: "security",
      action: event,
      metadata: {
        severity: details?.severity || "MEDIUM",
        ipAddress: details?.ipAddress,
        userAgent: details?.userAgent,
        ...details?.metadata,
      },
    });
  }

  /**
   * Log performance metric
   */
  logPerformance(
    operation: string,
    duration: number,
    context?: {
      userId?: string;
      tenantId?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.info(`Performance: ${operation}`, {
      userId: context?.userId,
      tenantId: context?.tenantId,
      module: "performance",
      action: operation,
      metadata: {
        duration: `${duration}ms`,
        durationMs: duration,
        ...context?.metadata,
      },
    });
  }

  /**
   * Log audit event
   */
  logAuditEvent(entry: {
    id: string;
    timestamp: Date;
    userId: string;
    tenantId: string;
    action: string;
    resource: string;
    resourceId?: string;
    details?: Record<string, unknown>;
    ipAddress: string;
    userAgent: string;
    outcome: "SUCCESS" | "FAILURE";
    errorMessage?: string;
    correlationId?: string;
  }): void {
    this.info(`Audit: ${entry.action} on ${entry.resource}`, {
      userId: entry.userId,
      tenantId: entry.tenantId,
      module: "audit",
      action: entry.action,
      metadata: {
        auditId: entry.id,
        resource: entry.resource,
        resourceId: entry.resourceId,
        details: entry.details,
        ipAddress: entry.ipAddress,
        userAgent: entry.userAgent,
        outcome: entry.outcome,
        errorMessage: entry.errorMessage,
        correlationId: entry.correlationId,
        timestamp: entry.timestamp.toISOString(),
      },
    });
  }

  /**
   * Create a child logger with additional context
   */
  child(context: {
    userId?: string;
    tenantId?: string;
    module?: string;
  }): ChildLogger {
    return new ChildLogger(this, context);
  }
}

/**
 * Child logger that automatically includes context in all logs
 */
export class ChildLogger {
  constructor(
    private parent: StructuredLogger,
    private context: {
      userId?: string;
      tenantId?: string;
      module?: string;
    },
  ) {}

  setCorrelationId(correlationId: string): void {
    this.parent.setCorrelationId(correlationId);
  }

  info(
    message: string,
    context?: {
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.parent.info(message, {
      ...this.context,
      action: context?.action,
      metadata: context?.metadata,
    });
  }

  warn(
    message: string,
    context?: {
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.parent.warn(message, {
      ...this.context,
      action: context?.action,
      metadata: context?.metadata,
    });
  }

  error(
    message: string,
    error?: Error,
    context?: {
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.parent.error(message, error, {
      ...this.context,
      action: context?.action,
      metadata: context?.metadata,
    });
  }

  debug(
    message: string,
    context?: {
      action?: string;
      metadata?: Record<string, unknown>;
    },
  ): void {
    this.parent.debug(message, {
      ...this.context,
      action: context?.action,
      metadata: context?.metadata,
    });
  }

  child(additionalContext: {
    userId?: string;
    tenantId?: string;
    module?: string;
  }): ChildLogger {
    return new ChildLogger(this.parent, {
      ...this.context,
      ...additionalContext,
    });
  }
}

// Export singleton instance
export const structuredLogger = StructuredLogger.getInstance();
