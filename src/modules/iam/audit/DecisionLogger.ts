/**
 * Decision Logger - Enterprise-grade Audit Logger
 *
 * Handles immutable audit logging for authorization decisions,
 * policy changes, security events, and compliance reporting.
 * Designed for SOC2, ISO 27001, and enterprise audit requirements.
 */

import * as crypto from "crypto";
import {
  Subject,
  Resource,
  Action,
  AuthorizationContext,
  AuthorizationDecision,
} from "../policy/models/types";

// Import SIEMIntegration for type reference (avoiding circular dependency)
import type { SIEMIntegration } from "./SIEMIntegration";

// ==================== AUDIT EVENT TYPES ====================

/**
 * Audit event types for comprehensive event categorization
 */
export type AuditEventType =
  | "AUTHORIZATION_DECISION"
  | "POLICY_CHANGE"
  | "TENANT_LIFECYCLE"
  | "USER_LIFECYCLE"
  | "SESSION_EVENT"
  | "CONFIGURATION_CHANGE"
  | "SECURITY_EVENT"
  | "BOUNDARY_VIOLATION";

/**
 * Audit severity levels for event prioritization
 */
export type AuditSeverity = "DEBUG" | "INFO" | "WARNING" | "ERROR" | "CRITICAL";

/**
 * Security event types for specialized security logging
 */
export type SecurityEventType =
  | "FAILED_LOGIN"
  | "SUCCESSFUL_LOGIN"
  | "LOGOUT"
  | "PASSWORD_CHANGE"
  | "MFA_ENABLED"
  | "MFA_DISABLED"
  | "API_KEY_CREATED"
  | "API_KEY_REVOKED"
  | "PERMISSION_GRANTED"
  | "PERMISSION_REVOKED"
  | "SUSPICIOUS_ACTIVITY"
  | "BRUTE_FORCE_DETECTED"
  | "IMPOSSIBLE_TRAVEL"
  | "ANOMALOUS_BEHAVIOR";

/**
 * Audit metadata with additional context
 */
export interface AuditMetadata {
  source: string;
  service: string;
  region?: string;
  traceId?: string;
  spanId?: string;
  parentSpanId?: string;
  correlationId?: string;
  duration?: number;
  [key: string]: unknown;
}

/**
 * Complete audit event interface with all compliance fields
 */
export interface AuditEvent {
  // Required Fields
  eventId: string; // Unique event ID (UUID)
  eventType: AuditEventType;
  tenantId: string;
  timestamp: Date;
  version: string; // Schema version

  // Subject Information
  subject: {
    id: string;
    type: "user" | "service" | "api_key" | "session";
    tenantId: string;
    roles?: string[];
    attributes?: Record<string, unknown>;
  };

  // Action Information
  action: {
    name: string;
    type?: string;
    method?: string;
    category?: string;
  };

  // Resource Information
  resource: {
    type: string;
    id?: string;
    tenantId: string;
    ownerId?: string;
    attributes?: Record<string, unknown>;
  };

  // Context Information
  context: {
    ip: string;
    userAgent?: string;
    requestId: string;
    mfa: boolean;
    riskScore: number;
    environment: "production" | "staging" | "development";
    timestamp: Date;
  };

  // Decision Information
  decision?: {
    result: "ALLOW" | "DENY";
    reason: string;
    reasonCode: string;
    matchedPolicies: string[];
    matchedStatements?: string[];
    evaluationId: string;
  };

  // Additional Metadata
  metadata: AuditMetadata;

  // Compliance Fields
  compliance: {
    soc2: boolean;
    iso27001: boolean;
    pciDss: boolean;
    hipaa: boolean;
    fedramp: boolean;
  };

  // Signature for tamper evidence
  signature?: string;
}

/**
 * Options for logging operations
 */
export interface LogOptions {
  async?: boolean; // Log asynchronously
  sign?: boolean; // Sign event for tamper evidence
  streamToSIEM?: boolean; // Stream to SIEM immediately
  priority?: "LOW" | "NORMAL" | "HIGH";
}

/**
 * Audit query interface for log retrieval
 */
export interface AuditQuery {
  tenantId?: string;
  subjectId?: string;
  action?: string;
  resourceType?: string;
  decision?: "ALLOW" | "DENY";
  startDate?: Date;
  endDate?: Date;
  eventTypes?: AuditEventType[];
  limit?: number;
  offset?: number;
  orderBy?: "timestamp" | "eventType";
  orderDirection?: "ASC" | "DESC";
}

/**
 * Audit logger configuration
 */
export interface AuditLoggerConfig {
  schemaVersion: string;
  serviceName: string;
  region?: string;
  enableSigning: boolean;
  signingKey?: string;
  retentionDays: number;
  archiveEnabled: boolean;
  archivePath?: string;
}

/**
 * Boundary violation event
 */
export interface AuditBoundaryViolation {
  violationType: "TENANT_ISOLATION" | "RATE_LIMIT" | "QUOTA_EXCEEDED";
  sourceTenantId: string;
  targetTenantId?: string;
  resourcePath: string;
  httpMethod: string;
  attemptedBy: string;
  description: string;
}

/**
 * Compliance report interface
 */
export interface ComplianceReport {
  reportId: string;
  reportType: "SOC2" | "ISO27001" | "PCI_DSS" | "CUSTOM";
  generatedAt: Date;
  period: { start: Date; end: Date };
  summary: ReportSummary;
  details: AuditEvent[];
  signature: string;
}

/**
 * Report summary statistics
 */
export interface ReportSummary {
  totalEvents: number;
  allowDecisions: number;
  denyDecisions: number;
  policyChanges: number;
  securityIncidents: number;
  boundaryViolations: number;
  uniqueUsers: number;
  uniqueResources: number;
}

/**
 * Audit log repository interface
 */
export interface IAuditLogRepository {
  append(event: AuditEvent): Promise<void>;
  appendBatch(events: AuditEvent[]): Promise<void>;
  query(query: AuditQuery): Promise<AuditEvent[]>;
  getById(eventId: string): Promise<AuditEvent | null>;
  getByTenant(tenantId: string, limit: number): Promise<AuditEvent[]>;
  deleteOldEvents(beforeDate: Date): Promise<number>;
  archive(events: AuditEvent[], path: string): Promise<void>;
}

/**
 * Crypto service interface for signing
 */
export interface CryptoService {
  sign(data: string, key?: string): string;
  verify(data: string, signature: string, key?: string): boolean;
  hash(data: string): string;
}

// ==================== DEFAULT CRYPTO SERVICE ====================

/**
 * Default crypto service implementation
 */
class DefaultCryptoService implements CryptoService {
  constructor(private readonly secretKey?: string) {}

  sign(data: string, key?: string): string {
    const secretKey = key || this.secretKey || "default-audit-signing-key";
    const hmac = crypto.createHmac("sha256", secretKey);
    hmac.update(data);
    return `sha256=${hmac.digest("hex")}`;
  }

  verify(data: string, signature: string, key?: string): boolean {
    if (!signature.startsWith("sha256=")) {
      return false;
    }
    const expectedSignature = signature.replace("sha256=", "");
    const secretKey = key || this.secretKey || "default-audit-signing-key";
    const hmac = crypto.createHmac("sha256", secretKey);
    hmac.update(data);
    const computedSignature = hmac.digest("hex");
    return crypto.timingSafeEqual(
      Buffer.from(expectedSignature),
      Buffer.from(computedSignature),
    );
  }

  hash(data: string): string {
    return crypto.createHash("sha256").update(data).digest("hex");
  }
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Generate a UUID v4
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

// ==================== DECISION LOGGER CLASS ====================

/**
 * Decision Logger - Enterprise-grade audit logger for authorization decisions
 */
export class DecisionLogger {
  private readonly cryptoService: CryptoService;
  private readonly eventBuffer: AuditEvent[] = [];
  private readonly bufferFlushInterval: NodeJS.Timeout;
  private isShuttingDown = false;

  constructor(
    private readonly auditRepository: IAuditLogRepository,
    private readonly siemIntegration: SIEMIntegration | null,
    private readonly config: AuditLoggerConfig,
    cryptoService?: CryptoService,
  ) {
    this.cryptoService =
      cryptoService || new DefaultCryptoService(config.signingKey);

    // Start periodic buffer flush (every 5 seconds)
    this.bufferFlushInterval = setInterval(() => {
      this.flushBuffer().catch((error) => {
        console.error("[DecisionLogger] Buffer flush error:", error);
      });
    }, 5000);

    // Handle graceful shutdown
    process.on("SIGTERM", () => this.shutdown());
    process.on("SIGINT", () => this.shutdown());
  }

  /**
   * Log an authorization decision
   */
  async logDecision(
    decision: AuthorizationDecision,
    subject: Subject,
    action: Action,
    resource: Resource,
    context: AuthorizationContext,
    options?: LogOptions,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "AUTHORIZATION_DECISION",
      tenantId: subject.tenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: subject.id,
        type: this.mapPrincipalType(subject.type),
        tenantId: subject.tenantId,
        roles: subject.roles,
        attributes: subject.attributes,
      },
      action: {
        name: action.id || action.displayName || "unknown",
        method: action.method,
        category: action.category,
      },
      resource: {
        type: resource.type,
        id: resource.id,
        tenantId: resource.tenantId,
        ownerId: resource.ownerId,
        attributes: resource.attributes,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: context.context.riskScore || 0,
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(context.context.timestamp),
      },
      decision: {
        result: this.mapDecisionResult(decision.decision),
        reason: decision.reason,
        reasonCode: decision.reasonCode,
        matchedPolicies: decision.matchedPolicies.map((p) => p.policyId),
        matchedStatements: decision.matchedPolicies.map((p) => p.statementId),
        evaluationId: generateUUID(),
      },
      metadata: {
        source: "policy-engine",
        service: this.config.serviceName,
        region: this.config.region,
        traceId: context.context.sessionId,
        duration: decision.metrics.evaluationTimeMs,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, options);
  }

  /**
   * Log a policy change event
   */
  async logPolicyChange(
    eventType: "CREATE" | "UPDATE" | "DELETE",
    policyId: string,
    tenantId: string,
    actorId: string,
    changes: Record<string, unknown>,
    context: AuthorizationContext,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "POLICY_CHANGE",
      tenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: actorId,
        type: "user",
        tenantId,
      },
      action: {
        name: `POLICY_${eventType}`,
        category: "administration",
      },
      resource: {
        type: "policy",
        id: policyId,
        tenantId,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: context.context.riskScore || 0,
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(context.context.timestamp),
      },
      metadata: {
        source: "policy-management",
        service: this.config.serviceName,
        region: this.config.region,
        correlationId: generateUUID(),
        changes,
        eventType,
        policyId,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, { sign: true, streamToSIEM: true });
  }

  /**
   * Log a tenant lifecycle event
   */
  async logTenantLifecycle(
    eventType: "CREATE" | "SUSPEND" | "RESUME" | "OFFBOARD",
    tenantId: string,
    actorId: string,
    reason: string,
    context: AuthorizationContext,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "TENANT_LIFECYCLE",
      tenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: actorId,
        type: "user",
        tenantId,
      },
      action: {
        name: `TENANT_${eventType}`,
        category: "administration",
      },
      resource: {
        type: "tenant",
        id: tenantId,
        tenantId,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: context.context.riskScore || 0,
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(context.context.timestamp),
      },
      metadata: {
        source: "tenant-management",
        service: this.config.serviceName,
        region: this.config.region,
        reason,
        eventType,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, { sign: true, streamToSIEM: true });
  }

  /**
   * Log a user lifecycle event
   */
  async logUserLifecycle(
    eventType: "CREATE" | "UPDATE" | "DELETE" | "SUSPEND" | "RESUME",
    userId: string,
    tenantId: string,
    actorId: string,
    changes: Record<string, unknown>,
    context: AuthorizationContext,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "USER_LIFECYCLE",
      tenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: actorId,
        type: "user",
        tenantId,
      },
      action: {
        name: `USER_${eventType}`,
        category: "administration",
      },
      resource: {
        type: "user",
        id: userId,
        tenantId,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: context.context.riskScore || 0,
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(context.context.timestamp),
      },
      metadata: {
        source: "user-management",
        service: this.config.serviceName,
        region: this.config.region,
        changes,
        eventType,
        userId,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, { sign: true, streamToSIEM: true });
  }

  /**
   * Log a security event
   */
  async logSecurityEvent(
    eventType: SecurityEventType,
    tenantId: string,
    subject: Subject,
    description: string,
    severity: AuditSeverity,
    context: AuthorizationContext,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "SECURITY_EVENT",
      tenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: subject.id,
        type: this.mapPrincipalType(subject.type),
        tenantId: subject.tenantId,
        roles: subject.roles,
        attributes: subject.attributes,
      },
      action: {
        name: eventType,
        category: "security",
      },
      resource: {
        type: "security",
        tenantId,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: context.context.riskScore || 0,
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(context.context.timestamp),
      },
      metadata: {
        source: "security-monitor",
        service: this.config.serviceName,
        region: this.config.region,
        description,
        severity,
        eventType,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, {
      sign: true,
      streamToSIEM: true,
      priority: "HIGH",
    });
  }

  /**
   * Log a boundary violation
   */
  async logBoundaryViolation(
    violation: AuditBoundaryViolation,
    context: AuthorizationContext,
  ): Promise<AuditEvent> {
    const event: AuditEvent = {
      eventId: generateUUID(),
      eventType: "BOUNDARY_VIOLATION",
      tenantId: violation.sourceTenantId,
      timestamp: new Date(),
      version: this.config.schemaVersion,
      subject: {
        id: violation.attemptedBy,
        type: "user",
        tenantId: violation.sourceTenantId,
      },
      action: {
        name: violation.violationType,
        method: violation.httpMethod,
        category: "security",
      },
      resource: {
        type: "boundary",
        tenantId: violation.targetTenantId || violation.sourceTenantId,
      },
      context: {
        ip: context.context.ipAddress || "unknown",
        userAgent: context.context.userAgent,
        requestId: context.context.sessionId || generateUUID(),
        mfa: context.context.mfaAuthenticated || false,
        riskScore: 100, // High risk for violations
        environment: this.mapEnvironment(context.context.environment),
        timestamp: new Date(),
      },
      metadata: {
        source: "boundary-enforcement",
        service: this.config.serviceName,
        region: this.config.region,
        ...violation,
      },
      compliance: {
        soc2: true,
        iso27001: true,
        pciDss: false,
        hipaa: false,
        fedramp: false,
      },
    };

    return this.processEvent(event, {
      sign: true,
      streamToSIEM: true,
      priority: "HIGH",
    });
  }

  /**
   * Sign event for tamper evidence
   */
  signEvent(event: AuditEvent): string {
    // Create canonical representation of the event
    const eventData = this.getCanonicalEventData(event);
    return this.cryptoService.sign(eventData);
  }

  /**
   * Verify event signature
   */
  verifySignature(event: AuditEvent): boolean {
    if (!event.signature) {
      return false;
    }
    const canonicalData = this.getCanonicalEventData(event);
    return this.cryptoService.verify(canonicalData, event.signature);
  }

  /**
   * Query audit logs
   */
  async query(query: AuditQuery): Promise<AuditEvent[]> {
    return this.auditRepository.query(query);
  }

  /**
   * Generate a compliance report
   */
  async generateComplianceReport(
    reportType: "SOC2" | "ISO27001" | "PCI_DSS" | "CUSTOM",
    startDate: Date,
    endDate: Date,
  ): Promise<ComplianceReport> {
    const events = await this.auditRepository.query({
      startDate,
      endDate,
      orderBy: "timestamp",
      orderDirection: "ASC",
    });

    const summary = this.calculateSummary(events);
    const report: ComplianceReport = {
      reportId: generateUUID(),
      reportType,
      generatedAt: new Date(),
      period: { start: startDate, end: endDate },
      summary,
      details: events,
      signature: "",
    };

    // Sign the report
    report.signature = this.signReport(report);

    return report;
  }

  /**
   * Get audit event statistics
   */
  async getStatistics(tenantId?: string): Promise<ReportSummary> {
    const query: AuditQuery = {
      tenantId,
      limit: 10000, // Get all for statistics calculation
    };

    const events = await this.auditRepository.query(query);
    return this.calculateSummary(events);
  }

  // ==================== PRIVATE METHODS ====================

  /**
   * Process and store an audit event
   */
  private async processEvent(
    event: AuditEvent,
    options?: LogOptions,
  ): Promise<AuditEvent> {
    const effectiveOptions = {
      async: options?.async ?? true,
      sign: options?.sign ?? this.config.enableSigning,
      streamToSIEM: options?.streamToSIEM ?? false,
      priority: options?.priority ?? "NORMAL",
    };

    // Sign event if required
    if (effectiveOptions.sign) {
      event.signature = this.signEvent(event);
    }

    // Add to buffer for batch processing
    this.eventBuffer.push(event);

    // Flush immediately for high priority or SIEM streaming
    if (
      effectiveOptions.priority === "HIGH" ||
      this.eventBuffer.length >= 100 ||
      effectiveOptions.async === false
    ) {
      await this.flushBuffer();
    }

    // Stream to SIEM if requested
    if (effectiveOptions.streamToSIEM && this.siemIntegration) {
      this.siemIntegration.streamEvent(event).catch((_error: unknown) => {
        console.error("[DecisionLogger] SIEM streaming error:", _error);
      });
    }

    return event;
  }

  /**
   * Flush event buffer to repository
   */
  private async flushBuffer(): Promise<void> {
    if (this.eventBuffer.length === 0) {
      return;
    }

    const events = [...this.eventBuffer];
    this.eventBuffer.length = 0;

    try {
      await this.auditRepository.appendBatch(events);
    } catch (error) {
      console.error("[DecisionLogger] Failed to append events:", error);
      // Re-add failed events to buffer for retry
      this.eventBuffer.push(...events);
    }
  }

  /**
   * Shutdown gracefully
   */
  private async shutdown(): Promise<void> {
    if (this.isShuttingDown) {
      return;
    }
    this.isShuttingDown = true;

    clearInterval(this.bufferFlushInterval);

    // Flush remaining events
    await this.flushBuffer();

    // Stop SIEM integration
    if (this.siemIntegration) {
      this.siemIntegration.stop();
    }
  }

  /**
   * Get canonical event data for signing
   */
  private getCanonicalEventData(event: AuditEvent): string {
    // Create a stable, deterministic representation
    const canonical: Record<string, unknown> = {
      eventId: event.eventId,
      eventType: event.eventType,
      tenantId: event.tenantId,
      timestamp: event.timestamp.toISOString(),
      version: event.version,
      subject: event.subject,
      action: event.action,
      resource: event.resource,
      context: event.context,
      metadata: event.metadata,
      compliance: event.compliance,
    };

    if (event.decision) {
      canonical.decision = event.decision;
    }

    return JSON.stringify(canonical, Object.keys(canonical).sort() as string[]);
  }

  /**
   * Sign a compliance report
   */
  private signReport(report: ComplianceReport): string {
    const reportData = {
      reportId: report.reportId,
      reportType: report.reportType,
      generatedAt: report.generatedAt.toISOString(),
      period: report.period,
      summary: report.summary,
      totalEvents: report.details.length,
    };

    return this.cryptoService.sign(JSON.stringify(reportData));
  }

  /**
   * Calculate summary statistics from events
   */
  private calculateSummary(events: AuditEvent[]): ReportSummary {
    const uniqueUsersSet = new Set<string>();
    const uniqueResourcesSet = new Set<string>();

    for (const event of events) {
      uniqueUsersSet.add(event.subject.id);
      if (event.resource.id) {
        uniqueResourcesSet.add(`${event.resource.type}:${event.resource.id}`);
      }
    }

    const summary: ReportSummary = {
      totalEvents: events.length,
      allowDecisions: 0,
      denyDecisions: 0,
      policyChanges: 0,
      securityIncidents: 0,
      boundaryViolations: 0,
      uniqueUsers: uniqueUsersSet.size,
      uniqueResources: uniqueResourcesSet.size,
    };

    for (const event of events) {
      if (event.decision?.result === "ALLOW") {
        summary.allowDecisions++;
      } else if (event.decision?.result === "DENY") {
        summary.denyDecisions++;
      }

      if (event.eventType === "POLICY_CHANGE") {
        summary.policyChanges++;
      } else if (event.eventType === "SECURITY_EVENT") {
        summary.securityIncidents++;
      } else if (event.eventType === "BOUNDARY_VIOLATION") {
        summary.boundaryViolations++;
      }
    }

    return summary;
  }

  /**
   * Map principal type to audit subject type
   */
  private mapPrincipalType(
    type: string,
  ): "user" | "service" | "api_key" | "session" {
    switch (type) {
      case "Service":
        return "service";
      case "Anonymous":
        return "api_key";
      default:
        return "user";
    }
  }

  /**
   * Map environment string
   */
  private mapEnvironment(
    env?: string,
  ): "production" | "staging" | "development" {
    switch (env) {
      case "production":
        return "production";
      case "staging":
        return "staging";
      default:
        return "development";
    }
  }

  /**
   * Map decision result
   */
  private mapDecisionResult(
    decision: "ALLOW" | "DENY" | "NO_MATCH" | "INDETERMINATE",
  ): "ALLOW" | "DENY" {
    return decision === "ALLOW" ? "ALLOW" : "DENY";
  }
}
