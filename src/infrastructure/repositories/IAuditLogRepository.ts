import { AuditLog } from "@prisma/client";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";

// Audit query options for filtering
export interface AuditQuery {
  tenantId?: string;
  eventType?: string;
  subjectId?: string;
  subjectType?: string;
  resourceType?: string;
  resourceId?: string;
  decision?: string;
  startDate?: Date;
  endDate?: Date;
  riskScore?: number;
  environment?: string;
}

// Pagination options
export interface PaginationOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
}

// Compliance report options
export interface ComplianceReport {
  tenantId: string;
  startDate: Date;
  endDate: Date;
  totalEvents: number;
  allowCount: number;
  denyCount: number;
  eventsByType: Record<string, number>;
  highRiskEvents: number;
  policyChanges: number;
  boundaryViolations: number;
  mfaBypassAttempts: number;
}

// Extended audit event DTO with all required fields
export interface AuditEventInput {
  eventType: string;
  tenantId: string;
  subjectId: string;
  subjectType: string;
  subjectTenantId: string;
  actionName: string;
  actionType?: string;
  resourceType: string;
  resourceId?: string;
  resourceTenantId: string;
  ipAddress: string;
  userAgent?: string;
  requestId: string;
  mfaVerified: boolean;
  riskScore: number;
  environment: string;
  context?: Record<string, unknown>;
  decision: string;
  reason: string;
  reasonCode: string;
  matchedPolicies?: string[];
  evaluationId: string;
  duration?: number;
  traceId?: string;
  signature?: string;
}

// Union type for backward compatibility
export type AuditLogEntryInput = AuditEventInput | AuditLogEntry;

export interface IAuditLogRepository {
  // Backward compatibility - accepts legacy AuditLogEntry
  save(entry: AuditLogEntry): Promise<void>;

  // Append-only operations with full audit event
  append(event: AuditEventInput): Promise<AuditLog>;

  // Query operations (read-only)
  query(query: AuditQuery, options?: PaginationOptions): Promise<AuditLog[]>;
  count(query: AuditQuery): Promise<number>;

  // Specialized queries
  getByEvaluationId(evaluationId: string): Promise<AuditLog | null>;
  getByRequestId(requestId: string): Promise<AuditLog | null>;
  getByTenantAndDateRange(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    options?: PaginationOptions,
  ): Promise<AuditLog[]>;
  getBySubject(
    subjectId: string,
    tenantId?: string,
    options?: PaginationOptions,
  ): Promise<AuditLog[]>;
  getByResource(
    resourceType: string,
    resourceId?: string,
    tenantId?: string,
    options?: PaginationOptions,
  ): Promise<AuditLog[]>;
  getDeniedEvents(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    options?: PaginationOptions,
  ): Promise<AuditLog[]>;

  // Compliance operations
  generateComplianceReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<ComplianceReport>;

  // Statistics
  getEventStatistics(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsByDecision: Record<string, number>;
    highRiskCount: number;
  }>;

  // Retention operations
  deleteOlderThan(date: Date): Promise<number>;
}
