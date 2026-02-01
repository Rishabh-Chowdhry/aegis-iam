import { PrismaClient, AuditLog } from "@prisma/client";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import {
  IAuditLogRepository,
  AuditQuery,
  PaginationOptions,
  ComplianceReport,
  AuditEventInput,
} from "./IAuditLogRepository";
import { createHash } from "crypto";

export class PrismaAuditLogRepository implements IAuditLogRepository {
  constructor(private prisma: PrismaClient) {}

  async save(entry: AuditLogEntry): Promise<void> {
    // Generate cryptographic hash for immutability
    const logData = {
      userId: entry.userId,
      action: entry.action,
      timestamp: entry.timestamp,
      details: entry.details,
      tenantId: entry.tenantId,
    };
    const hash = this.generateHash(logData);

    await this.prisma.auditLog.create({
      data: {
        eventType: entry.action,
        subjectId: entry.userId,
        subjectType: "user",
        subjectTenantId: entry.tenantId,
        actionName: entry.action,
        details: entry.details as any,
        context: entry.details as any,
        createdAt: entry.timestamp,
        tenantId: entry.tenantId,
        hash,
      } as any,
    });
  }

  async append(event: AuditEventInput): Promise<AuditLog> {
    const hash = this.generateHash(event);
    return this.prisma.auditLog.create({
      data: event as any,
    });
  }

  async query(
    query: AuditQuery,
    options?: PaginationOptions,
  ): Promise<AuditLog[]> {
    const where: any = {};

    if (query.tenantId) where.tenantId = query.tenantId;
    if (query.eventType) where.eventType = query.eventType;
    if (query.subjectId) where.subjectId = query.subjectId;
    if (query.subjectType) where.subjectType = query.subjectType;
    if (query.resourceType) where.resourceType = query.resourceType;
    if (query.resourceId) where.resourceId = query.resourceId;
    if (query.decision) where.decision = query.decision;
    if (query.environment) where.environment = query.environment;
    if (query.riskScore) where.riskScore = query.riskScore;

    if (query.startDate && query.endDate) {
      where.createdAt = {
        gte: query.startDate,
        lte: query.endDate,
      };
    }

    return this.prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
      take: options?.limit || 10,
    });
  }

  async count(query: AuditQuery): Promise<number> {
    const where: any = {};

    if (query.tenantId) where.tenantId = query.tenantId;
    if (query.eventType) where.eventType = query.eventType;
    if (query.subjectId) where.subjectId = query.subjectId;
    if (query.subjectType) where.subjectType = query.subjectType;
    if (query.resourceType) where.resourceType = query.resourceType;
    if (query.resourceId) where.resourceId = query.resourceId;
    if (query.decision) where.decision = query.decision;
    if (query.environment) where.environment = query.environment;

    if (query.startDate && query.endDate) {
      where.createdAt = {
        gte: query.startDate,
        lte: query.endDate,
      };
    }

    return this.prisma.auditLog.count({ where });
  }

  async getByEvaluationId(evaluationId: string): Promise<AuditLog | null> {
    return this.prisma.auditLog.findFirst({
      where: { evaluationId },
    });
  }

  async getByRequestId(requestId: string): Promise<AuditLog | null> {
    return this.prisma.auditLog.findFirst({
      where: { requestId },
    });
  }

  async getByTenantAndDateRange(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    options?: PaginationOptions,
  ): Promise<AuditLog[]> {
    return this.prisma.auditLog.findMany({
      where: {
        tenantId,
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
      orderBy: { createdAt: "desc" },
      skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
      take: options?.limit || 10,
    });
  }

  async getBySubject(
    subjectId: string,
    tenantId?: string,
    options?: PaginationOptions,
  ): Promise<AuditLog[]> {
    const where: any = { subjectId };
    if (tenantId) where.tenantId = tenantId;

    return this.prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
      take: options?.limit || 10,
    });
  }

  async getByResource(
    resourceType: string,
    resourceId?: string,
    tenantId?: string,
    options?: PaginationOptions,
  ): Promise<AuditLog[]> {
    const where: any = { resourceType };
    if (resourceId) where.resourceId = resourceId;
    if (tenantId) where.tenantId = tenantId;

    return this.prisma.auditLog.findMany({
      where,
      orderBy: { createdAt: "desc" },
      skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
      take: options?.limit || 10,
    });
  }

  async getDeniedEvents(
    tenantId: string,
    startDate: Date,
    endDate: Date,
    options?: PaginationOptions,
  ): Promise<AuditLog[]> {
    return this.prisma.auditLog.findMany({
      where: {
        tenantId,
        decision: "DENY",
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
      orderBy: { createdAt: "desc" },
      skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
      take: options?.limit || 10,
    });
  }

  async generateComplianceReport(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<ComplianceReport> {
    const events = await this.getByTenantAndDateRange(
      tenantId,
      startDate,
      endDate,
    );

    const eventsByType: Record<string, number> = {};
    let allowCount = 0;
    let denyCount = 0;
    let highRiskEvents = 0;
    let policyChanges = 0;
    let boundaryViolations = 0;

    for (const event of events) {
      eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1;

      if (event.decision === "ALLOW") allowCount++;
      else if (event.decision === "DENY") denyCount++;

      if (event.riskScore >= 70) highRiskEvents++;
      if (event.eventType === "POLICY_CHANGE") policyChanges++;
      if (event.eventType === "BOUNDARY_VIOLATION") boundaryViolations++;
    }

    return {
      tenantId,
      startDate,
      endDate,
      totalEvents: events.length,
      allowCount,
      denyCount,
      eventsByType,
      highRiskEvents,
      policyChanges,
      boundaryViolations,
      mfaBypassAttempts: 0,
    };
  }

  async getEventStatistics(
    tenantId: string,
    startDate: Date,
    endDate: Date,
  ): Promise<{
    totalEvents: number;
    eventsByType: Record<string, number>;
    eventsByDecision: Record<string, number>;
    highRiskCount: number;
  }> {
    const events = await this.getByTenantAndDateRange(
      tenantId,
      startDate,
      endDate,
    );

    const eventsByType: Record<string, number> = {};
    const eventsByDecision: Record<string, number> = {};
    let highRiskCount = 0;

    for (const event of events) {
      eventsByType[event.eventType] = (eventsByType[event.eventType] || 0) + 1;
      eventsByDecision[event.decision] =
        (eventsByDecision[event.decision] || 0) + 1;
      if (event.riskScore >= 70) highRiskCount++;
    }

    return {
      totalEvents: events.length,
      eventsByType,
      eventsByDecision,
      highRiskCount,
    };
  }

  async deleteOlderThan(date: Date): Promise<number> {
    const result = await this.prisma.auditLog.deleteMany({
      where: {
        createdAt: {
          lt: date,
        },
      },
    });
    return result.count;
  }

  async findByUserId(
    userId: string,
    tenantId: string,
  ): Promise<AuditLogEntry[]> {
    const logsData = await this.prisma.auditLog.findMany({
      where: { subjectId: userId, tenantId },
      orderBy: { createdAt: "desc" },
    });
    return logsData.map(this.mapToDomain);
  }

  async findByAction(
    action: string,
    tenantId: string,
  ): Promise<AuditLogEntry[]> {
    const logsData = await this.prisma.auditLog.findMany({
      where: { actionName: action, tenantId },
      orderBy: { createdAt: "desc" },
    });
    return logsData.map(this.mapToDomain);
  }

  async findByDateRange(
    startDate: Date,
    endDate: Date,
    tenantId: string,
  ): Promise<AuditLogEntry[]> {
    const logsData = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        createdAt: {
          gte: startDate,
          lte: endDate,
        },
      },
      orderBy: { createdAt: "desc" },
    });
    return logsData.map(this.mapToDomain);
  }

  async exportToJSON(
    tenantId: string,
    startDate?: Date,
    endDate?: Date,
  ): Promise<string> {
    const logsData = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        ...(startDate &&
          endDate && {
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          }),
      },
      orderBy: { createdAt: "desc" },
    });

    return JSON.stringify(logsData, null, 2);
  }

  async exportToCSV(
    tenantId: string,
    startDate?: Date,
    endDate?: Date,
  ): Promise<string> {
    const logsData = await this.prisma.auditLog.findMany({
      where: {
        tenantId,
        ...(startDate &&
          endDate && {
            createdAt: {
              gte: startDate,
              lte: endDate,
            },
          }),
      },
      orderBy: { createdAt: "desc" },
    });

    const headers = [
      "id",
      "eventType",
      "subjectId",
      "actionName",
      "resourceType",
      "createdAt",
      "tenantId",
      "hash",
    ];
    const rows = logsData.map((log) => [
      log.id,
      log.eventType || "",
      log.subjectId || "",
      log.actionName || "",
      log.resourceType || "",
      log.createdAt?.toISOString() || "",
      log.tenantId,
      (log as any).hash || "",
    ]);

    return [headers.join(","), ...rows.map((row) => row.join(","))].join("\n");
  }

  async cleanupOldLogs(
    retentionDays: number,
    tenantId: string,
  ): Promise<number> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    const result = await this.prisma.auditLog.deleteMany({
      where: {
        tenantId,
        createdAt: {
          lt: cutoffDate,
        },
      },
    });

    return result.count;
  }

  async verifyLogIntegrity(logId: string): Promise<boolean> {
    const log = await this.prisma.auditLog.findUnique({
      where: { id: logId },
    });

    if (!log || !(log as any).hash) {
      return false;
    }

    const logData = {
      userId: log.subjectId,
      action: log.actionName,
      timestamp: log.createdAt,
      details: log.context,
      tenantId: log.tenantId,
    };

    const computedHash = this.generateHash(logData);
    return computedHash === (log as any).hash;
  }

  private generateHash(data: any): string {
    const dataString = JSON.stringify(data, Object.keys(data).sort());
    return createHash("sha256").update(dataString).digest("hex");
  }

  private mapToDomain(logData: any): AuditLogEntry {
    return new AuditLogEntry(
      logData.subjectId || "",
      logData.actionName || logData.eventType || "",
      logData.createdAt,
      (logData.context || {}) as Record<string, any>,
      logData.tenantId,
    );
  }
}
