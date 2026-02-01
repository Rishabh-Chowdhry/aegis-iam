/**
 * Scheduled Cleanup Jobs Service
 *
 * Provides scheduled cleanup jobs for audit logs, expired sessions,
 * and other temporary data.
 */

import { PrismaClient } from "@prisma/client";
import { logger } from "../../../shared/logger";

/**
 * Cleanup Job Configuration
 */
export interface CleanupJobConfig {
  /** Enable scheduled cleanup */
  enabled: boolean;

  /** Cleanup interval in minutes */
  intervalMinutes?: number;

  /** Audit log retention days */
  auditLogRetentionDays?: number;

  /** Session retention minutes */
  sessionRetentionMinutes?: number;

  /** Batch size for cleanup operations */
  batchSize?: number;
}

/**
 * Cleanup Job Statistics
 */
export interface CleanupJobStats {
  lastRunTime: Date | null;
  lastRunDuration: number;
  lastRunRecordsCleaned: number;
  totalRuns: number;
  totalRecordsCleaned: number;
}

/**
 * Scheduled Cleanup Jobs Service
 */
export class ScheduledCleanupJobs {
  private readonly config: CleanupJobConfig;
  private readonly prisma: PrismaClient;
  private cleanupInterval: NodeJS.Timeout | null = null;
  private stats: CleanupJobStats = {
    lastRunTime: null,
    lastRunDuration: 0,
    lastRunRecordsCleaned: 0,
    totalRuns: 0,
    totalRecordsCleaned: 0,
  };

  constructor(config: CleanupJobConfig, prisma: PrismaClient) {
    this.config = {
      intervalMinutes: config.intervalMinutes ?? 60,
      auditLogRetentionDays: config.auditLogRetentionDays ?? 90,
      sessionRetentionMinutes: config.sessionRetentionMinutes ?? 1440, // 24 hours
      batchSize: config.batchSize ?? 1000,
      ...config,
    };
    this.prisma = prisma;

    // Start scheduled cleanup
    if (this.config.enabled) {
      this.startScheduledCleanup();
    }
  }

  /**
   * Start scheduled cleanup
   */
  private startScheduledCleanup(): void {
    const intervalMs = (this.config.intervalMinutes ?? 60) * 60 * 1000;

    this.cleanupInterval = setInterval(async () => {
      await this.runCleanupJob();
    }, intervalMs);

    logger.info(
      `Scheduled cleanup jobs started (interval: ${this.config.intervalMinutes} minutes)`,
    );
  }

  /**
   * Run cleanup job
   */
  private async runCleanupJob(): Promise<void> {
    const startTime = Date.now();

    try {
      logger.info("Starting scheduled cleanup job");

      // Clean up old audit logs
      const auditLogsCleaned = await this.cleanupOldAuditLogs();

      // Clean up expired sessions
      const sessionsCleaned = await this.cleanupExpiredSessions();

      // Clean up old decision audits
      const decisionAuditsCleaned = await this.cleanupOldDecisionAudits();

      const totalCleaned =
        auditLogsCleaned + sessionsCleaned + decisionAuditsCleaned;
      const duration = Date.now() - startTime;

      // Update stats
      this.stats = {
        lastRunTime: new Date(),
        lastRunDuration: duration,
        lastRunRecordsCleaned: totalCleaned,
        totalRuns: this.stats.totalRuns + 1,
        totalRecordsCleaned: this.stats.totalRecordsCleaned + totalCleaned,
      };

      logger.info("Scheduled cleanup job completed", {
        auditLogsCleaned,
        sessionsCleaned,
        decisionAuditsCleaned,
        totalCleaned,
        duration,
      });
    } catch (error) {
      logger.error("Error in scheduled cleanup job", { error });
    }
  }

  /**
   * Clean up old audit logs
   */
  private async cleanupOldAuditLogs(): Promise<number> {
    const retentionDays = this.config.auditLogRetentionDays ?? 90;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    let cleanedCount = 0;
    let hasMore = true;

    while (hasMore) {
      const batchSize = this.config.batchSize ?? 1000;

      // Find old audit logs
      const oldLogs = await (this.prisma as any).auditLogEntry.findMany({
        where: {
          timestamp: {
            lt: cutoffDate,
          },
        },
        take: batchSize,
      });

      if (oldLogs.length === 0) {
        hasMore = false;
        break;
      }

      // Delete old logs
      const ids = oldLogs.map((log: any) => log.id);
      await (this.prisma as any).auditLogEntry.deleteMany({
        where: {
          id: { in: ids },
        },
      });

      cleanedCount += oldLogs.length;
    }

    logger.info(
      `Cleaned up ${cleanedCount} old audit logs (older than ${retentionDays} days)`,
    );
    return cleanedCount;
  }

  /**
   * Clean up expired sessions
   */
  private async cleanupExpiredSessions(): Promise<number> {
    const retentionMinutes = this.config.sessionRetentionMinutes ?? 1440;
    const cutoffDate = new Date();
    cutoffDate.setMinutes(cutoffDate.getMinutes() - retentionMinutes);

    let cleanedCount = 0;
    let hasMore = true;

    while (hasMore) {
      const batchSize = this.config.batchSize ?? 1000;

      // Find expired sessions
      const expiredSessions = await (this.prisma as any).session.findMany({
        where: {
          lastAccessedAt: {
            lt: cutoffDate,
          },
        },
        take: batchSize,
      });

      if (expiredSessions.length === 0) {
        hasMore = false;
        break;
      }

      // Delete expired sessions
      const ids = expiredSessions.map((session: any) => session.id);
      await (this.prisma as any).session.deleteMany({
        where: {
          id: { in: ids },
        },
      });

      cleanedCount += expiredSessions.length;
    }

    logger.info(
      `Cleaned up ${cleanedCount} expired sessions (older than ${retentionMinutes} minutes)`,
    );
    return cleanedCount;
  }

  /**
   * Clean up old decision audits
   */
  private async cleanupOldDecisionAudits(): Promise<number> {
    const retentionDays = this.config.auditLogRetentionDays ?? 90;
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - retentionDays);

    let cleanedCount = 0;
    let hasMore = true;

    while (hasMore) {
      const batchSize = this.config.batchSize ?? 1000;

      // Find old decision audits
      const oldAudits = await (this.prisma as any).decisionAudit.findMany({
        where: {
          evaluatedAt: {
            lt: cutoffDate,
          },
        },
        take: batchSize,
      });

      if (oldAudits.length === 0) {
        hasMore = false;
        break;
      }

      // Delete old audits
      const ids = oldAudits.map((audit: any) => audit.id);
      await (this.prisma as any).decisionAudit.deleteMany({
        where: {
          id: { in: ids },
        },
      });

      cleanedCount += oldAudits.length;
    }

    logger.info(
      `Cleaned up ${cleanedCount} old decision audits (older than ${retentionDays} days)`,
    );
    return cleanedCount;
  }

  /**
   * Stop scheduled cleanup
   */
  stop(): void {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
      logger.info("Scheduled cleanup jobs stopped");
    }
  }

  /**
   * Get cleanup job statistics
   */
  getStats(): CleanupJobStats {
    return { ...this.stats };
  }

  /**
   * Manually trigger cleanup job
   */
  async triggerCleanup(): Promise<{
    auditLogsCleaned: number;
    sessionsCleaned: number;
    decisionAuditsCleaned: number;
    totalCleaned: number;
    duration: number;
  }> {
    const startTime = Date.now();

    const auditLogsCleaned = await this.cleanupOldAuditLogs();
    const sessionsCleaned = await this.cleanupExpiredSessions();
    const decisionAuditsCleaned = await this.cleanupOldDecisionAudits();
    const totalCleaned =
      auditLogsCleaned + sessionsCleaned + decisionAuditsCleaned;
    const duration = Date.now() - startTime;

    // Update stats
    this.stats = {
      lastRunTime: new Date(),
      lastRunDuration: duration,
      lastRunRecordsCleaned: totalCleaned,
      totalRuns: this.stats.totalRuns + 1,
      totalRecordsCleaned: this.stats.totalRecordsCleaned + totalCleaned,
    };

    return {
      auditLogsCleaned,
      sessionsCleaned,
      decisionAuditsCleaned,
      totalCleaned,
      duration,
    };
  }
}
