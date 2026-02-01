/**
 * Health Check Controller
 *
 * Provides comprehensive health checks for Kubernetes and monitoring:
 * - Liveness probe: Is the application running?
 * - Readiness probe: Is the application ready to receive traffic?
 * - Detailed health report: Full system status
 */

import { Request, Response } from "express";
import { PrismaClient } from "@prisma/client";
import { ResilientRedisService } from "../../infrastructure/redis/ResilientRedisService";
import * as fs from "fs";
import * as path from "path";

interface CheckResult {
  name: string;
  status: "healthy" | "degraded" | "unhealthy";
  message?: string;
  latencyMs?: number;
}

interface HealthResponse {
  status: "OK" | "DEGRADED" | "ERROR";
  timestamp: string;
  uptime: number;
  checks: CheckResult[];
}

interface DetailedHealthResponse extends HealthResponse {
  version: string;
  environment: string;
  memory: NodeJS.MemoryUsage;
  disk: {
    total: number;
    available: number;
    usedPercent: number;
  };
  circuitBreaker: {
    state: string;
    failureCount: number;
    nextAttemptTime: string | null;
  };
}

export class HealthController {
  private prisma: PrismaClient;
  private redisService: ResilientRedisService;
  private startTime: Date;

  constructor(prisma: PrismaClient, redisService: ResilientRedisService) {
    this.prisma = prisma;
    this.redisService = redisService;
    this.startTime = new Date();
  }

  /**
   * Liveness Probe - Kubernetes uses this to determine if the container should be restarted
   * Returns 200 if the application is running
   */
  async liveness(req: Request, res: Response): Promise<void> {
    const uptime = process.uptime();
    const memoryUsage = process.memoryUsage();

    // Check if the application is running and not stuck
    const isResponsive =
      uptime > 0 && memoryUsage.heapUsed < 1024 * 1024 * 1024; // Less than 1GB

    if (isResponsive) {
      res.status(200).json({
        status: "OK",
        timestamp: new Date().toISOString(),
        uptime: Math.floor(uptime),
      });
    } else {
      res.status(503).json({
        status: "ERROR",
        timestamp: new Date().toISOString(),
        uptime: Math.floor(uptime),
        message: "Application is not responsive",
      });
    }
  }

  /**
   * Readiness Probe - Kubernetes uses this to determine if the container should receive traffic
   * Returns 200 only if the application can handle requests
   */
  async readiness(req: Request, res: Response): Promise<void> {
    const checks = await this.performReadinessChecks();
    const hasCriticalFailure = checks.some(
      (c) => c.status === "unhealthy" && this.isCriticalCheck(c.name),
    );
    const isReady = !hasCriticalFailure;

    const response: HealthResponse = {
      status: isReady ? "OK" : "DEGRADED",
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
      checks,
    };

    res.status(isReady ? 200 : 503).json(response);
  }

  /**
   * Detailed Health Report - Provides comprehensive system status
   */
  async detailed(req: Request, res: Response): Promise<void> {
    const checks = await this.performReadinessChecks();
    const memoryUsage = process.memoryUsage();
    const diskInfo = await this.getDiskInfo();

    const circuitMetrics = this.redisService.getCircuitMetrics();

    const overallStatus = checks.some((c) => c.status === "unhealthy")
      ? "DEGRADED"
      : "OK";

    const response: DetailedHealthResponse = {
      status: overallStatus,
      timestamp: new Date().toISOString(),
      uptime: Math.floor(process.uptime()),
      version: process.env.npm_package_version || "unknown",
      environment: process.env.NODE_ENV || "development",
      memory: memoryUsage,
      disk: diskInfo,
      circuitBreaker: {
        state: circuitMetrics.state,
        failureCount: circuitMetrics.failureCount,
        nextAttemptTime: circuitMetrics.nextAttemptTime
          ? new Date(circuitMetrics.nextAttemptTime).toISOString()
          : null,
      },
      checks,
    };

    res.status(200).json(response);
  }

  /**
   * Metrics Endpoint - Prometheus-compatible metrics
   */
  async metrics(req: Request, res: Response): Promise<void> {
    const memoryUsage = process.memoryUsage();
    const uptime = process.uptime();
    const circuitMetrics = this.redisService.getCircuitMetrics();

    const metrics = [
      `# HELP nodejs_uptime_seconds Application uptime in seconds`,
      `# TYPE nodejs_uptime_seconds gauge`,
      `nodejs_uptime_seconds ${uptime}`,
      ``,
      `# HELP nodejs_memory_heap_used_bytes Memory heap used`,
      `# TYPE nodejs_memory_heap_used_bytes gauge`,
      `nodejs_memory_heap_used_bytes ${memoryUsage.heapUsed}`,
      ``,
      `# HELP nodejs_memory_heap_total_bytes Memory heap total`,
      `# TYPE nodejs_memory_heap_total_bytes gauge`,
      `nodejs_memory_heap_total_bytes ${memoryUsage.heapTotal}`,
      ``,
      `# HELP nodejs_memory_rss_bytes Resident set size`,
      `# TYPE nodejs_memory_rss_bytes gauge`,
      `nodejs_memory_rss_bytes ${memoryUsage.rss}`,
      ``,
      `# HELP redis_circuit_breaker_state Circuit breaker state (0=closed, 1=half-open, 2=open)`,
      `# TYPE redis_circuit_breaker_state gauge`,
      `redis_circuit_breaker_state ${this.getCircuitStateValue(circuitMetrics.state)}`,
      ``,
      `# HELP redis_circuit_breaker_failures_total Number of failures`,
      `# TYPE redis_circuit_breaker_failures_total counter`,
      `redis_circuit_breaker_failures_total ${circuitMetrics.failureCount}`,
    ].join("\n");

    res.set("Content-Type", "text/plain").status(200).send(metrics);
  }

  /**
   * Live Stats - Real-time system statistics
   */
  async stats(req: Request, res: Response): Promise<void> {
    const memoryUsage = process.memoryUsage();
    const circuitMetrics = this.redisService.getCircuitMetrics();
    const fallbackStats = this.redisService.getFallbackStats();

    res.status(200).json({
      uptime: {
        seconds: process.uptime(),
        formatted: this.formatUptime(process.uptime()),
      },
      memory: {
        heapUsed: this.formatBytes(memoryUsage.heapUsed),
        heapTotal: this.formatBytes(memoryUsage.heapTotal),
        rss: this.formatBytes(memoryUsage.rss),
        external: this.formatBytes(memoryUsage.external),
      },
      redis: {
        state: circuitMetrics.state,
        failureCount: circuitMetrics.failureCount,
        fallbackCache: fallbackStats,
      },
      process: {
        pid: process.pid,
        nodeVersion: process.version,
        platform: process.platform,
      },
    });
  }

  /**
   * Perform all readiness checks
   */
  private async performReadinessChecks(): Promise<CheckResult[]> {
    return Promise.all([
      this.checkDatabase(),
      this.checkRedis(),
      this.checkDiskSpace(),
      this.checkMemory(),
    ]);
  }

  /**
   * Check database connectivity
   */
  private async checkDatabase(): Promise<CheckResult> {
    const startTime = Date.now();

    try {
      // Perform a simple query to check database connectivity
      // Use Prisma's built-in connection check
      await this.prisma.$connect();

      return {
        name: "database",
        status: "healthy",
        message: "Connected",
        latencyMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        name: "database",
        status: "unhealthy",
        message: error instanceof Error ? error.message : "Unknown error",
        latencyMs: Date.now() - startTime,
      };
    } finally {
      try {
        await this.prisma.$disconnect();
      } catch {
        // Ignore disconnect errors
      }
    }
  }

  /**
   * Check Redis connectivity
   */
  private async checkRedis(): Promise<CheckResult> {
    const startTime = Date.now();

    try {
      const isHealthy = await this.redisService.isHealthy();
      const circuitState = this.redisService.getCircuitState();

      if (isHealthy && circuitState === "CLOSED") {
        return {
          name: "redis",
          status: "healthy",
          message: `Connected (Circuit: ${circuitState})`,
          latencyMs: Date.now() - startTime,
        };
      } else if (circuitState === "HALF_OPEN") {
        return {
          name: "redis",
          status: "degraded",
          message: `Recovering (Circuit: ${circuitState})`,
          latencyMs: Date.now() - startTime,
        };
      } else {
        return {
          name: "redis",
          status: "unhealthy",
          message: `Circuit open - Redis unavailable`,
          latencyMs: Date.now() - startTime,
        };
      }
    } catch (error) {
      return {
        name: "redis",
        status: "unhealthy",
        message: error instanceof Error ? error.message : "Unknown error",
        latencyMs: Date.now() - startTime,
      };
    }
  }

  /**
   * Check available disk space
   */
  private async checkDiskSpace(): Promise<CheckResult> {
    try {
      const stats = await fs.promises.statfs(__dirname);
      const total = stats.blocks * stats.bsize;
      const available = stats.bfree * stats.bsize;
      const usedPercent = ((total - available) / total) * 100;
      const threshold = 10; // 10% threshold

      if (available < threshold) {
        return {
          name: "disk",
          status: "unhealthy",
          message: `Low disk space: ${usedPercent.toFixed(1)}% used`,
        };
      } else if (available < threshold * 3) {
        return {
          name: "disk",
          status: "degraded",
          message: `Warning: ${usedPercent.toFixed(1)}% disk used`,
        };
      }

      return {
        name: "disk",
        status: "healthy",
        message: `${usedPercent.toFixed(1)}% used`,
      };
    } catch (error) {
      return {
        name: "disk",
        status: "degraded",
        message: "Could not check disk space",
      };
    }
  }

  /**
   * Check memory usage
   */
  private checkMemory(): CheckResult {
    const memoryUsage = process.memoryUsage();
    const heapUsedPercent =
      (memoryUsage.heapUsed / memoryUsage.heapTotal) * 100;
    const threshold = 90; // 90% threshold

    if (heapUsedPercent > threshold) {
      return {
        name: "memory",
        status: "unhealthy",
        message: `Heap usage: ${heapUsedPercent.toFixed(1)}%`,
      };
    } else if (heapUsedPercent > threshold * 0.8) {
      return {
        name: "memory",
        status: "degraded",
        message: `Heap usage: ${heapUsedPercent.toFixed(1)}%`,
      };
    }

    return {
      name: "memory",
      status: "healthy",
      message: `Heap usage: ${heapUsedPercent.toFixed(1)}%`,
    };
  }

  /**
   * Get disk information
   */
  private async getDiskInfo(): Promise<{
    total: number;
    available: number;
    usedPercent: number;
  }> {
    try {
      const stats = await fs.promises.statfs(__dirname);
      const total = stats.blocks * stats.bsize;
      const available = stats.bfree * stats.bsize;
      const usedPercent = ((total - available) / total) * 100;

      return {
        total,
        available,
        usedPercent,
      };
    } catch {
      return {
        total: 0,
        available: 0,
        usedPercent: 0,
      };
    }
  }

  /**
   * Check if a check is critical
   */
  private isCriticalCheck(name: string): boolean {
    return name === "database";
  }

  /**
   * Convert circuit state to numeric value for metrics
   */
  private getCircuitStateValue(state: string): number {
    switch (state) {
      case "CLOSED":
        return 0;
      case "HALF_OPEN":
        return 1;
      case "OPEN":
        return 2;
      default:
        return -1;
    }
  }

  /**
   * Format bytes to human readable string
   */
  private formatBytes(bytes: number): string {
    if (bytes === 0) return "0 B";
    const k = 1024;
    const sizes = ["B", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
  }

  /**
   * Format uptime to human readable string
   */
  private formatUptime(seconds: number): string {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    const parts = [];
    if (days > 0) parts.push(`${days}d`);
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    parts.push(`${secs}s`);

    return parts.join(" ");
  }
}
