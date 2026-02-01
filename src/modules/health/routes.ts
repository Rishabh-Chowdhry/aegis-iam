/**
 * Health Check Routes
 *
 * Provides health check endpoints for Kubernetes and monitoring:
 * - GET /health/live - Liveness probe
 * - GET /health/ready - Readiness probe
 * - GET /health - Detailed health check
 * - GET /health/stats - Real-time statistics
 * - GET /health/metrics - Prometheus metrics
 */

import { Router, Request, Response } from "express";
import { HealthController } from "./health.controller";

export function createHealthRoutes(healthController: HealthController): Router {
  const router = Router();

  /**
   * GET /health/live - Liveness probe
   * Kubernetes uses this to determine if the container should be restarted
   */
  router.get("/live", (req: Request, res: Response) => {
    healthController.liveness(req, res);
  });

  /**
   * GET /health/ready - Readiness probe
   * Kubernetes uses this to determine if the container should receive traffic
   */
  router.get("/ready", (req: Request, res: Response) => {
    healthController.readiness(req, res);
  });

  /**
   * GET /health - Detailed health check
   * Provides comprehensive system status
   */
  router.get("/", (req: Request, res: Response) => {
    healthController.detailed(req, res);
  });

  /**
   * GET /health/stats - Real-time statistics
   * Provides real-time system statistics
   */
  router.get("/stats", (req: Request, res: Response) => {
    healthController.stats(req, res);
  });

  /**
   * GET /health/metrics - Prometheus metrics
   * Provides metrics in Prometheus format
   */
  router.get("/metrics", (req: Request, res: Response) => {
    healthController.metrics(req, res);
  });

  return router;
}
