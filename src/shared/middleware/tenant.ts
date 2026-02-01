import { Request, Response, NextFunction } from "express";
import { PrismaClient } from "@prisma/client";
import { logger } from "../logger";

export interface TenantRequest extends Request {
  tenantId?: string;
  tenant?: {
    id: string;
    name: string;
    status: string;
    parentId?: string;
  };
}

/**
 * Tenant validation middleware
 * Validates tenant ID, checks tenant status, and enforces tenant boundaries
 */
export const validateTenant = (prisma: PrismaClient) => {
  return async (req: TenantRequest, res: Response, next: NextFunction) => {
    const tenantId =
      (req.headers["x-tenant-id"] as string) || (req.query.tenantId as string);

    if (!tenantId) {
      return res.status(400).json({ error: "Tenant ID is required" });
    }

    try {
      // Fetch tenant from database
      const tenant = await (prisma as any).tenant.findUnique({
        where: { id: tenantId },
      });

      if (!tenant) {
        logger.warn("Tenant not found", { tenantId });
        return res.status(404).json({ error: "Tenant not found" });
      }

      // Check tenant status
      if (tenant.status !== "ACTIVE") {
        logger.warn("Tenant is not active", {
          tenantId,
          status: tenant.status,
        });
        return res.status(403).json({
          error: `Tenant is ${tenant.status}`,
          status: tenant.status,
        });
      }

      // Check if tenant is terminated
      if (tenant.terminatedAt && new Date(tenant.terminatedAt) <= new Date()) {
        logger.warn("Tenant is terminated", {
          tenantId,
          terminatedAt: tenant.terminatedAt,
        });
        return res.status(403).json({
          error: "Tenant has been terminated",
          terminatedAt: tenant.terminatedAt,
        });
      }

      // Attach tenant to request
      req.tenantId = tenantId;
      req.tenant = {
        id: tenant.id,
        name: tenant.name,
        status: tenant.status,
        parentId: tenant.parentId || undefined,
      };

      next();
    } catch (error) {
      logger.error("Error validating tenant", { tenantId, error });
      return res.status(500).json({ error: "Internal server error" });
    }
  };
};

/**
 * Tenant boundary enforcement middleware
 * Ensures that requests cannot access resources from other tenants
 */
export const enforceTenantBoundary = () => {
  return (req: TenantRequest, res: Response, next: NextFunction) => {
    const requestTenantId = req.tenantId;
    const resourceTenantId = req.headers["x-resource-tenant-id"] as string;

    // If resource tenant ID is specified, it must match request tenant ID
    if (resourceTenantId && resourceTenantId !== requestTenantId) {
      logger.warn("Tenant boundary violation detected", {
        requestTenantId,
        resourceTenantId,
        path: req.path,
        method: req.method,
      });

      return res.status(403).json({
        error: "Tenant boundary violation",
        message: "Cannot access resources from another tenant",
      });
    }

    next();
  };
};

/**
 * Extract tenant ID from request
 * @deprecated Use validateTenant middleware instead
 */
export const extractTenant = (
  req: TenantRequest,
  res: Response,
  next: NextFunction,
) => {
  const tenantId =
    (req.headers["x-tenant-id"] as string) || (req.query.tenantId as string);

  if (!tenantId) {
    return res.status(400).json({ error: "Tenant ID is required" });
  }

  req.tenantId = tenantId;
  next();
};
