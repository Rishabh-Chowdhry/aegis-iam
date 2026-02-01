/**
 * Tenant Context Legacy Exports
 *
 * Maintains backward compatibility with existing code.
 * These exports are deprecated and will be removed in future versions.
 */

import { Request } from "express";

/**
 * Tenant Context Interface (Legacy)
 * @deprecated Use TenantContext from TenantContext.ts instead
 */
export interface ITenantContext {
  tenantId: string;
  requestId: string;
  timestamp: string;
}

/**
 * Tenant Context Factory (Legacy)
 * @deprecated Use TenantContextManager from TenantContext.ts instead
 */
export class TenantContextFactory {
  /**
   * Create tenant context from Express request
   */
  createFromRequest(req: Request): ITenantContext {
    return {
      tenantId: this.getTenantId(req),
      requestId: this.getRequestId(req),
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get tenant ID from request
   */
  private getTenantId(req: Request): string {
    // Check header first
    const headerTenant = req.headers["x-tenant-id"];
    if (typeof headerTenant === "string") {
      return headerTenant;
    }

    // Check JWT token
    const tokenTenant = (req as any).user?.tenantId;
    if (tokenTenant) {
      return tokenTenant;
    }

    // Check query parameter
    const queryTenant = req.query.tenantId;
    if (typeof queryTenant === "string") {
      return queryTenant;
    }

    throw new Error("Tenant ID not found in request");
  }

  /**
   * Get request ID from request
   */
  private getRequestId(req: Request): string {
    const headerRequestId = req.headers["x-request-id"];
    if (typeof headerRequestId === "string") {
      return headerRequestId;
    }

    return `req_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`;
  }
}
