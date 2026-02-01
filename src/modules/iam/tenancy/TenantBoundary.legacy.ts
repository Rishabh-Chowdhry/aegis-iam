/**
 * Tenant Boundary Legacy Exports
 *
 * Maintains backward compatibility with existing code.
 * These exports are deprecated and will be removed in future versions.
 */

import { AuthorizationRequest } from "../policy/models/types";

/**
 * Tenant Boundary Interface (Legacy)
 * @deprecated Use TenantBoundaryEnforcer from TenantBoundary.ts instead
 */
export interface ITenantBoundary {
  enforce(request: AuthorizationRequest): Promise<void>;
}

/**
 * Tenant Boundary Implementation (Legacy)
 * @deprecated Use TenantBoundaryEnforcer from TenantBoundary.ts instead
 */
export class TenantBoundary implements ITenantBoundary {
  /**
   * Enforce tenant isolation for authorization request
   * Throws TenantIsolationError if violation detected
   */
  async enforce(request: AuthorizationRequest): Promise<void> {
    // 1. Verify tenant ID is present
    if (!request.subject.tenantId) {
      throw new TenantIsolationError("Subject tenant ID is required");
    }

    if (!request.resource.tenantId) {
      throw new TenantIsolationError("Resource tenant ID is required");
    }

    // 2. Check for cross-tenant access
    if (request.subject.tenantId !== request.resource.tenantId) {
      throw new TenantIsolationError(
        `Cross-tenant access denied: Subject tenant ${request.subject.tenantId} ` +
          `cannot access resource in tenant ${request.resource.tenantId}`,
      );
    }
  }
}

/**
 * Tenant Isolation Error
 */
export class TenantIsolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TenantIsolationError";
  }
}
