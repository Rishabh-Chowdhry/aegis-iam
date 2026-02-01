/**
 * Tenancy Module Index
 *
 * Enterprise-grade multi-tenant context management and boundary enforcement.
 * Exports all tenant-related interfaces, types, and classes.
 */

// Tenant Context exports from TenantContext.ts
export {
  TenantContextManager,
  TenantContext,
  TenantConfig,
  TenantLifecycle,
  TenantSettings,
  TenantLimits,
  TenantFeatures,
  PasswordPolicy,
  TenantStatus,
  RequestScope,
  ValidationResult,
  TenantContextError,
  TenantCacheService,
  createTenantContextMiddleware,
  getTenantContext,
  getTenantId,
} from "./TenantContext";

// Legacy exports for backward compatibility
export { TenantContextFactory, ITenantContext } from "./TenantContext.legacy";

// Tenant Boundary exports from TenantBoundary.ts
export {
  TenantBoundaryEnforcer,
  BoundaryViolation,
  BoundaryResult,
  CrossTenantAccessResult,
  AuditInfo,
  BoundaryConfig,
  ViolationType,
  ViolationSeverity,
  SubjectWithTenant,
  TenantScopedResource,
  BoundaryContext,
  TenantBoundaryError,
  createTenantBoundaryMiddleware,
} from "./TenantBoundary";

// Legacy exports for backward compatibility
export {
  TenantBoundary,
  TenantIsolationError,
  ITenantBoundary,
} from "./TenantBoundary.legacy";
