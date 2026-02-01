/**
 * Enforcement Module Index
 *
 * Exports all enforcement components including middleware, guards,
 * and permission checking utilities.
 */

// IAM Middleware exports
export {
  IAMMiddleware,
  IAMRequestContext,
  IAMMiddlewareConfig,
  ContextExtractors,
  hasRole,
  hasAnyRole,
  hasAllRoles,
  extractTenantId,
} from "./Middleware";

// Legacy exports for backward compatibility
export {
  createAuthorizationMiddleware,
  requireAll,
  requireAny,
  AuthorizationRequestExt,
  AuthorizationMiddlewareOptions,
} from "./Middleware";

// Authorization Guard exports
export {
  AuthorizationGuard,
  AuthorizationGuard as Guard,
  GuardOptions,
  PermissionChecker,
  AuthorizationDeniedError,
  createGuard,
  createPermissionChecker,
} from "./Guard";

// Legacy guard exports for backward compatibility
export { Guard as LegacyGuard, GuardConfig } from "./Guard";
