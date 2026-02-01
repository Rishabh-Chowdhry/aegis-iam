import { Request, Response, NextFunction } from "express";
import {
  AuthenticatedRequest,
  authenticateToken,
} from "../../shared/middleware/auth";
import { AppError, ErrorCode } from "../../shared/errors/AppError";
import { logger } from "../../shared/logger";

export interface PermissionGuardOptions {
  permissions?: string[];
  roles?: string[];
  requireAllPermissions?: boolean; // If true, user must have ALL permissions; if false, ANY permission
  requireAllRoles?: boolean; // If true, user must have ALL roles; if false, ANY role
}

/**
 * Middleware to check if user has required permissions
 */
export const requirePermissions = (options: PermissionGuardOptions) => {
  return async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ) => {
    try {
      if (!req.user) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      const {
        permissions = [],
        roles = [],
        requireAllPermissions = false,
        requireAllRoles = false,
      } = options;

      // Check roles
      if (roles.length > 0) {
        const hasRequiredRoles = requireAllRoles
          ? roles.every((role) => req.user!.roles.includes(role))
          : roles.some((role) => req.user!.roles.includes(role));

        if (!hasRequiredRoles) {
          logger.warn("Access denied: insufficient roles", {
            userId: req.user.id,
            requiredRoles: roles,
            userRoles: req.user.roles,
            requireAll: requireAllRoles,
          });
          throw AppError.fromErrorCode(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            "Insufficient roles for this action",
          );
        }
      }

      // For now, permissions check is simplified
      // In a full implementation, this would check against a permission service
      // that resolves user roles to permissions
      if (permissions.length > 0) {
        // Simplified check: assume users with roles have permissions
        // This should be replaced with proper permission resolution
        const hasPermissions = req.user.roles.length > 0;

        if (!hasPermissions) {
          logger.warn("Access denied: insufficient permissions", {
            userId: req.user.id,
            requiredPermissions: permissions,
            userRoles: req.user.roles,
          });
          throw AppError.fromErrorCode(
            ErrorCode.INSUFFICIENT_PERMISSIONS,
            "Insufficient permissions for this action",
          );
        }
      }

      next();
    } catch (error) {
      if (error instanceof AppError) {
        return res.status(error.statusCode).json({
          error: error.message,
          code: error.code,
        });
      }
      res.status(500).json({ error: "Authorization check failed" });
    }
  };
};

/**
 * Middleware to check if user owns the resource or has admin permissions
 */
export const requireOwnershipOrAdmin = (
  resourceUserIdField: string = "userId",
) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      const resourceUserId =
        req.params[resourceUserIdField] || req.body[resourceUserIdField];
      const isOwner = req.user.id === resourceUserId;
      const isAdmin =
        req.user.roles.includes("admin") ||
        req.user.roles.includes("super_admin");

      if (!isOwner && !isAdmin) {
        logger.warn("Access denied: not owner or admin", {
          userId: req.user.id,
          resourceUserId,
          userRoles: req.user.roles,
        });
        throw AppError.fromErrorCode(
          ErrorCode.INSUFFICIENT_PERMISSIONS,
          "Access denied: not owner or admin",
        );
      }

      next();
    } catch (error) {
      if (error instanceof AppError) {
        return res.status(error.statusCode).json({
          error: error.message,
          code: error.code,
        });
      }
      res.status(500).json({ error: "Ownership check failed" });
    }
  };
};

/**
 * Combined auth middleware: authenticate + authorize
 */
export const authGuard = (options: PermissionGuardOptions = {}) => {
  return [authenticateToken, requirePermissions(options)];
};

/**
 * Admin-only guard
 */
export const adminGuard = authGuard({
  roles: ["admin", "super_admin"],
  requireAllRoles: false,
});

/**
 * Super admin-only guard
 */
export const superAdminGuard = authGuard({
  roles: ["super_admin"],
  requireAllRoles: true,
});
