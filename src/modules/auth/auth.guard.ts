/**
 * AuthGuard - Authentication Middleware
 *
 * This module provides authentication guards for protecting routes:
 * - JWT token verification
 * - Token blacklisting check
 * - User information extraction
 *
 * Security Considerations:
 * - Verifies token signature
 * - Checks token blacklist
 * - Extracts user information for downstream handlers
 */

import { Request, Response, NextFunction } from "express";
import { TokenService } from "./services/TokenService";
import { SessionStore } from "../../infrastructure/redis/SessionStore";
import { AppError, ErrorCode } from "../../shared/errors/AppError";
import { logger } from "../../shared/logger";

/**
 * Extended Request with authenticated user
 */
export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    tenantId: string;
    roles: string[];
  };
  sessionId?: string;
  jti?: string;
}

/**
 * AuthGuard configuration
 */
export interface AuthGuardConfig {
  /** Optional: Required roles for access */
  requiredRoles?: string[];
  /** Optional: Required permissions for access */
  requiredPermissions?: string[];
  /** Whether to allow inactive users (default: false) */
  allowInactiveUsers?: boolean;
}

/**
 * AuthGuard class for protecting routes
 */
export class AuthGuard {
  private tokenService: TokenService;
  private sessionStore: SessionStore;
  private config: AuthGuardConfig;

  constructor(
    tokenService?: TokenService,
    sessionStore?: SessionStore,
    config?: AuthGuardConfig,
  ) {
    this.tokenService = tokenService || TokenService.getInstance();
    this.sessionStore =
      sessionStore ||
      new SessionStore({
        redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
      });
    this.config = config || {};
  }

  /**
   * Create Express middleware for authentication
   */
  middleware(config?: AuthGuardConfig) {
    return async (
      req: AuthenticatedRequest,
      res: Response,
      next: NextFunction,
    ): Promise<void> => {
      try {
        const result = await this.canActivate(req);

        if (!result.success) {
          res.status(401).json({
            success: false,
            error: {
              message: result.error || "Authentication required",
              code: result.errorCode || ErrorCode.TOKEN_INVALID,
            },
          });
          return;
        }

        // Attach user info to request
        if (result.user) {
          req.user = result.user;
        }
        if (result.sessionId) {
          req.sessionId = result.sessionId;
        }
        if (result.jti) {
          req.jti = result.jti;
        }

        // Check role requirements if configured
        if (config?.requiredRoles && config.requiredRoles.length > 0) {
          const userRoles = result.user?.roles || [];
          const hasRequiredRole = config.requiredRoles.some((role) =>
            userRoles.includes(role),
          );

          if (!hasRequiredRole) {
            logger.warn("Access denied: insufficient roles", {
              userId: result.user?.id,
              requiredRoles: config.requiredRoles,
              userRoles,
            });

            res.status(403).json({
              success: false,
              error: {
                message: "Insufficient permissions",
                code: ErrorCode.INSUFFICIENT_PERMISSIONS,
              },
            });
            return;
          }
        }

        next();
      } catch (error) {
        logger.error("Auth guard error", { error });

        if (error instanceof AppError) {
          res.status(error.statusCode).json({
            success: false,
            error: {
              message: error.message,
              code: error.code,
            },
          });
          return;
        }

        res.status(401).json({
          success: false,
          error: {
            message: "Authentication failed",
            code: ErrorCode.TOKEN_INVALID,
          },
        });
      }
    };
  }

  /**
   * Check if request can be activated (authenticated)
   */
  async canActivate(req: AuthenticatedRequest): Promise<{
    success: boolean;
    user?: AuthenticatedRequest["user"];
    sessionId?: string;
    jti?: string;
    error?: string;
    errorCode?: ErrorCode;
  }> {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return {
        success: false,
        error: "No token provided",
        errorCode: ErrorCode.TOKEN_MISSING,
      };
    }

    const token = authHeader.substring(7);

    try {
      // Verify access token
      const payload = await this.tokenService.verifyAccessToken(token);

      // Check if token is blacklisted
      const isBlacklisted = await this.sessionStore.isAccessTokenBlacklisted(
        payload.jti,
      );
      if (isBlacklisted) {
        return {
          success: false,
          error: "Token has been revoked",
          errorCode: ErrorCode.TOKEN_INVALID,
        };
      }

      // Get session info from refresh token store
      const sessionData = await this.sessionStore.getRefreshToken(payload.jti);

      return {
        success: true,
        user: {
          id: payload.sub,
          email: payload.email,
          tenantId: payload.tenantId,
          roles: payload.roles,
        },
        sessionId: sessionData?.sessionId,
        jti: payload.jti,
      };
    } catch (error) {
      if (error instanceof AppError) {
        return {
          success: false,
          error: error.message,
          errorCode: error.code,
        };
      }

      logger.error("Token verification failed", { error });
      return {
        success: false,
        error: "Invalid token",
        errorCode: ErrorCode.TOKEN_INVALID,
      };
    }
  }

  /**
   * Create a guard that requires specific roles
   */
  requireRoles(...roles: string[]) {
    return this.middleware({ requiredRoles: roles });
  }

  /**
   * Create a guard that requires specific permissions
   */
  requirePermissions(...permissions: string[]) {
    return this.middleware({ requiredPermissions: permissions });
  }

  /**
   * Create a guard for admin-only routes
   */
  adminOnly() {
    return this.requireRoles("ADMIN", "SUPER_ADMIN");
  }

  /**
   * Create a guard for authenticated routes
   */
  authenticated() {
    return this.middleware();
  }
}

/**
 * Default auth guard instance
 */
export const authGuard = new AuthGuard();

/**
 * Higher-order function for creating protected route handlers
 */
export function withAuth(
  handler: (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction,
  ) => Promise<void>,
  config?: AuthGuardConfig,
) {
  const guard = new AuthGuard(undefined, undefined, config);

  return async (
    req: Request,
    res: Response,
    next: NextFunction,
  ): Promise<void> => {
    const authResult = await guard.canActivate(req as AuthenticatedRequest);

    if (!authResult.success) {
      res.status(401).json({
        success: false,
        error: {
          message: authResult.error || "Authentication required",
          code: authResult.errorCode || ErrorCode.TOKEN_INVALID,
        },
      });
      return;
    }

    // Attach user info to request
    const authReq = req as AuthenticatedRequest;
    authReq.user = authResult.user;
    authReq.sessionId = authResult.sessionId;
    authReq.jti = authResult.jti;

    await handler(authReq, res, next);
  };
}

export default AuthGuard;
