import { Request, Response, NextFunction } from "express";
import { SecurityUtils } from "../security";
import { AppError, ErrorCode } from "../errors/AppError";
import { structuredLogger } from "../../core/logger/structuredLogger";
import { AuditLoggerService } from "../../infrastructure/services/AuditLoggerService";

export interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    email: string;
    roles: string[];
    tenantId: string;
  };
  tenantId?: string;
  correlationId?: string;
}

// Get audit logger instance
const auditLogger = AuditLoggerService.getInstance();

export const authenticateToken = (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction,
) => {
  try {
    const authHeader = req.headers.authorization;
    const token = SecurityUtils.extractTokenFromHeader(authHeader);
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get("User-Agent");
    const correlationId = req.correlationId;

    if (!token) {
      // Log missing token as security event
      auditLogger.logAuth(
        "LOGIN_FAILED",
        {
          userId: undefined,
          tenantId: req.tenantId || "unknown",
          ipAddress,
          userAgent,
          correlationId,
        },
        {
          outcome: "FAILURE",
          errorMessage: "Token missing from request",
        },
      );

      throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
    }

    const decoded = SecurityUtils.verifyAccessToken(token);
    req.user = {
      id: decoded.userId,
      email: decoded.email,
      roles: decoded.roles,
      tenantId: decoded.tenantId,
    };
    req.tenantId = decoded.tenantId;

    // Log successful token verification
    structuredLogger.logAuth("TOKEN_VERIFIED", "SUCCESS", {
      userId: decoded.userId,
      tenantId: decoded.tenantId,
      ipAddress,
      userAgent,
      correlationId,
    });

    next();
  } catch (error) {
    // Log authentication failure
    const ipAddress = req.ip || req.connection.remoteAddress;
    const userAgent = req.get("User-Agent");
    const correlationId = req.correlationId;

    if (error instanceof AppError) {
      if (error.code === ErrorCode.TOKEN_EXPIRED) {
        auditLogger.logAuth(
          "LOGIN_FAILED",
          {
            userId: req.user?.id,
            tenantId: req.tenantId || "unknown",
            ipAddress,
            userAgent,
            correlationId,
          },
          {
            outcome: "FAILURE",
            errorMessage: "Token expired",
          },
        );
      } else if (error.code === ErrorCode.TOKEN_INVALID) {
        auditLogger.logAuth(
          "LOGIN_FAILED",
          {
            userId: undefined,
            tenantId: req.tenantId || "unknown",
            ipAddress,
            userAgent,
            correlationId,
          },
          {
            outcome: "FAILURE",
            errorMessage: "Invalid token",
          },
        );
      }
    }

    structuredLogger.error("Authentication failed", error as Error, {
      module: "auth",
      action: "authenticate",
      userId: req.user?.id,
      tenantId: req.tenantId,
      metadata: {
        ip: req.ip,
        path: req.path,
      },
    });

    if (error instanceof AppError) {
      return res.status(error.statusCode).json({
        error: error.message,
        code: error.code,
      });
    }
    res.status(403).json({ error: "Authentication failed" });
  }
};

/**
 * Authorization middleware that checks user permissions
 */
export const authorize = (requiredPermission?: string) => {
  return (req: AuthenticatedRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw AppError.fromErrorCode(ErrorCode.INSUFFICIENT_PERMISSIONS);
      }

      const ipAddress = req.ip || req.connection.remoteAddress;
      const userAgent = req.get("User-Agent");
      const correlationId = req.correlationId;

      // If no specific permission is required, just check that user is authenticated
      if (!requiredPermission) {
        return next();
      }

      // Check if user has the required permission (simplified check)
      // In a real implementation, this would use the PolicyEngine
      const hasPermission = req.user.roles.some(
        (role) => role.includes(requiredPermission) || role === "admin",
      );

      if (!hasPermission) {
        auditLogger.logAuthorization(
          "PERMISSION_DENIED",
          requiredPermission,
          {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            ipAddress,
            userAgent,
            correlationId,
          },
          {
            outcome: "FAILURE",
            details: {
              userRoles: req.user.roles,
              requiredPermission,
              reason: `Missing required permission: ${requiredPermission}`,
            },
          },
        );

        structuredLogger.logAuthorization(
          "PERMISSION_DENIED",
          requiredPermission,
          "FAILURE",
          {
            userId: req.user.id,
            tenantId: req.user.tenantId,
            ipAddress,
            userAgent,
            reason: `Missing required permission: ${requiredPermission}`,
          },
        );

        return res.status(403).json({
          error: "Forbidden",
          message: `Missing required permission: ${requiredPermission}`,
        });
      }

      next();
    } catch (error) {
      structuredLogger.error("Authorization failed", error as Error, {
        module: "authorization",
        action: "authorize",
        userId: req.user?.id,
        tenantId: req.tenantId,
      });

      if (error instanceof AppError) {
        return res.status(error.statusCode).json({
          error: error.message,
          code: error.code,
        });
      }
      res.status(403).json({ error: "Authorization failed" });
    }
  };
};
