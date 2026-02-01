/**
 * AuthController - HTTP Request Handlers
 *
 * This controller handles all authentication-related HTTP requests:
 * - POST /auth/register - User registration
 * - POST /auth/login - User login
 * - POST /auth/refresh - Token refresh
 * - POST /auth/logout - Logout current session
 * - POST /auth/logout-all - Logout from all sessions
 * - POST /auth/forgot-password - Initiate password reset
 * - POST /auth/reset-password - Complete password reset
 * - GET /auth/me - Get current user
 *
 * Security Considerations:
 * - All endpoints validate input using Zod schemas
 * - Sensitive operations are rate limited
 * - Audit logging for all operations
 * - Proper error handling without information leakage
 */

import { Request, Response } from "express";
import {
  AuthService,
  RegisterUserDto,
  LoginUserDto,
} from "./services/AuthService";
import { PasswordService } from "./services/PasswordService";
import { TokenService } from "./services/TokenService";
import { DeviceInfo } from "../../infrastructure/redis/SessionStore";
import { AppError, ErrorCode } from "../../shared/errors/AppError";
import { logger } from "../../shared/logger";
import { z } from "zod";

/**
 * Extended Request with user information
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
 * Generic response helper
 */
interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    message: string;
    code?: string;
  };
}

/**
 * AuthController
 *
 * All methods follow the same pattern:
 * 1. Extract and validate input
 * 2. Call appropriate service method
 * 3. Return standardized response
 * 4. Handle errors appropriately
 */
export class AuthController {
  constructor(
    private authService: AuthService,
    private passwordService: PasswordService,
    private tokenService: TokenService,
  ) {}

  /**
   * POST /auth/register
   * Register a new user
   *
   * Request body:
   * - email: string (valid email)
   * - password: string (min 12 chars)
   * - firstName: string
   * - lastName: string
   * - tenantId?: string
   */
  async register(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, firstName, lastName, tenantId } =
        req.body as RegisterUserDto;

      const metadata: DeviceInfo = {
        userAgent: req.get("User-Agent") || "unknown",
        ip: this.getClientIp(req),
        deviceId: req.cookies?.deviceId,
      };

      const result = await this.authService.register(
        { email, password, firstName, lastName, tenantId },
        metadata,
      );

      this.sendSuccess(res, 201, {
        user: result.user,
        tokens: result.tokens,
        sessionId: result.sessionId,
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/login
   * Authenticate user with email/password
   *
   * Request body:
   * - email: string (valid email)
   * - password: string
   * - tenantId?: string
   */
  async login(req: Request, res: Response): Promise<void> {
    try {
      const { email, password, tenantId } = req.body as LoginUserDto;

      const metadata: DeviceInfo = {
        userAgent: req.get("User-Agent") || "unknown",
        ip: this.getClientIp(req),
        deviceId: req.cookies?.deviceId,
      };

      const result = await this.authService.login(
        { email, password, tenantId },
        metadata,
      );

      // Set secure cookies for tokens
      this.setTokenCookies(res, result.tokens);

      this.sendSuccess(res, 200, {
        user: result.user,
        tokens: {
          accessToken: result.tokens.accessToken,
          expiresIn: result.tokens.expiresIn,
          tokenType: result.tokens.tokenType,
        },
        sessionId: result.sessionId,
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   *
   * Request body:
   * - refreshToken: string
   */
  async refresh(req: Request, res: Response): Promise<void> {
    try {
      const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;

      if (!refreshToken) {
        throw AppError.fromErrorCode(
          ErrorCode.TOKEN_MISSING,
          "Refresh token is required",
        );
      }

      const metadata: DeviceInfo = {
        userAgent: req.get("User-Agent") || "unknown",
        ip: this.getClientIp(req),
      };

      const result = await this.authService.refreshTokens(
        refreshToken,
        metadata,
      );

      // Set secure cookies for new tokens
      this.setTokenCookies(res, result);

      this.sendSuccess(res, 200, {
        tokens: result,
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/logout
   * Logout current session
   *
   * Requires authentication
   */
  async logout(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      const sessionId = req.sessionId || req.body.sessionId;

      const metadata: DeviceInfo = {
        userAgent: req.get("User-Agent") || "unknown",
        ip: this.getClientIp(req),
      };

      await this.authService.logout(userId, sessionId, metadata);

      // Clear token cookies
      this.clearTokenCookies(res);

      this.sendSuccess(res, 200, { success: true });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/logout-all
   * Logout from all sessions
   *
   * Requires authentication
   */
  async logoutAll(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      const metadata: DeviceInfo = {
        userAgent: req.get("User-Agent") || "unknown",
        ip: this.getClientIp(req),
      };

      await this.authService.logoutAll(userId, metadata);

      // Clear all token cookies
      this.clearTokenCookies(res);

      this.sendSuccess(res, 200, { success: true });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/forgot-password
   * Initiate password reset
   *
   * Request body:
   * - email: string (valid email)
   */
  async forgotPassword(req: Request, res: Response): Promise<void> {
    try {
      const { email, tenantId } = req.body;

      // Validate email
      if (!z.string().email().safeParse(email).success) {
        throw AppError.fromErrorCode(ErrorCode.INVALID_EMAIL);
      }

      await this.authService.initiatePasswordReset(email, tenantId);

      // Always return success even if email doesn't exist
      this.sendSuccess(res, 200, {
        message:
          "If an account exists with that email, a password reset link has been sent",
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/reset-password
   * Reset password with token
   *
   * Request body:
   * - token: string (reset token)
   * - password: string (min 12 chars)
   */
  async resetPassword(req: Request, res: Response): Promise<void> {
    try {
      const { token, password, tenantId } = req.body;

      if (!token || !password) {
        throw AppError.fromErrorCode(
          ErrorCode.REQUIRED_FIELD_MISSING,
          "Token and new password are required",
        );
      }

      // Validate password strength before DB call
      const strengthResult = this.passwordService.validateStrength(password);
      if (!strengthResult.isValid) {
        throw AppError.fromErrorCode(
          ErrorCode.INVALID_PASSWORD,
          `Password does not meet requirements: ${strengthResult.errors.join(", ")}`,
        );
      }

      await this.authService.resetPassword(token, password, tenantId);

      this.sendSuccess(res, 200, {
        message: "Password has been reset successfully",
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/change-password
   * Change password (authenticated)
   *
   * Requires authentication
   *
   * Request body:
   * - currentPassword: string
   * - newPassword: string (min 12 chars)
   */
  async changePassword(
    req: AuthenticatedRequest,
    res: Response,
  ): Promise<void> {
    try {
      const userId = req.user?.id;
      if (!userId) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      const { currentPassword, newPassword, tenantId } = req.body;
      const resolvedTenantId = tenantId || req.user?.tenantId || "default";

      if (!currentPassword || !newPassword) {
        throw AppError.fromErrorCode(
          ErrorCode.REQUIRED_FIELD_MISSING,
          "Current and new password are required",
        );
      }

      await this.authService.changePassword(
        userId,
        currentPassword,
        newPassword,
        resolvedTenantId,
      );

      this.sendSuccess(res, 200, {
        message: "Password has been changed successfully",
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * GET /auth/me
   * Get current user
   *
   * Requires authentication
   */
  async me(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const user = req.user;
      if (!user) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_MISSING);
      }

      // Get user details from request (already decoded from token)
      this.sendSuccess(res, 200, {
        user: {
          id: user.id,
          email: user.email,
          roles: user.roles,
          tenantId: user.tenantId,
        },
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * POST /auth/verify-token
   * Verify if current access token is valid
   *
   * Requires authentication
   */
  async verifyToken(req: AuthenticatedRequest, res: Response): Promise<void> {
    try {
      const user = req.user;
      if (!user) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_INVALID);
      }

      this.sendSuccess(res, 200, {
        valid: true,
        user,
      });
    } catch (error) {
      this.handleError(res, error);
    }
  }

  /**
   * Get client IP address
   */
  private getClientIp(req: Request): string {
    return (
      req.ip ||
      req.get("X-Forwarded-For")?.split(",")[0] ||
      req.connection?.remoteAddress ||
      "unknown"
    );
  }

  /**
   * Set secure HTTP-only cookies for tokens
   */
  private setTokenCookies(
    res: Response,
    tokens: { accessToken: string; refreshToken: string; expiresIn: number },
  ): void {
    const cookieOptions = {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict" as const,
      maxAge: tokens.expiresIn * 1000,
    };

    // Set access token cookie
    res.cookie("accessToken", tokens.accessToken, {
      ...cookieOptions,
      maxAge: tokens.expiresIn * 1000, // 15 minutes
    });

    // Set refresh token cookie (longer)
    res.cookie("refreshToken", tokens.refreshToken, {
      ...cookieOptions,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
  }

  /**
   * Clear token cookies
   */
  private clearTokenCookies(res: Response): void {
    res.clearCookie("accessToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
    res.clearCookie("refreshToken", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
    });
  }

  /**
   * Send success response
   */
  private sendSuccess<T>(res: Response, statusCode: number, data: T): void {
    const response: ApiResponse<T> = {
      success: true,
      data,
    };
    res.status(statusCode).json(response);
  }

  /**
   * Handle error response
   */
  private handleError(res: Response, error: any): void {
    if (error instanceof AppError) {
      const response: ApiResponse = {
        success: false,
        error: {
          message: error.message,
          code: error.code,
        },
      };
      res.status(error.statusCode).json(response);
      return;
    }

    logger.error("Unexpected error in AuthController", { error });
    const response: ApiResponse = {
      success: false,
      error: {
        message: "An unexpected error occurred",
        code: ErrorCode.INTERNAL_SERVER_ERROR,
      },
    };
    res.status(500).json(response);
  }
}

export default AuthController;
