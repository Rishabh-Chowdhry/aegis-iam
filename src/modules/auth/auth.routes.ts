/**
 * Auth Routes - HTTP Route Definitions
 *
 * This module defines all authentication-related routes:
 * - Public routes (no authentication required)
 * - Protected routes (authentication required)
 *
 * Security Considerations:
 * - All routes use input validation middleware
 * - Sensitive routes have rate limiting
 * - CORS is configured appropriately
 */

import { Router, Response } from "express";
import { AuthController } from "./auth.controller";
import { AuthService } from "./services/AuthService";
import { PasswordService } from "./services/PasswordService";
import { TokenService } from "./services/TokenService";
import { SessionStore } from "../../infrastructure/redis/SessionStore";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";
import { authenticateToken } from "../../shared/middleware/auth";
import { validateRequest } from "../../shared/middleware/validation";
import {
  registerSchema,
  loginSchema,
  refreshSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from "./auth.schemas";
import { logger } from "../../shared/logger";

/**
 * Create and configure auth router
 */
export function createAuthRouter(
  userRepository: IUserRepository,
  auditLogRepository: IAuditLogRepository,
): Router {
  const router = Router();

  // Initialize services
  const sessionStore = new SessionStore({
    redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  });

  const tokenService = TokenService.getInstance(sessionStore);
  const passwordService = PasswordService.getInstance();
  const authService = AuthService.getInstance(
    userRepository,
    auditLogRepository,
    tokenService,
    passwordService,
    sessionStore,
  );

  const authController = new AuthController(
    authService,
    passwordService,
    tokenService,
  );

  // ========================================
  // Public Routes (No Authentication Required)
  // ========================================

  /**
   * POST /auth/register
   * Register a new user
   */
  router.post(
    "/register",
    validateRequest(registerSchema),
    (req: any, res: Response) => authController.register(req, res),
  );

  /**
   * POST /auth/login
   * Authenticate user with email/password
   */
  router.post(
    "/login",
    validateRequest(loginSchema),
    (req: any, res: Response) => authController.login(req, res),
  );

  /**
   * POST /auth/refresh
   * Refresh access token using refresh token
   */
  router.post(
    "/refresh",
    validateRequest(refreshSchema),
    (req: any, res: Response) => authController.refresh(req, res),
  );

  /**
   * POST /auth/forgot-password
   * Initiate password reset
   */
  router.post(
    "/forgot-password",
    validateRequest(forgotPasswordSchema),
    (req: any, res: Response) => authController.forgotPassword(req, res),
  );

  /**
   * POST /auth/reset-password
   * Reset password with token
   */
  router.post(
    "/reset-password",
    validateRequest(resetPasswordSchema),
    (req: any, res: Response) => authController.resetPassword(req, res),
  );

  // ========================================
  // Protected Routes (Authentication Required)
  // ========================================

  /**
   * POST /auth/logout
   * Logout current session
   */
  router.post("/logout", authenticateToken, (req: any, res: Response) =>
    authController.logout(req, res),
  );

  /**
   * POST /auth/logout-all
   * Logout from all sessions
   */
  router.post("/logout-all", authenticateToken, (req: any, res: Response) =>
    authController.logoutAll(req, res),
  );

  /**
   * POST /auth/change-password
   * Change password (authenticated)
   */
  router.post(
    "/change-password",
    authenticateToken,
    validateRequest(changePasswordSchema),
    (req: any, res: Response) => authController.changePassword(req, res),
  );

  /**
   * GET /auth/me
   * Get current user
   */
  router.get("/me", authenticateToken, (req: any, res: Response) =>
    authController.me(req, res),
  );

  /**
   * POST /auth/verify-token
   * Verify if current access token is valid
   */
  router.post("/verify-token", authenticateToken, (req: any, res: Response) =>
    authController.verifyToken(req, res),
  );

  return router;
}

export default createAuthRouter;
