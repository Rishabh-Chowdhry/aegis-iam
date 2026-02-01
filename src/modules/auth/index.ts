/**
 * Auth Module - Exports
 *
 * This module exports all authentication components:
 * - Services: AuthService, TokenService, PasswordService
 * - Controllers: AuthController
 * - Guards: AuthGuard
 * - Routes: authRouter
 * - Schemas: All validation schemas
 *
 * Usage:
 * import { AuthService, AuthController, authRouter } from "./modules/auth";
 */

export { AuthController, AuthenticatedRequest } from "./auth.controller";

// Services
export { AuthService } from "./services/AuthService";
export { TokenService } from "./services/TokenService";
export { PasswordService } from "./services/PasswordService";

// Types from services
export type {
  RegisterUserDto,
  LoginUserDto,
  UserResponse,
  AuthResult,
  RefreshTokenResult,
} from "./services/AuthService";

export type {
  TokenPayload,
  AccessTokenResult,
  TokenPair,
} from "./services/TokenService";

export type { PasswordStrengthResult } from "./services/PasswordService";

// Routes
export { createAuthRouter as authRouter } from "./auth.routes";
export { createAuthRouter as authRoutes } from "./auth.routes";
export { createAuthRouter } from "./auth.routes";

// Guards
export {
  AuthGuard,
  authGuard,
  withAuth,
  AuthenticatedRequest as AuthenticatedReq,
} from "./auth.guard";

// Schemas
export {
  registerSchema,
  loginSchema,
  refreshSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
  changePasswordSchema,
} from "./auth.schemas";

export type {
  RegisterInput,
  LoginInput,
  RefreshInput,
  ForgotPasswordInput,
  ResetPasswordInput,
  ChangePasswordInput,
} from "./auth.schemas";

// Re-exports for convenience
export * from "./auth.schemas";

// Session store (for advanced use cases)
export {
  SessionStore,
  DeviceInfo,
} from "../../infrastructure/redis/SessionStore";
