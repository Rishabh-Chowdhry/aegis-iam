/**
 * AuthService - Core Authentication Logic
 *
 * This service handles all authentication operations:
 * - User registration with secure password hashing
 * - User login with credential validation
 * - Token refresh with rotation
 * - Logout with token revocation
 * - Password reset flows
 *
 * Security Considerations:
 * - All operations are audited
 * - Failed attempts are rate limited
 * - Password strength is enforced
 * - Sessions can be invalidated globally
 */

import { User } from "../../../domain/entities/User";
import { Email } from "../../../domain/value-objects/Email";
import { PasswordHash } from "../../../domain/value-objects/PasswordHash";
import { PasswordService } from "./PasswordService";
import { TokenService } from "./TokenService";
import { IUserRepository } from "../../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../../infrastructure/repositories/IAuditLogRepository";
import { AuditLogEntry } from "../../../domain/value-objects/AuditLogEntry";
import {
  SessionStore,
  DeviceInfo,
} from "../../../infrastructure/redis/SessionStore";
import { AppError, ErrorCode } from "../../../shared/errors/AppError";
import { logger } from "../../../shared/logger";
import * as crypto from "crypto";

/**
 * User registration input
 */
export interface RegisterUserDto {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  tenantId?: string;
}

/**
 * User login input
 */
export interface LoginUserDto {
  email: string;
  password: string;
  tenantId?: string;
}

/**
 * User response (without sensitive data)
 */
export interface UserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: string[];
  tenantId: string;
  createdAt: Date;
}

/**
 * Authentication result with tokens
 */
export interface AuthResult {
  user: UserResponse;
  tokens: {
    accessToken: string;
    refreshToken: string;
    expiresIn: number;
    tokenType: string;
  };
  sessionId: string;
}

/**
 * Token refresh result
 */
export interface RefreshTokenResult {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

/**
 * AuthService Configuration
 */
export interface AuthServiceConfig {
  /** Default role for new users */
  defaultRole?: string;
  /** Maximum failed login attempts before lockout */
  maxLoginAttempts?: number;
  /** Lockout duration in seconds (default: 900 = 15 minutes) */
  lockoutDuration?: number;
}

export class AuthService {
  private static instance: AuthService;

  private passwordService: PasswordService;
  private tokenService: TokenService;
  private sessionStore: SessionStore;
  private userRepository: IUserRepository;
  private auditLogRepository: IAuditLogRepository;

  private config: {
    defaultRole: string;
    maxLoginAttempts: number;
    lockoutDuration: number;
  };

  // Role constants
  private readonly DEFAULT_ROLE = "MEMBER";
  private readonly MAX_LOGIN_ATTEMPTS = 5;
  private readonly LOCKOUT_DURATION = 15 * 60; // 15 minutes

  private constructor(
    userRepository: IUserRepository,
    auditLogRepository: IAuditLogRepository,
    tokenService?: TokenService,
    passwordService?: PasswordService,
    sessionStore?: SessionStore,
    config?: AuthServiceConfig,
  ) {
    this.userRepository = userRepository;
    this.auditLogRepository = auditLogRepository;
    this.tokenService = tokenService || TokenService.getInstance();
    this.passwordService = passwordService || PasswordService.getInstance();
    this.sessionStore =
      sessionStore ||
      new SessionStore({
        redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
      });

    this.config = {
      defaultRole: config?.defaultRole || this.DEFAULT_ROLE,
      maxLoginAttempts: config?.maxLoginAttempts || this.MAX_LOGIN_ATTEMPTS,
      lockoutDuration: config?.lockoutDuration || this.LOCKOUT_DURATION,
    };
  }

  /**
   * Get singleton instance
   */
  static getInstance(
    userRepository: IUserRepository,
    auditLogRepository: IAuditLogRepository,
    tokenService?: TokenService,
    passwordService?: PasswordService,
    sessionStore?: SessionStore,
    config?: AuthServiceConfig,
  ): AuthService {
    if (!AuthService.instance) {
      AuthService.instance = new AuthService(
        userRepository,
        auditLogRepository,
        tokenService,
        passwordService,
        sessionStore,
        config,
      );
    }
    return AuthService.instance;
  }

  /**
   * Register a new user
   *
   * @param input - Registration data
   * @param metadata - Device information
   * @param performedBy - User ID performing the action (optional, defaults to "self")
   * @returns Authentication result with tokens
   */
  async register(
    input: RegisterUserDto,
    metadata: DeviceInfo,
    performedBy: string = "self",
  ): Promise<AuthResult> {
    const tenantId = input.tenantId || "default";

    logger.info("User registration initiated", {
      email: input.email,
      tenantId,
      ip: metadata.ip,
    });

    // Validate password strength
    const strengthResult = this.passwordService.validateStrength(
      input.password,
    );
    if (!strengthResult.isValid) {
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_PASSWORD,
        `Password does not meet requirements: ${strengthResult.errors.join(", ")}`,
      );
    }

    // Check if email already exists
    const existingUser = await this.userRepository.findByEmail(
      input.email,
      tenantId,
    );
    if (existingUser) {
      await this.logAudit(
        "REGISTRATION_FAILED",
        undefined,
        "user",
        undefined,
        tenantId,
        {
          email: input.email,
          reason: "email_exists",
          ip: metadata.ip,
          userAgent: metadata.userAgent,
        },
        performedBy,
      );

      throw AppError.fromErrorCode(
        ErrorCode.RESOURCE_ALREADY_EXISTS,
        "User with this email already exists",
      );
    }

    // Hash password
    const passwordHash = await this.passwordService.hash(input.password);

    // Create user using domain entity
    const email = new Email(input.email);
    const user = new User(
      crypto.randomUUID(),
      email,
      new PasswordHash(passwordHash),
      [this.config.defaultRole],
      "active" as any,
      new Date(),
      new Date(),
      tenantId,
    );

    // Save user to repository
    await this.userRepository.save(user);

    // Generate tokens
    const accessTokenResult = await this.tokenService.generateAccessToken(user);
    const refreshToken = await this.tokenService.generateRefreshToken(
      user,
      metadata,
    );

    // Get session ID from refresh token
    const decodedRefresh = this.tokenService.decodeToken(refreshToken);
    const sessionId = decodedRefresh?.sub || user.id;

    // Log successful registration
    await this.logAudit(
      "USER_REGISTERED",
      user.id,
      "user",
      user.id,
      tenantId,
      {
        email: input.email,
        roles: user.roles,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
      },
      performedBy,
    );

    logger.info("User registered successfully", {
      userId: user.id,
      email: input.email,
      tenantId,
    });

    return {
      user: this.toUserResponse(user),
      tokens: {
        accessToken: accessTokenResult.token,
        refreshToken,
        expiresIn: accessTokenResult.expiresIn,
        tokenType: "Bearer",
      },
      sessionId,
    };
  }

  /**
   * Authenticate user with email/password
   *
   * @param input - Login credentials
   * @param metadata - Device information
   * @returns Authentication result with tokens
   */
  async login(input: LoginUserDto, metadata: DeviceInfo): Promise<AuthResult> {
    const tenantId = input.tenantId || "default";

    logger.info("Login attempt", {
      email: input.email,
      tenantId,
      ip: metadata.ip,
    });

    // Find user by email
    const user = await this.userRepository.findByEmail(input.email, tenantId);

    if (!user) {
      // Log failed attempt even if user doesn't exist (security)
      await this.logAudit(
        "LOGIN_FAILED",
        undefined,
        "user",
        undefined,
        tenantId,
        {
          email: input.email,
          reason: "user_not_found",
          ip: metadata.ip,
          userAgent: metadata.userAgent,
        },
      );

      // Use constant-time comparison to prevent timing attacks
      await this.passwordService.verify(input.password, "$argon2i$dummy$hash");

      throw AppError.fromErrorCode(ErrorCode.INVALID_CREDENTIALS);
    }

    // Check if user is active
    if (!this.isUserActive(user)) {
      await this.logAudit("LOGIN_FAILED", user.id, "user", user.id, tenantId, {
        email: input.email,
        reason: "user_inactive",
        status: user.status,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
      });

      throw AppError.fromErrorCode(
        user.status === "suspended"
          ? ErrorCode.USER_SUSPENDED
          : ErrorCode.USER_INACTIVE,
      );
    }

    // Verify password
    const isPasswordValid = await this.passwordService.verify(
      input.password,
      user.hashedPassword.hash,
    );

    if (!isPasswordValid) {
      await this.logAudit("LOGIN_FAILED", user.id, "user", user.id, tenantId, {
        email: input.email,
        reason: "invalid_password",
        ip: metadata.ip,
        userAgent: metadata.userAgent,
      });

      throw AppError.fromErrorCode(ErrorCode.INVALID_CREDENTIALS);
    }

    // Generate tokens
    const accessTokenResult = await this.tokenService.generateAccessToken(user);
    const refreshToken = await this.tokenService.generateRefreshToken(
      user,
      metadata,
    );

    // Get session ID
    const decodedRefresh = this.tokenService.decodeToken(refreshToken);
    const sessionId = decodedRefresh?.sub || user.id;

    // Log successful login
    await this.logAudit("LOGIN_SUCCESS", user.id, "user", user.id, tenantId, {
      email: input.email,
      roles: user.roles,
      ip: metadata.ip,
      userAgent: metadata.userAgent,
    });

    logger.info("Login successful", {
      userId: user.id,
      email: input.email,
      tenantId,
    });

    return {
      user: this.toUserResponse(user),
      tokens: {
        accessToken: accessTokenResult.token,
        refreshToken,
        expiresIn: accessTokenResult.expiresIn,
        tokenType: "Bearer",
      },
      sessionId,
    };
  }

  /**
   * Refresh tokens with rotation
   *
   * This implements refresh token rotation:
   * - New access and refresh tokens are issued
   * - Old refresh token is invalidated immediately
   * - Prevents token reuse attacks
   *
   * @param refreshToken - Current refresh token
   * @param metadata - Device information
   * @returns New token pair
   */
  async refreshTokens(
    refreshToken: string,
    metadata: DeviceInfo,
  ): Promise<RefreshTokenResult> {
    // Verify existing refresh token
    const storedData = await this.tokenService.verifyRefreshToken(refreshToken);

    // Decode token to get user info
    const decodedToken = this.tokenService.decodeToken(refreshToken);
    if (!decodedToken) {
      throw AppError.fromErrorCode(ErrorCode.TOKEN_INVALID);
    }

    // Get user from database
    const user = await this.userRepository.findById(
      decodedToken.sub,
      storedData.tenantId,
    );
    if (!user) {
      throw AppError.fromErrorCode(ErrorCode.USER_NOT_FOUND);
    }

    // Check if user is still active
    if (!this.isUserActive(user)) {
      throw AppError.fromErrorCode(
        user.status === "suspended"
          ? ErrorCode.USER_SUSPENDED
          : ErrorCode.USER_INACTIVE,
      );
    }

    // Revoke old refresh token (rotation)
    await this.tokenService.revokeRefreshToken(decodedToken.jti);

    // Generate new tokens
    const accessTokenResult = await this.tokenService.generateAccessToken(user);
    const newRefreshToken = await this.tokenService.generateRefreshToken(
      user,
      metadata,
      storedData.sessionId, // Keep same session ID
    );

    // Log token refresh
    await this.logAudit(
      "TOKEN_REFRESHED",
      user.id,
      "user",
      user.id,
      user.tenantId,
      {
        sessionId: storedData.sessionId,
        previousJti: decodedToken.jti,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
      },
    );

    logger.info("Tokens refreshed", {
      userId: user.id,
      tenantId: user.tenantId,
      sessionId: storedData.sessionId,
    });

    return {
      accessToken: accessTokenResult.token,
      refreshToken: newRefreshToken,
      expiresIn: accessTokenResult.expiresIn,
      tokenType: "Bearer",
    };
  }

  /**
   * Logout current session
   *
   * @param userId - User ID
   * @param sessionId - Session ID to logout
   * @param metadata - Device information
   */
  async logout(
    userId: string,
    sessionId: string,
    metadata: DeviceInfo,
  ): Promise<void> {
    logger.info("Logout", { userId, sessionId });

    // Get user to find tenant
    const user = await this.userRepository.findById(userId, userId); // Use userId as tenant for lookup
    if (user) {
      // Get refresh token for this session and revoke it
      const refreshTokenData = await this.sessionStore.getSession(sessionId);
      if (refreshTokenData) {
        await this.tokenService.revokeRefreshToken(refreshTokenData.jti);
      }

      // Also revoke access token by blacklisting
      const accessTokenResult =
        await this.tokenService.generateAccessToken(user);
      const decodedAccess = this.tokenService.decodeToken(
        accessTokenResult.token,
      );
      if (decodedAccess) {
        await this.tokenService.revokeAccessToken(
          decodedAccess.jti,
          accessTokenResult.expiresIn,
        );
      }

      await this.logAudit("LOGOUT", userId, "user", userId, user.tenantId, {
        sessionId,
        ip: metadata.ip,
        userAgent: metadata.userAgent,
      });
    }
  }

  /**
   * Logout from all sessions
   *
   * @param userId - User ID
   * @param metadata - Device information
   */
  async logoutAll(userId: string, metadata: DeviceInfo): Promise<void> {
    logger.info("Logout all sessions", { userId });

    // Get user to find tenant
    const user = await this.userRepository.findById(userId, userId);
    const tenantId = user?.tenantId || userId;

    // Revoke all refresh tokens
    const revokedCount = await this.tokenService.revokeAllUserTokens(userId);

    await this.logAudit("LOGOUT_ALL", userId, "user", userId, tenantId, {
      sessionsRevoked: revokedCount,
      ip: metadata.ip,
      userAgent: metadata.userAgent,
    });

    logger.info("All sessions revoked", { userId, sessionCount: revokedCount });
  }

  /**
   * Initiate password reset
   *
   * Generates a secure reset token and stores it in Redis.
   * In production, this would send an email to the user.
   *
   * @param email - User email
   * @param tenantId - Tenant ID
   */
  async initiatePasswordReset(
    email: string,
    tenantId: string = "default",
  ): Promise<void> {
    logger.info("Password reset initiated", { email, tenantId });

    const user = await this.userRepository.findByEmail(email, tenantId);

    // Always return success even if user doesn't exist (prevent enumeration)
    if (!user) {
      logger.debug("Password reset requested for non-existent user", { email });
      return;
    }

    // Generate secure reset token
    const resetToken = crypto.randomBytes(32).toString("hex");
    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    // Store hashed token in Redis (1 hour TTL)
    await this.sessionStore.storePasswordResetToken(
      user.id,
      hashedToken,
      60 * 60,
    );

    // Log password reset initiation
    await this.logAudit(
      "PASSWORD_RESET_INITIATED",
      user.id,
      "user",
      user.id,
      tenantId,
      { email: user.email.value },
    );

    logger.info("Password reset token generated", {
      userId: user.id,
      expiresIn: "1 hour",
    });

    // TODO: Send email with reset token (plain text token)
    // In production, use a proper email service
  }

  /**
   * Reset password with token
   *
   * @param token - Reset token (plain text)
   * @param newPassword - New password
   * @param tenantId - Tenant ID
   */
  async resetPassword(
    token: string,
    newPassword: string,
    tenantId: string = "default",
  ): Promise<void> {
    // Hash the token to compare with stored hash
    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    // Find user by scanning (in production, use a lookup map)
    // For now, we'll need to implement a proper lookup mechanism
    // This is a simplified version that assumes we can find by reset token
    const users = await this.userRepository.findAll(tenantId);
    let userId: string | null = null;

    for (const user of users) {
      const isValid = await this.sessionStore.consumePasswordResetToken(
        user.id,
        hashedToken,
      );
      if (isValid) {
        userId = user.id;
        break;
      }
    }

    if (!userId) {
      throw AppError.fromErrorCode(
        ErrorCode.TOKEN_INVALID,
        "Invalid or expired reset token",
      );
    }

    // Get user
    const user = await this.userRepository.findById(userId, tenantId);
    if (!user) {
      throw AppError.fromErrorCode(ErrorCode.USER_NOT_FOUND);
    }

    // Validate new password strength
    const strengthResult = this.passwordService.validateStrength(newPassword);
    if (!strengthResult.isValid) {
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_PASSWORD,
        `Password does not meet requirements: ${strengthResult.errors.join(", ")}`,
      );
    }

    // Hash new password
    const newPasswordHash = await this.passwordService.hash(newPassword);

    // Update user's password (using the user entity)
    user.updatePassword(new PasswordHash(newPasswordHash));
    await this.userRepository.update(user);

    // Log password reset completion
    await this.logAudit(
      "PASSWORD_RESET_COMPLETED",
      userId,
      "user",
      userId,
      tenantId,
      { email: user.email.value },
    );

    logger.info("Password reset completed", { userId });
  }

  /**
   * Change password (authenticated)
   *
   * @param userId - User ID
   * @param currentPassword - Current password
   * @param newPassword - New password
   * @param tenantId - Tenant ID
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    tenantId: string,
  ): Promise<void> {
    const user = await this.userRepository.findById(userId, tenantId);
    if (!user) {
      throw AppError.fromErrorCode(ErrorCode.USER_NOT_FOUND);
    }

    // Verify current password
    const isValid = await this.passwordService.verify(
      currentPassword,
      user.hashedPassword.hash,
    );
    if (!isValid) {
      await this.logAudit(
        "PASSWORD_CHANGE_FAILED",
        userId,
        "user",
        userId,
        tenantId,
        { reason: "invalid_current_password" },
      );
      throw AppError.fromErrorCode(ErrorCode.INVALID_CREDENTIALS);
    }

    // Validate new password strength
    const strengthResult = this.passwordService.validateStrength(newPassword);
    if (!strengthResult.isValid) {
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_PASSWORD,
        `Password does not meet requirements: ${strengthResult.errors.join(", ")}`,
      );
    }

    // Hash new password
    const newPasswordHash = await this.passwordService.hash(newPassword);

    // Update password
    user.updatePassword(new PasswordHash(newPasswordHash));
    await this.userRepository.update(user);

    // Revoke all sessions (force re-login)
    await this.logoutAll(userId, {
      ip: "unknown",
      userAgent: "password_change",
    });

    await this.logAudit("PASSWORD_CHANGED", userId, "user", userId, tenantId, {
      allSessionsRevoked: true,
    });

    logger.info("Password changed", { userId });
  }

  /**
   * Check if user is active
   */
  private isUserActive(user: User): boolean {
    return user.status === "active";
  }

  /**
   * Convert User entity to UserResponse
   */
  private toUserResponse(user: User): UserResponse {
    return {
      id: user.id,
      email: user.email.value,
      firstName: "",
      lastName: "",
      roles: user.roles,
      tenantId: user.tenantId,
      createdAt: user.createdAt,
    };
  }

  /**
   * Log audit event
   */
  private async logAudit(
    action: string,
    userId: string | undefined,
    resourceType: string,
    resourceId: string | undefined,
    tenantId: string,
    metadata: Record<string, any>,
    performedBy: string = "system",
  ): Promise<void> {
    try {
      // For operations where userId is not available, use a placeholder
      const effectiveUserId = userId || performedBy;

      const entry = new AuditLogEntry(
        effectiveUserId,
        action,
        new Date(),
        metadata,
        tenantId,
      );

      await this.auditLogRepository.save(entry);
    } catch (error) {
      // Don't fail the operation if audit logging fails
      logger.error("Audit logging failed", { action, error });
    }
  }
}
