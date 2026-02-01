/**
 * TokenService - JWT Token Management
 *
 * This service handles all JWT token operations:
 * - Access token generation (short-lived: 15 minutes)
 * - Refresh token generation (long-lived: 7 days with rotation)
 * - Token verification with proper security checks
 * - Token blacklisting for immediate revocation
 *
 * Security Considerations:
 * - Access tokens use RS256 or HS256 signing
 * - Refresh tokens are rotated on every use
 * - Each token has a unique jti (JWT ID) for revocation tracking
 * - Tokens include tenant context for multi-tenant systems
 */

import * as jwt from "jsonwebtoken";
import * as crypto from "crypto";
import { config } from "../../../shared/config";
import { AppError, ErrorCode } from "../../../shared/errors/AppError";
import { logger } from "../../../shared/logger";
import { User } from "../../../domain/entities/User";
import {
  SessionStore,
  DeviceInfo,
} from "../../../infrastructure/redis/SessionStore";

/**
 * Token payload structure
 */
export interface TokenPayload {
  sub: string; // User ID
  email: string;
  tenantId: string;
  roles: string[];
  jti: string; // Unique token ID
  type: "access" | "refresh";
  iat?: number; // Issued at
  exp?: number; // Expiration time
  iss?: string; // Issuer
  aud?: string; // Audience
}

/**
 * Access token with expiration
 */
export interface AccessTokenResult {
  token: string;
  expiresIn: number; // Seconds until expiration
}

/**
 * Token pair for authentication response
 */
export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
  tokenType: string;
}

/**
 * Refresh token data for storage
 */
export interface RefreshTokenStorageData {
  userId: string;
  sessionId: string;
  deviceInfo: DeviceInfo;
  createdAt: Date;
  lastUsedAt: Date;
  jti: string;
  tenantId: string;
}

/**
 * TokenService Configuration
 */
export interface TokenServiceConfig {
  /** Access token expiration (default: 15 minutes) */
  accessTokenExpiresIn?: string;
  /** Refresh token expiration (default: 7 days) */
  refreshTokenExpiresIn?: string;
  /** JWT issuer */
  issuer?: string;
  /** JWT audience */
  audience?: string;
}

export class TokenService {
  private static instance: TokenService;
  private sessionStore: SessionStore;
  private config: {
    accessTokenExpiresIn: string;
    refreshTokenExpiresIn: string;
    issuer: string;
    audience: string;
  };

  // Token expiration constants
  private readonly DEFAULT_ACCESS_EXPIRES_IN = "15m";
  private readonly DEFAULT_REFRESH_EXPIRES_IN = "7d";
  private readonly DEFAULT_ISSUER = "iam-system";
  private readonly DEFAULT_AUDIENCE = "iam-clients";

  private constructor(
    sessionStore?: SessionStore,
    config?: TokenServiceConfig,
  ) {
    this.sessionStore =
      sessionStore ||
      new SessionStore({
        redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
      });
    this.config = {
      accessTokenExpiresIn:
        config?.accessTokenExpiresIn || this.DEFAULT_ACCESS_EXPIRES_IN,
      refreshTokenExpiresIn:
        config?.refreshTokenExpiresIn || this.DEFAULT_REFRESH_EXPIRES_IN,
      issuer: config?.issuer || this.DEFAULT_ISSUER,
      audience: config?.audience || this.DEFAULT_AUDIENCE,
    };
  }

  /**
   * Get singleton instance
   */
  static getInstance(
    sessionStore?: SessionStore,
    config?: TokenServiceConfig,
  ): TokenService {
    if (!TokenService.instance) {
      TokenService.instance = new TokenService(sessionStore, config);
    }
    return TokenService.instance;
  }

  /**
   * Generate access token for a user
   *
   * Access tokens are short-lived (15 minutes) for security:
   * - Limits exposure if token is compromised
   * - Forces periodic re-authentication
   * - Reduces the window for replay attacks
   *
   * @param user - User entity to generate token for
   * @returns Access token and expiration time in seconds
   */
  async generateAccessToken(user: User): Promise<AccessTokenResult> {
    const jti = this.generateSecureToken(16);
    const now = Math.floor(Date.now() / 1000);

    // Parse expiration to seconds
    const expiresInSeconds = this.parseExpiresIn(
      this.config.accessTokenExpiresIn,
    );

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email.value,
      tenantId: user.tenantId,
      roles: user.roles,
      jti,
      type: "access",
      iat: now,
      exp: now + expiresInSeconds,
      iss: this.config.issuer,
      aud: this.config.audience,
    };

    const token = jwt.sign(payload, config.jwtSecret, {
      expiresIn: this.config.accessTokenExpiresIn,
      issuer: this.config.issuer,
      audience: this.config.audience,
    } as jwt.SignOptions);

    logger.debug("Generated access token", {
      userId: user.id,
      tenantId: user.tenantId,
      jti,
      expiresIn: expiresInSeconds,
    });

    return {
      token,
      expiresIn: expiresInSeconds,
    };
  }

  /**
   * Generate refresh token for a user
   *
   * Refresh tokens are long-lived (7 days) with rotation:
   * - New refresh token is issued on each use
   * - Old token is invalidated immediately
   * - Stored in Redis for verification and revocation
   *
   * @param user - User entity to generate token for
   * @param deviceInfo - Device information for session tracking
   * @param existingSessionId - Optional existing session ID for refresh
   * @returns New refresh token string
   */
  async generateRefreshToken(
    user: User,
    deviceInfo: DeviceInfo,
    existingSessionId?: string,
  ): Promise<string> {
    const jti = this.generateSecureToken(16);
    const sessionId = existingSessionId || this.generateSecureToken(24);
    const now = new Date();

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email.value,
      tenantId: user.tenantId,
      roles: user.roles,
      jti,
      type: "refresh",
      iat: Math.floor(now.getTime() / 1000),
      iss: this.config.issuer,
      aud: this.config.audience,
    };

    const token = jwt.sign(payload, config.jwtRefreshSecret, {
      expiresIn: this.config.refreshTokenExpiresIn,
      issuer: this.config.issuer,
      audience: this.config.audience,
    } as jwt.SignOptions);

    // Store refresh token data in Redis
    const refreshTokenData: RefreshTokenStorageData = {
      userId: user.id,
      sessionId,
      deviceInfo,
      createdAt: now,
      lastUsedAt: now,
      jti,
      tenantId: user.tenantId,
    };

    const ttlSeconds = this.parseExpiresIn(this.config.refreshTokenExpiresIn);
    await this.sessionStore.storeRefreshToken(
      jti,
      refreshTokenData,
      ttlSeconds,
    );

    logger.debug("Generated refresh token", {
      userId: user.id,
      tenantId: user.tenantId,
      sessionId,
      jti,
    });

    return token;
  }

  /**
   * Verify and decode an access token
   *
   * @param token - Access token to verify
   * @returns Decoded token payload
   * @throws AppError if token is invalid or expired
   */
  async verifyAccessToken(token: string): Promise<TokenPayload> {
    try {
      const decoded = jwt.verify(token, config.jwtSecret, {
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as TokenPayload;

      // Check if token is blacklisted
      const isBlacklisted = await this.sessionStore.isAccessTokenBlacklisted(
        decoded.jti,
      );
      if (isBlacklisted) {
        logger.warn("Access token is blacklisted", {
          jti: decoded.jti,
          userId: decoded.sub,
        });
        throw AppError.fromErrorCode(
          ErrorCode.TOKEN_INVALID,
          "Token has been revoked",
        );
      }

      logger.debug("Access token verified", {
        userId: decoded.sub,
        tenantId: decoded.tenantId,
        jti: decoded.jti,
      });

      return decoded;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        logger.debug("Access token expired", {
          error: (error as Error).message,
        });
        throw AppError.fromErrorCode(
          ErrorCode.TOKEN_EXPIRED,
          "Access token has expired",
        );
      }
      if (error instanceof jwt.JsonWebTokenError) {
        logger.debug("Invalid access token", {
          error: (error as Error).message,
        });
        throw AppError.fromErrorCode(
          ErrorCode.TOKEN_INVALID,
          "Invalid access token",
        );
      }
      if (error instanceof AppError) {
        throw error;
      }
      logger.error("Unexpected error verifying access token", { error });
      throw AppError.fromErrorCode(
        ErrorCode.TOKEN_INVALID,
        "Token verification failed",
      );
    }
  }

  /**
   * Verify a refresh token
   *
   * This performs comprehensive validation:
   * 1. JWT signature verification
   * 2. Check if token exists in Redis storage
   * 3. Check if token is not revoked
   * 4. Update last used timestamp
   *
   * @param token - Refresh token to verify
   * @returns Stored refresh token data
   * @throws AppError if token is invalid
   */
  async verifyRefreshToken(token: string): Promise<RefreshTokenStorageData> {
    try {
      const decoded = jwt.verify(token, config.jwtRefreshSecret, {
        issuer: this.config.issuer,
        audience: this.config.audience,
      }) as TokenPayload;

      // Get stored refresh token data
      const storedData = await this.sessionStore.getRefreshToken(decoded.jti);

      if (!storedData) {
        logger.warn("Refresh token not found in storage", {
          jti: decoded.jti,
          userId: decoded.sub,
        });
        throw AppError.fromErrorCode(
          ErrorCode.REFRESH_TOKEN_INVALID,
          "Refresh token is invalid or has been revoked",
        );
      }

      // Verify the token hasn't been revoked
      const isRevoked = await this.sessionStore.isTokenRevoked(decoded.jti);
      if (isRevoked) {
        logger.warn("Refresh token has been revoked", {
          jti: decoded.jti,
          userId: decoded.sub,
        });
        throw AppError.fromErrorCode(
          ErrorCode.REFRESH_TOKEN_INVALID,
          "Refresh token has been revoked",
        );
      }

      // Update last used timestamp
      await this.sessionStore.updateRefreshTokenUsage(decoded.jti);

      logger.debug("Refresh token verified", {
        userId: decoded.sub,
        sessionId: storedData.sessionId,
        jti: decoded.jti,
      });

      return storedData;
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw AppError.fromErrorCode(
          ErrorCode.TOKEN_EXPIRED,
          "Refresh token has expired",
        );
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw AppError.fromErrorCode(
          ErrorCode.REFRESH_TOKEN_INVALID,
          "Invalid refresh token",
        );
      }
      if (error instanceof AppError) {
        throw error;
      }
      logger.error("Unexpected error verifying refresh token", { error });
      throw AppError.fromErrorCode(
        ErrorCode.REFRESH_TOKEN_INVALID,
        "Refresh token verification failed",
      );
    }
  }

  /**
   * Generate a cryptographically secure random token
   *
   * @param length - Byte length of the token (default: 32 bytes = 64 hex chars)
   * @returns Random token as hex string
   */
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString("hex");
  }

  /**
   * Decode a token without verification (for debugging/logging)
   *
   * @param token - JWT token to decode
   * @returns Decoded payload or null if invalid
   */
  decodeToken(token: string): TokenPayload | null {
    try {
      return jwt.decode(token) as TokenPayload;
    } catch {
      return null;
    }
  }

  /**
   * Get the expiration time for access tokens
   *
   * @returns Expiration time in seconds
   */
  getAccessTokenExpiresIn(): number {
    return this.parseExpiresIn(this.config.accessTokenExpiresIn);
  }

  /**
   * Get the expiration time for refresh tokens
   *
   * @returns Expiration time in seconds
   */
  getRefreshTokenExpiresIn(): number {
    return this.parseExpiresIn(this.config.refreshTokenExpiresIn);
  }

  /**
   * Revoke an access token by adding it to blacklist
   *
   * @param jti - JWT ID of the token to revoke
   * @param expiresIn - Seconds until the token naturally expires
   */
  async revokeAccessToken(jti: string, expiresIn?: number): Promise<void> {
    await this.sessionStore.blacklistAccessToken(jti, expiresIn);
    logger.info("Access token revoked", { jti });
  }

  /**
   * Revoke a refresh token by deleting it from storage
   *
   * @param jti - JWT ID of the token to revoke
   * @returns true if token was revoked
   */
  async revokeRefreshToken(jti: string): Promise<boolean> {
    const deleted = await this.sessionStore.deleteRefreshToken(jti);
    if (deleted) {
      logger.info("Refresh token revoked", { jti });
    }
    return deleted;
  }

  /**
   * Revoke all tokens for a user (logout from all devices)
   *
   * @param userId - User ID
   * @returns Number of sessions revoked
   */
  async revokeAllUserTokens(userId: string): Promise<number> {
    const count = await this.sessionStore.deleteAllUserSessions(userId);
    logger.info("Revoked all user tokens", { userId, sessionCount: count });
    return count;
  }

  /**
   * Parse expiration string to seconds
   *
   * @param expiresIn - Expiration string (e.g., "15m", "7d", "1h")
   * @returns Seconds
   */
  private parseExpiresIn(expiresIn: string): number {
    const match = expiresIn.match(/^(\d+)([smhd])$/);
    if (!match) {
      // Default to 15 minutes if invalid format
      return 15 * 60;
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case "s":
        return value;
      case "m":
        return value * 60;
      case "h":
        return value * 3600;
      case "d":
        return value * 86400;
      default:
        return 15 * 60;
    }
  }

  /**
   * Get token service configuration
   */
  getConfig(): Readonly<TokenServiceConfig> {
    return { ...this.config };
  }
}
