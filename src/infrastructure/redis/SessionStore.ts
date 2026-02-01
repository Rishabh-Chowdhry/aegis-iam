/**
 * SessionStore - Redis-backed Session Management
 *
 * This service handles all session-related operations including:
 * - Refresh token storage and verification
 * - Token blacklisting for immediate revocation
 * - Password reset token management
 * - Session invalidation across all user devices
 *
 * Security Features:
 * - Cryptographically secure token IDs
 * - TTL-based automatic expiration
 * - Fail-closed behavior when Redis is unavailable
 * - In-memory fallback for rate limiting (with documented tradeoffs)
 */

import { createClient, RedisClientType } from "redis";
import { logger } from "../../shared/logger";
import { AppError, ErrorCode } from "../../shared/errors/AppError";

/**
 * Device information for session tracking
 */
export interface DeviceInfo {
  userAgent: string;
  ip: string;
  deviceId?: string;
}

/**
 * Refresh token data stored in Redis
 */
export interface RefreshTokenData {
  userId: string;
  sessionId: string;
  deviceInfo: DeviceInfo;
  createdAt: Date;
  lastUsedAt: Date;
  jti: string; // JWT ID for revocation
  tenantId: string;
}

/**
 * Password reset token data
 */
export interface PasswordResetTokenData {
  userId: string;
  hashedToken: string;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Configuration for SessionStore
 */
export interface SessionStoreConfig {
  redisUrl: string;
  /** Prefix for all Redis keys to avoid collisions */
  keyPrefix?: string;
  /** Default TTL for refresh tokens in seconds (7 days) */
  refreshTokenTTL?: number;
  /** Default TTL for access token blacklist in seconds (15 minutes) */
  accessTokenTTL?: number;
  /** Default TTL for password reset tokens in seconds (1 hour) */
  passwordResetTTL?: number;
  /** Enable fallback to in-memory cache when Redis fails */
  fallbackEnabled?: boolean;
}

export class SessionStore {
  private client: RedisClientType | null = null;
  private isConnected: boolean = false;

  // Key prefixes for namespace isolation
  private readonly REFRESH_TOKEN_PREFIX = "refresh_token:";
  private readonly ACCESS_TOKEN_BLACKLIST_PREFIX = "access_blacklist:";
  private readonly PASSWORD_RESET_PREFIX = "password_reset:";
  private readonly SESSION_PREFIX = "session:";
  private readonly USER_SESSIONS_PREFIX = "user_sessions:";

  // TTL values
  private readonly REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
  private readonly ACCESS_TOKEN_TTL_SECONDS = 15 * 60; // 15 minutes
  private readonly PASSWORD_RESET_TTL_SECONDS = 60 * 60; // 1 hour

  // In-memory fallback cache (only for rate limiting degradation)
  private fallbackCache: Map<string, { data: string; expiry: number }> =
    new Map();
  private readonly FALLBACK_MAX_ENTRIES = 1000;
  private readonly FALLBACK_TTL_SECONDS = 3600; // 1 hour

  constructor(private readonly config: SessionStoreConfig) {
    // Apply custom TTL values if provided
    if (config.refreshTokenTTL) {
      this.REFRESH_TOKEN_TTL_SECONDS = config.refreshTokenTTL;
    }
    if (config.accessTokenTTL) {
      this.ACCESS_TOKEN_TTL_SECONDS = config.accessTokenTTL;
    }
    if (config.passwordResetTTL) {
      this.PASSWORD_RESET_TTL_SECONDS = config.passwordResetTTL;
    }
  }

  /**
   * Connect to Redis
   */
  async connect(): Promise<void> {
    if (this.isConnected) {
      return;
    }

    try {
      this.client = createClient({
        url: this.config.redisUrl,
      });

      this.client.on("error", (err) => {
        logger.error("Redis Client Error", { error: err.message });
        this.isConnected = false;
      });

      this.client.on("connect", () => {
        logger.info("Redis client connected");
        this.isConnected = true;
      });

      this.client.on("disconnect", () => {
        logger.warn("Redis client disconnected");
        this.isConnected = false;
      });

      await this.client.connect();
      this.isConnected = true;
      logger.info("SessionStore Redis connection established");
    } catch (error) {
      logger.error("Failed to connect to Redis for SessionStore", error);
      this.isConnected = false;
      // Fail-closed: throw error to prevent auth operations when Redis is unavailable
      throw AppError.fromErrorCode(
        ErrorCode.REDIS_ERROR,
        "Authentication system unavailable - please try again later",
      );
    }
  }

  /**
   * Disconnect from Redis
   */
  async disconnect(): Promise<void> {
    if (this.client) {
      await this.client.disconnect();
      this.client = null;
      this.isConnected = false;
      logger.info("SessionStore Redis connection closed");
    }
  }

  /**
   * Check if Redis is healthy
   */
  async isHealthy(): Promise<boolean> {
    if (!this.client || !this.isConnected) {
      return false;
    }

    try {
      const result = await this.client.ping();
      return result === "PONG";
    } catch {
      return false;
    }
  }

  /**
   * Get full Redis key with prefix
   */
  private getKey(prefix: string, key: string): string {
    return `${this.config.keyPrefix || ""}${prefix}${key}`;
  }

  /**
   * Store a refresh token in Redis
   *
   * @param tokenId - Unique token identifier (jti)
   * @param data - Refresh token data
   * @param ttl - Time to live in seconds (optional, uses default if not provided)
   */
  async storeRefreshToken(
    tokenId: string,
    data: RefreshTokenData,
    ttl?: number,
  ): Promise<void> {
    await this.ensureConnected();

    const key = this.getKey(this.REFRESH_TOKEN_PREFIX, tokenId);
    const value = JSON.stringify({
      ...data,
      createdAt: data.createdAt.toISOString(),
      lastUsedAt: data.lastUsedAt.toISOString(),
    });

    const expiry = ttl || this.REFRESH_TOKEN_TTL_SECONDS;
    await this.client!.setEx(key, expiry, value);

    // Also store in user's session set for efficient logout-all operations
    const userSessionsKey = this.getKey(this.USER_SESSIONS_PREFIX, data.userId);
    await this.client!.sAdd(userSessionsKey, tokenId);
    await this.client!.expire(userSessionsKey, this.REFRESH_TOKEN_TTL_SECONDS);

    logger.debug("Stored refresh token", { userId: data.userId, tokenId });
  }

  /**
   * Get refresh token data from Redis
   *
   * @param tokenId - Unique token identifier (jti)
   * @returns Refresh token data or null if not found/expired
   */
  async getRefreshToken(tokenId: string): Promise<RefreshTokenData | null> {
    await this.ensureConnected();

    const key = this.getKey(this.REFRESH_TOKEN_PREFIX, tokenId);
    const data = await this.client!.get(key);

    if (!data) {
      return null;
    }

    try {
      const parsed = JSON.parse(data);
      return {
        ...parsed,
        createdAt: new Date(parsed.createdAt),
        lastUsedAt: new Date(parsed.lastUsedAt),
      };
    } catch {
      logger.error("Failed to parse refresh token data", { tokenId });
      return null;
    }
  }

  /**
   * Update the lastUsedAt timestamp for a refresh token
   * Called on every token refresh to track usage
   *
   * @param tokenId - Unique token identifier (jti)
   */
  async updateRefreshTokenUsage(tokenId: string): Promise<void> {
    await this.ensureConnected();

    const key = this.getKey(this.REFRESH_TOKEN_PREFIX, tokenId);
    const data = await this.client!.get(key);

    if (!data) {
      return;
    }

    try {
      const parsed: RefreshTokenData = JSON.parse(data);
      parsed.lastUsedAt = new Date();
      await this.client!.setEx(
        key,
        this.REFRESH_TOKEN_TTL_SECONDS,
        JSON.stringify(parsed),
      );
    } catch {
      logger.error("Failed to update refresh token usage", { tokenId });
    }
  }

  /**
   * Delete a refresh token (logout from current session)
   *
   * @param tokenId - Unique token identifier (jti)
   * @returns true if token was deleted, false if not found
   */
  async deleteRefreshToken(tokenId: string): Promise<boolean> {
    await this.ensureConnected();

    // First get the token to know the userId for cleanup
    const tokenData = await this.getRefreshToken(tokenId);

    const key = this.getKey(this.REFRESH_TOKEN_PREFIX, tokenId);
    const deleted = await this.client!.del(key);

    if (tokenData) {
      // Remove from user's session set
      const userSessionsKey = this.getKey(
        this.USER_SESSIONS_PREFIX,
        tokenData.userId,
      );
      await this.client!.sRem(userSessionsKey, tokenId);
    }

    logger.debug("Deleted refresh token", { tokenId, found: deleted > 0 });
    return deleted > 0;
  }

  /**
   * Delete all refresh tokens for a user (logout from all sessions)
   *
   * @param userId - User ID
   * @returns Number of tokens deleted
   */
  async deleteAllUserSessions(userId: string): Promise<number> {
    await this.ensureConnected();

    const userSessionsKey = this.getKey(this.USER_SESSIONS_PREFIX, userId);
    const tokenIds = await this.client!.sMembers(userSessionsKey);

    if (tokenIds.length === 0) {
      return 0;
    }

    // Delete all refresh tokens
    const keysToDelete = tokenIds.map((tokenId) =>
      this.getKey(this.REFRESH_TOKEN_PREFIX, tokenId),
    );
    keysToDelete.push(userSessionsKey);

    await this.client!.del(keysToDelete);

    logger.info("Deleted all user sessions", {
      userId,
      sessionCount: tokenIds.length,
    });
    return tokenIds.length;
  }

  /**
   * Check if a refresh token has been revoked
   *
   * @param tokenId - Unique token identifier (jti)
   * @returns true if token is revoked/not found, false if valid
   */
  async isTokenRevoked(tokenId: string): Promise<boolean> {
    const token = await this.getRefreshToken(tokenId);
    return token === null;
  }

  /**
   * Blacklist an access token by its jti
   * Used for immediate access token revocation (logout)
   *
   * @param jti - JWT ID
   * @param expiresIn - Seconds until the token naturally expires
   */
  async blacklistAccessToken(jti: string, expiresIn?: number): Promise<void> {
    await this.ensureConnected();

    const key = this.getKey(this.ACCESS_TOKEN_BLACKLIST_PREFIX, jti);
    const ttl = expiresIn || this.ACCESS_TOKEN_TTL_SECONDS;

    await this.client!.setEx(key, ttl, "1");
    logger.debug("Blacklisted access token", { jti, ttl });
  }

  /**
   * Check if an access token is blacklisted
   *
   * @param jti - JWT ID
   * @returns true if token is blacklisted
   */
  async isAccessTokenBlacklisted(jti: string): Promise<boolean> {
    await this.ensureConnected();

    const key = this.getKey(this.ACCESS_TOKEN_BLACKLIST_PREFIX, jti);
    const result = await this.client!.get(key);
    return result !== null;
  }

  /**
   * Store a password reset token (hashed)
   *
   * @param userId - User ID
   * @param hashedToken - Hashed reset token
   * @param ttl - Time to live in seconds (optional)
   */
  async storePasswordResetToken(
    userId: string,
    hashedToken: string,
    ttl?: number,
  ): Promise<void> {
    await this.ensureConnected();

    const key = this.getKey(this.PASSWORD_RESET_PREFIX, userId);
    const expiry = ttl || this.PASSWORD_RESET_TTL_SECONDS;

    await this.client!.setEx(key, expiry, hashedToken);
    logger.debug("Stored password reset token", { userId });
  }

  /**
   * Verify and consume a password reset token
   * The token is deleted after successful verification (one-time use)
   *
   * @param userId - User ID
   * @param hashedToken - Hashed token to verify
   * @returns true if token is valid and was consumed
   */
  async consumePasswordResetToken(
    userId: string,
    hashedToken: string,
  ): Promise<boolean> {
    await this.ensureConnected();

    const key = this.getKey(this.PASSWORD_RESET_PREFIX, userId);
    const storedToken = await this.client!.get(key);

    if (!storedToken) {
      logger.debug("Password reset token not found or expired", { userId });
      return false;
    }

    // Use constant-time comparison to prevent timing attacks
    const isValid = this.constantTimeEquals(storedToken, hashedToken);

    if (isValid) {
      // Delete the token after successful verification (one-time use)
      await this.client!.del(key);
      logger.info("Password reset token consumed", { userId });
    }

    return isValid;
  }

  /**
   * Get all active session IDs for a user
   * Useful for displaying active sessions to users
   *
   * @param userId - User ID
   * @returns Array of session IDs
   */
  async getUserSessionIds(userId: string): Promise<string[]> {
    await this.ensureConnected();

    const userSessionsKey = this.getKey(this.USER_SESSIONS_PREFIX, userId);
    return await this.client!.sMembers(userSessionsKey);
  }

  /**
   * Get session data for a specific session
   *
   * @param sessionId - Session ID
   * @returns Session data or null if not found
   */
  async getSession(sessionId: string): Promise<RefreshTokenData | null> {
    return await this.getRefreshToken(sessionId);
  }

  /**
   * Clean up expired entries from fallback cache
   * Called periodically to prevent memory leaks
   */
  private cleanupFallbackCache(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, entry] of this.fallbackCache.entries()) {
      if (entry.expiry < now) {
        this.fallbackCache.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      logger.debug("Cleaned up fallback cache entries", { count: cleaned });
    }
  }

  /**
   * Ensure Redis is connected before operations
   * Throws error if not connected (fail-closed behavior)
   */
  private async ensureConnected(): Promise<void> {
    if (!this.isConnected || !this.client) {
      // Attempt to reconnect
      try {
        await this.connect();
      } catch {
        throw AppError.fromErrorCode(
          ErrorCode.REDIS_ERROR,
          "Session store unavailable - authentication temporarily unavailable",
        );
      }
    }
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  private constantTimeEquals(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}
