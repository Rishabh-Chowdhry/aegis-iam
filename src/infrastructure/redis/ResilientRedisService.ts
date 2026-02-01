/**
 * Resilient Redis Service with Circuit Breaker and Fallback Strategies
 *
 * This service provides a robust Redis implementation that:
 * - Uses circuit breaker to prevent cascading failures
 * - Provides in-memory fallback for session storage
 * - Implements token blacklisting
 * - Handles distributed locks
 * - Provides graceful degradation
 */

import { createClient, RedisClientType } from "redis";
import {
  CircuitBreaker,
  CircuitState,
  createDefaultConfig,
  CircuitBreakerMetrics,
  CircuitOpenError,
} from "./CircuitBreaker";
import { logger } from "../../shared/logger";

export interface SessionData {
  userId: string;
  email: string;
  roles: string[];
  tenantId: string;
  tokenId: string;
  createdAt: number;
  lastAccessedAt: number;
}

export interface FallbackCacheEntry {
  data: SessionData;
  expiry: number;
}

export interface ResilientRedisConfig {
  url: string;
  circuitBreakerConfig?: {
    failureThreshold?: number;
    recoveryTimeout?: number;
    successThreshold?: number;
    monitoringWindow?: number;
  };
  fallbackEnabled?: boolean;
  fallbackMaxEntries?: number;
  fallbackTTL?: number; // in seconds
}

export class ResilientRedisService {
  private client: RedisClientType | null = null;
  private circuitBreaker: CircuitBreaker;
  private fallbackCache: Map<string, FallbackCacheEntry> = new Map();
  private fallbackConfig: {
    enabled: boolean;
    maxEntries: number;
    ttl: number;
  };
  private isConnected: boolean = false;

  constructor(private readonly config: ResilientRedisConfig) {
    this.circuitBreaker = new CircuitBreaker({
      ...createDefaultConfig(),
      ...config.circuitBreakerConfig,
    });
    this.fallbackConfig = {
      enabled: config.fallbackEnabled ?? true,
      maxEntries: config.fallbackMaxEntries ?? 1000,
      ttl: config.fallbackTTL ?? 3600, // 1 hour default
    };
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
        url: this.config.url,
      });

      this.client.on("error", (err) => this.handleRedisError(err));
      this.client.on("connect", () => {
        logger.info("Redis client connected");
        this.isConnected = true;
      });
      this.client.on("disconnect", () => {
        logger.warn("Redis client disconnected");
        this.isConnected = false;
      });
      this.client.on("reconnecting", () => {
        logger.info("Redis client reconnecting");
      });

      await this.client.connect();
      this.isConnected = true;
      logger.info("Redis connection established");
    } catch (error) {
      logger.error("Failed to connect to Redis", error);
      this.isConnected = false;
      throw error;
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
      logger.info("Redis connection closed");
    }
  }

  /**
   * Check if Redis is available
   */
  async isHealthy(): Promise<boolean> {
    if (!this.client || !this.isConnected) {
      return false;
    }

    try {
      const result = await this.circuitBreaker.execute(async () => {
        return await this.client!.ping();
      });
      return result === "PONG";
    } catch {
      return false;
    }
  }

  /**
   * Get circuit breaker metrics
   */
  getCircuitMetrics(): CircuitBreakerMetrics {
    return this.circuitBreaker.getMetrics();
  }

  /**
   * Get current state of the circuit breaker
   */
  getCircuitState(): CircuitState {
    return this.circuitBreaker.getState();
  }

  // ==================== Session Management ====================

  /**
   * Store session data
   */
  async setSession(
    sessionId: string,
    data: SessionData,
    ttl: number = 3600,
  ): Promise<void> {
    const key = this.getSessionKey(sessionId);

    try {
      await this.circuitBreaker.executeVoid(async () => {
        await this.client!.setEx(key, ttl, JSON.stringify(data));
      });
    } catch (error) {
      logger.error("Failed to store session in Redis", { sessionId, error });
      this.storeInFallback(sessionId, data, ttl);
    }
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<SessionData | null> {
    const key = this.getSessionKey(sessionId);

    try {
      const result = await this.circuitBreaker.execute(async () => {
        const data = await this.client!.get(key);
        return data ? JSON.parse(data) : null;
      });

      if (result) {
        // Update last accessed time
        const sessionData: SessionData = {
          ...result,
          lastAccessedAt: Date.now(),
        };
        // Async update (don't wait)
        this.setSession(sessionId, sessionData).catch(() => {});
        return sessionData;
      }

      return this.getFromFallback(sessionId);
    } catch (error) {
      if (error instanceof CircuitOpenError) {
        return this.getFromFallback(sessionId);
      }
      logger.error("Failed to get session from Redis", { sessionId, error });
      return this.getFromFallback(sessionId);
    }
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<void> {
    const key = this.getSessionKey(sessionId);

    try {
      await this.circuitBreaker.executeVoid(async () => {
        await this.client!.del(key);
      });
    } catch (error) {
      logger.error("Failed to delete session from Redis", { sessionId, error });
    }

    this.deleteFromFallback(sessionId);
  }

  // ==================== Token Blacklisting ====================

  /**
   * Blacklist a token
   */
  async blacklistToken(
    tokenId: string,
    userId: string,
    reason: string,
    ttl: number,
  ): Promise<void> {
    const key = `blacklist:${tokenId}`;

    try {
      await this.circuitBreaker.executeVoid(async () => {
        await this.client!.setEx(
          key,
          ttl,
          JSON.stringify({ userId, reason, timestamp: Date.now() }),
        );
      });
    } catch (error) {
      logger.error("Failed to blacklist token in Redis", { tokenId, error });
    }
  }

  /**
   * Check if a token is blacklisted
   */
  async isTokenBlacklisted(tokenId: string): Promise<boolean> {
    const key = `blacklist:${tokenId}`;

    try {
      const result = await this.circuitBreaker.execute(async () => {
        return await this.client!.exists(key);
      });
      return result === 1;
    } catch (error) {
      logger.error("Failed to check token blacklist in Redis", {
        tokenId,
        error,
      });
      return false;
    }
  }

  /**
   * Get blacklisted token info
   */
  async getBlacklistedTokenInfo(tokenId: string): Promise<{
    userId: string;
    reason: string;
    timestamp: number;
  } | null> {
    const key = `blacklist:${tokenId}`;

    try {
      const result = await this.circuitBreaker.execute(async () => {
        const data = await this.client!.get(key);
        return data ? JSON.parse(data) : null;
      });
      return result;
    } catch (error) {
      logger.error("Failed to get blacklisted token info", { tokenId, error });
      return null;
    }
  }

  // ==================== Rate Limiting ====================

  /**
   * Check rate limit
   */
  async checkRateLimit(
    key: string,
    limit: number,
    windowMs: number,
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const windowKey = `ratelimit:${key}:${Math.floor(Date.now() / windowMs)}`;

    try {
      return await this.circuitBreaker.execute(async () => {
        const count = await this.client!.incr(windowKey);
        if (count === 1) {
          await this.client!.expire(windowKey, Math.ceil(windowMs / 1000));
        }

        const remaining = Math.max(0, limit - count);
        const resetTime = Math.ceil(windowMs / 1000);

        return {
          allowed: count <= limit,
          remaining,
          resetTime,
        };
      });
    } catch (error) {
      logger.warn("Rate limiting degraded, allowing request", { key, error });
      // Fail open: allow the request if Redis is unavailable
      return {
        allowed: true,
        remaining: limit,
        resetTime: Math.ceil(windowMs / 1000),
      };
    }
  }

  // ==================== Distributed Locks ====================

  /**
   * Acquire a distributed lock
   */
  async acquireLock(
    lockName: string,
    timeoutMs: number = 10000,
  ): Promise<string | null> {
    const lockKey = `lock:${lockName}`;
    const lockValue = `${process.pid}:${Date.now()}:${Math.random().toString(36).substr(2, 9)}`;

    try {
      const acquired = await this.circuitBreaker.execute(async () => {
        return await this.client!.set(lockKey, lockValue, {
          NX: true,
          PX: timeoutMs,
        });
      });

      return acquired ? lockValue : null;
    } catch (error) {
      logger.error("Failed to acquire lock", { lockName, error });
      return null;
    }
  }

  /**
   * Release a distributed lock
   */
  async releaseLock(lockName: string, lockValue: string): Promise<boolean> {
    const lockKey = `lock:${lockName}`;

    try {
      // Lua script for atomic check-and-delete
      const script = `
        if redis.call("get", KEYS[1]) == ARGV[1] then
          return redis.call("del", KEYS[1])
        else
          return 0
        end
      `;

      const result = await this.circuitBreaker.execute(async () => {
        return await this.client!.eval(script, {
          keys: [lockKey],
          arguments: [lockValue],
        });
      });

      return result === 1;
    } catch (error) {
      logger.error("Failed to release lock", { lockName, error });
      return false;
    }
  }

  // ==================== Generic Cache Operations ====================

  /**
   * Set a value in cache
   */
  async set(key: string, value: any, ttl?: number): Promise<void> {
    try {
      await this.circuitBreaker.executeVoid(async () => {
        if (ttl) {
          await this.client!.setEx(key, ttl, JSON.stringify(value));
        } else {
          await this.client!.set(key, JSON.stringify(value));
        }
      });
    } catch (error) {
      logger.error("Failed to set cache value", { key, error });
    }
  }

  /**
   * Get a value from cache
   */
  async get<T>(key: string): Promise<T | null> {
    try {
      const result = await this.circuitBreaker.execute(async () => {
        const data = await this.client!.get(key);
        return data ? JSON.parse(data) : null;
      });
      return result;
    } catch (error) {
      logger.error("Failed to get cache value", { key, error });
      return null;
    }
  }

  /**
   * Delete a value from cache
   */
  async delete(key: string): Promise<void> {
    try {
      await this.circuitBreaker.executeVoid(async () => {
        await this.client!.del(key);
      });
    } catch (error) {
      logger.error("Failed to delete cache value", { key, error });
    }
  }

  // ==================== Fallback Cache Management ====================

  /**
   * Store session in fallback cache
   */
  private storeInFallback(
    sessionId: string,
    data: SessionData,
    ttl: number,
  ): void {
    if (!this.fallbackConfig.enabled) {
      return;
    }

    // Evict old entries if cache is full
    if (this.fallbackCache.size >= this.fallbackConfig.maxEntries) {
      const oldestKey = this.findOldestEntry();
      if (oldestKey) {
        this.fallbackCache.delete(oldestKey);
      }
    }

    this.fallbackCache.set(sessionId, {
      data,
      expiry: Date.now() + ttl * 1000,
    });
  }

  /**
   * Get session from fallback cache
   */
  private getFromFallback(sessionId: string): SessionData | null {
    const entry = this.fallbackCache.get(sessionId);

    if (!entry) {
      return null;
    }

    if (Date.now() > entry.expiry) {
      this.fallbackCache.delete(sessionId);
      return null;
    }

    return entry.data;
  }

  /**
   * Delete session from fallback cache
   */
  private deleteFromFallback(sessionId: string): void {
    this.fallbackCache.delete(sessionId);
  }

  /**
   * Find the oldest entry in fallback cache
   */
  private findOldestEntry(): string | null {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;

    for (const [key, entry] of this.fallbackCache.entries()) {
      if (entry.expiry < oldestTime) {
        oldestTime = entry.expiry;
        oldestKey = key;
      }
    }

    return oldestKey;
  }

  /**
   * Clear fallback cache
   */
  clearFallbackCache(): void {
    this.fallbackCache.clear();
  }

  /**
   * Get fallback cache stats
   */
  getFallbackStats(): { size: number; maxSize: number } {
    return {
      size: this.fallbackCache.size,
      maxSize: this.fallbackConfig.maxEntries,
    };
  }

  // ==================== Utility Methods ====================

  /**
   * Get the full key for session storage
   */
  private getSessionKey(sessionId: string): string {
    return `session:${sessionId}`;
  }

  /**
   * Handle Redis client errors
   */
  private handleRedisError(error: Error): void {
    logger.error("Redis client error", { error: error.message });

    // Force circuit breaker to open on connection errors
    if (this.isConnected) {
      this.isConnected = false;
    }
  }

  /**
   * Ping Redis to check connection
   */
  async ping(): Promise<boolean> {
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
}

/**
 * Factory function to create ResilientRedisService
 */
export function createResilientRedisService(
  url: string,
): ResilientRedisService {
  return new ResilientRedisService({
    url,
    circuitBreakerConfig: {
      failureThreshold: 5,
      recoveryTimeout: 30000,
      successThreshold: 3,
      monitoringWindow: 60000,
    },
    fallbackEnabled: true,
    fallbackMaxEntries: 1000,
    fallbackTTL: 3600,
  });
}
