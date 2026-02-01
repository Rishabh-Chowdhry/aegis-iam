/**
 * Policy Cache
 *
 * Caches policies and authorization decisions for performance.
 * Supports distributed caching with Redis fallback to in-memory cache.
 */

import {
  AuthorizationRequest,
  AuthorizationDecision,
  ABACPolicy,
} from "../policy/models/types";
import { ResilientRedisService } from "../../../infrastructure/redis/ResilientRedisService";
import { logger } from "../../../shared/logger";

/**
 * Policy Cache Interface
 */
export interface IPolicyCache {
  get(request: AuthorizationRequest): Promise<AuthorizationDecision | null>;
  set(
    request: AuthorizationRequest,
    decision: AuthorizationDecision,
    ttl: number,
  ): Promise<void>;
  getPolicies(tenantId: string): Promise<ABACPolicy[]>;
  invalidate(tenantId?: string): Promise<void>;
}

/**
 * In-memory Policy Cache (fallback)
 */
export class PolicyCache implements IPolicyCache {
  private decisionCache: Map<
    string,
    { decision: AuthorizationDecision; expiresAt: number }
  > = new Map();
  private policyCache: Map<
    string,
    { policies: ABACPolicy[]; expiresAt: number }
  > = new Map();
  private defaultTTL: number = 300000; // 5 minutes
  private redisService: ResilientRedisService | null = null;
  private useDistributedCache: boolean = false;

  constructor(redisService?: ResilientRedisService) {
    if (redisService) {
      this.redisService = redisService;
      this.useDistributedCache = true;
    }
  }

  /**
   * Get cached decision
   */
  async get(
    request: AuthorizationRequest,
  ): Promise<AuthorizationDecision | null> {
    const key = this.generateDecisionCacheKey(request);

    // Try distributed cache first
    if (this.useDistributedCache && this.redisService) {
      try {
        const cached = await this.redisService.get<{
          decision: AuthorizationDecision;
          expiresAt: number;
        }>(key);

        if (cached && cached.expiresAt > Date.now()) {
          return cached.decision;
        }
      } catch (error) {
        logger.warn("Failed to get decision from distributed cache", { error });
        // Fall back to in-memory cache
      }
    }

    // Fall back to in-memory cache
    const cached = this.decisionCache.get(key);

    if (cached && cached.expiresAt > Date.now()) {
      return cached.decision;
    }

    return null;
  }

  /**
   * Cache decision
   */
  async set(
    request: AuthorizationRequest,
    decision: AuthorizationDecision,
    ttl: number,
  ): Promise<void> {
    const key = this.generateDecisionCacheKey(request);
    const expiresAt = Date.now() + ttl * 1000;
    const cacheEntry = { decision, expiresAt };

    // Store in distributed cache
    if (this.useDistributedCache && this.redisService) {
      try {
        await this.redisService.set(key, cacheEntry, ttl);
      } catch (error) {
        logger.warn("Failed to set decision in distributed cache", { error });
        // Fall back to in-memory cache
      }
    }

    // Always store in in-memory cache as fallback
    this.decisionCache.set(key, cacheEntry);
  }

  /**
   * Get cached policies for tenant
   */
  async getPolicies(tenantId: string): Promise<ABACPolicy[]> {
    const key = this.generatePolicyCacheKey(tenantId);

    // Try distributed cache first
    if (this.useDistributedCache && this.redisService) {
      try {
        const cached = await this.redisService.get<{
          policies: ABACPolicy[];
          expiresAt: number;
        }>(key);

        if (cached && cached.expiresAt > Date.now()) {
          return cached.policies;
        }
      } catch (error) {
        logger.warn("Failed to get policies from distributed cache", { error });
        // Fall back to in-memory cache
      }
    }

    // Fall back to in-memory cache
    const cached = this.policyCache.get(tenantId);

    if (cached && cached.expiresAt > Date.now()) {
      return cached.policies;
    }

    return [];
  }

  /**
   * Set policies for tenant
   */
  async setPolicies(
    tenantId: string,
    policies: ABACPolicy[],
    ttl?: number,
  ): Promise<void> {
    const key = this.generatePolicyCacheKey(tenantId);
    const expiresAt = Date.now() + (ttl ?? this.defaultTTL);
    const cacheEntry = { policies, expiresAt };

    // Store in distributed cache
    if (this.useDistributedCache && this.redisService) {
      try {
        await this.redisService.set(
          key,
          cacheEntry,
          ttl ?? this.defaultTTL / 1000,
        );
      } catch (error) {
        logger.warn("Failed to set policies in distributed cache", { error });
        // Fall back to in-memory cache
      }
    }

    // Always store in in-memory cache as fallback
    this.policyCache.set(tenantId, cacheEntry);
  }

  /**
   * Invalidate cache
   */
  async invalidate(tenantId?: string): Promise<void> {
    if (tenantId) {
      // Invalidate all decision cache entries for this tenant
      for (const [key] of this.decisionCache.entries()) {
        if (key.includes(`:${tenantId}:`)) {
          this.decisionCache.delete(key);
        }
      }
      this.policyCache.delete(tenantId);

      // Invalidate distributed cache
      if (this.useDistributedCache && this.redisService) {
        try {
          await this.redisService.delete(this.generatePolicyCacheKey(tenantId));
        } catch (error) {
          logger.warn("Failed to invalidate distributed cache", { error });
        }
      }
    } else {
      this.decisionCache.clear();
      this.policyCache.clear();
    }
  }

  /**
   * Generate cache key for decision
   * FIXED: Now includes full timestamp instead of just date
   */
  private generateDecisionCacheKey(request: AuthorizationRequest): string {
    const components = [
      request.subject.id,
      request.subject.tenantId,
      request.action.id,
      request.resource.type,
      request.resource.id || "*",
      request.context.timestamp, // Full timestamp (ISO 8601)
    ];

    return components.join(":");
  }

  /**
   * Generate cache key for policies
   */
  private generatePolicyCacheKey(tenantId: string): string {
    return `policies:${tenantId}`;
  }

  /**
   * Clean expired entries
   */
  async cleanExpired(): Promise<void> {
    const now = Date.now();

    for (const [key, value] of this.decisionCache.entries()) {
      if (value.expiresAt <= now) {
        this.decisionCache.delete(key);
      }
    }

    for (const [key, value] of this.policyCache.entries()) {
      if (value.expiresAt <= now) {
        this.policyCache.delete(key);
      }
    }
  }

  /**
   * Get cache statistics
   */
  getStats(): {
    decisionCacheSize: number;
    policyCacheSize: number;
    useDistributedCache: boolean;
  } {
    return {
      decisionCacheSize: this.decisionCache.size,
      policyCacheSize: this.policyCache.size,
      useDistributedCache: this.useDistributedCache,
    };
  }
}
