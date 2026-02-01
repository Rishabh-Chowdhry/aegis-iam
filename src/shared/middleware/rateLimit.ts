import { Request, Response, NextFunction } from "express";
import { RedisService } from "../../infrastructure/services/RedisService";
import { config } from "../config";
import { AppError, ErrorCode } from "../errors/AppError";
import { logger } from "../logger";

interface RateLimitOptions {
  windowMs?: number;
  maxRequests?: number;
  keyGenerator?: (req: Request) => string;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export class RateLimiter {
  private redis: RedisService;
  private windowMs: number;
  private maxRequests: number;
  private keyGenerator: (req: Request) => string;
  private skipSuccessfulRequests: boolean;
  private skipFailedRequests: boolean;

  constructor(options: RateLimitOptions = {}) {
    this.redis = new RedisService();
    this.windowMs = options.windowMs || config.rateLimitWindowMs;
    this.maxRequests = options.maxRequests || config.rateLimitMaxRequests;
    this.keyGenerator = options.keyGenerator || this.defaultKeyGenerator;
    this.skipSuccessfulRequests = options.skipSuccessfulRequests || false;
    this.skipFailedRequests = options.skipFailedRequests || false;
  }

  private defaultKeyGenerator(req: Request): string {
    // Use IP address and tenant ID for rate limiting
    const ip = req.ip || req.connection.remoteAddress || "unknown";
    const tenantId = req.tenantId || "default";
    return `ratelimit:${tenantId}:${ip}`;
  }

  middleware() {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const key = this.keyGenerator(req);
        const now = Date.now();
        const windowStart = now - this.windowMs;

        // Get current request count for this window
        const countKey = `${key}:count`;
        const windowKey = `${key}:window`;

        let requests = parseInt((await this.redis.get(countKey)) || "0", 10);
        const windowStartStored = parseInt(
          (await this.redis.get(windowKey)) || "0",
          10,
        );

        // Reset counter if window has expired
        if (now - windowStartStored > this.windowMs) {
          requests = 0;
          await this.redis.set(
            windowKey,
            now.toString(),
            Math.ceil(this.windowMs / 1000),
          );
        }

        if (requests >= this.maxRequests) {
          logger.warn("Rate limit exceeded", {
            key,
            requests,
            maxRequests: this.maxRequests,
            ip: req.ip,
            tenantId: req.tenantId,
          });

          throw AppError.fromErrorCode(
            ErrorCode.RATE_LIMIT_EXCEEDED,
            `Too many requests. Limit: ${this.maxRequests} per ${this.windowMs / 1000}s`,
          );
        }

        // Increment request count
        requests += 1;
        await this.redis.set(
          countKey,
          requests.toString(),
          Math.ceil(this.windowMs / 1000),
        );

        // Store rate limit info in response headers
        res.set({
          "X-RateLimit-Limit": this.maxRequests.toString(),
          "X-RateLimit-Remaining": Math.max(
            0,
            this.maxRequests - requests - 1,
          ).toString(),
          "X-RateLimit-Reset": new Date(now + this.windowMs).toISOString(),
        });

        next();
      } catch (error) {
        if (error instanceof AppError) {
          return res.status(error.statusCode).json({
            error: error.message,
            code: error.code,
          });
        }

        logger.logError(error as Error, req);
        res.status(500).json({ error: "Rate limiting error" });
      }
    };
  }
}

// Create default rate limiter instance
export const rateLimiter = new RateLimiter();

// Export middleware function
export const rateLimitMiddleware = rateLimiter.middleware();
