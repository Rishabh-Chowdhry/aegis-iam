import { createClient, RedisClientType } from "redis";

export class RedisService {
  private client: RedisClientType;

  constructor() {
    this.client = createClient({
      url: process.env.REDIS_URL || "redis://localhost:6379",
    });

    this.client.on("error", (err) => console.error("Redis Client Error", err));
  }

  async connect(): Promise<void> {
    await this.client.connect();
  }

  async disconnect(): Promise<void> {
    await this.client.disconnect();
  }

  // Cache operations
  async set(key: string, value: string, ttl?: number): Promise<void> {
    if (ttl) {
      await this.client.setEx(key, ttl, value);
    } else {
      await this.client.set(key, value);
    }
  }

  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  async del(key: string): Promise<number> {
    return await this.client.del(key);
  }

  // Session management
  async setSession(
    sessionId: string,
    data: any,
    ttl: number = 3600,
  ): Promise<void> {
    await this.set(`session:${sessionId}`, JSON.stringify(data), ttl);
  }

  async getSession(sessionId: string): Promise<any | null> {
    const data = await this.get(`session:${sessionId}`);
    return data ? JSON.parse(data) : null;
  }

  async deleteSession(sessionId: string): Promise<void> {
    await this.del(`session:${sessionId}`);
  }

  // Rate limiting
  async checkRateLimit(
    key: string,
    limit: number,
    window: number,
  ): Promise<boolean> {
    const now = Date.now();
    const windowKey = `ratelimit:${key}:${Math.floor(now / window)}`;

    const count = await this.client.incr(windowKey);
    if (count === 1) {
      await this.client.expire(windowKey, Math.ceil(window / 1000));
    }

    return count <= limit;
  }

  // Invalidate refresh tokens
  async invalidateRefreshToken(token: string): Promise<void> {
    await this.set(`invalidated:${token}`, "true", 7 * 24 * 60 * 60); // 7 days
  }

  async isRefreshTokenInvalidated(token: string): Promise<boolean> {
    const result = await this.get(`invalidated:${token}`);
    return result !== null;
  }

  // User-token mapping for efficient token revocation
  async addTokenToUserMapping(userId: string, tokenId: string): Promise<void> {
    await this.client.sAdd(`user_tokens:${userId}`, tokenId);
  }

  async getUserTokens(userId: string): Promise<string[]> {
    return await this.client.sMembers(`user_tokens:${userId}`);
  }

  async removeTokenFromUserMapping(
    userId: string,
    tokenId: string,
  ): Promise<void> {
    await this.client.sRem(`user_tokens:${userId}`, tokenId);
  }

  async deleteUserTokenMapping(userId: string): Promise<void> {
    await this.client.del(`user_tokens:${userId}`);
  }

  // Get all refresh token keys for a pattern (using SCAN for production)
  async getAllRefreshTokenKeys(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor = 0;

    do {
      const result = await this.client.scan(cursor, {
        MATCH: pattern,
        COUNT: 100,
      });
      cursor = result.cursor;
      keys.push(...result.keys);
    } while (cursor !== 0);

    return keys;
  }
}
