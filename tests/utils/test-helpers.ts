/**
 * Test Utilities for Authentication Integration Tests
 * Provides mock factories and test helpers for consistent test setup
 */

import express, { Express } from "express";
import jwt, { SignOptions } from "jsonwebtoken";
import { config } from "../../src/shared/config";

// Mock types
export interface MockUser {
  id: string;
  email: string;
  hashedPassword: string;
  roles: string[];
  status: "active" | "inactive" | "suspended";
  tenantId: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface MockSession {
  sessionId: string;
  userId: string;
  data: Record<string, any>;
  expiresAt: number;
}

export interface MockAuditLog {
  id: string;
  userId: string;
  action: string;
  timestamp: Date;
  details: Record<string, any>;
  tenantId: string;
}

// Jest mock type
type MockFunction = (...args: any[]) => any;

/**
 * Create a mock Prisma client with user repository methods
 */
export function createMockPrisma() {
  const users: Map<string, MockUser> = new Map();
  const auditLogs: MockAuditLog[] = [];

  const mockFindFirst: MockFunction = async (query: {
    where: { email?: string; id?: string };
  }) => {
    if (query.where.email) {
      return (
        Array.from(users.values()).find((u) => u.email === query.where.email) ||
        null
      );
    }
    if (query.where.id) {
      return users.get(query.where.id) || null;
    }
    return null;
  };

  const mockFindUnique: MockFunction = async (query: {
    where: { id: string };
  }) => {
    return users.get(query.where.id) || null;
  };

  const mockCreate: MockFunction = async (data: {
    data: Partial<MockUser>;
  }) => {
    const user: MockUser = {
      id: data.data.id || `user-${Date.now()}`,
      email: data.data.email || "",
      hashedPassword: data.data.hashedPassword || "",
      roles: data.data.roles || [],
      status: data.data.status || "active",
      tenantId: data.data.tenantId || "default",
      createdAt: new Date(),
      updatedAt: new Date(),
    };
    users.set(user.id, user);
    return user;
  };

  const mockUpdate: MockFunction = async (query: {
    where: { id: string };
    data: Partial<MockUser>;
  }) => {
    const user = users.get(query.where.id);
    if (user) {
      const updated = { ...user, ...query.data, updatedAt: new Date() };
      users.set(user.id, updated);
      return updated;
    }
    return null;
  };

  const mockDelete: MockFunction = async (query: { where: { id: string } }) => {
    const user = users.get(query.where.id);
    users.delete(query.where.id);
    return user;
  };

  const mockAuditSave: MockFunction = async (entry: MockAuditLog) => {
    auditLogs.push({ ...entry, id: `audit-${Date.now()}` });
    return entry;
  };

  return {
    user: {
      findFirst: mockFindFirst,
      findUnique: mockFindUnique,
      create: mockCreate,
      update: mockUpdate,
      delete: mockDelete,
      // Helper to add test users
      _addTestUser: (user: MockUser) => {
        users.set(user.id, user);
      },
      _clearTestUsers: () => {
        users.clear();
      },
    },
    auditLog: {
      save: mockAuditSave,
      findMany: async () => auditLogs,
      _clearAuditLogs: () => {
        auditLogs.length = 0;
      },
    },
  };
}

/**
 * Create a mock Redis service for session and token management
 */
export function createMockRedis() {
  const sessions: Map<string, { data: any; expiresAt: number }> = new Map();
  const blacklistedTokens: Set<string> = new Set();
  const rateLimitCounters: Map<string, number> = new Map();

  return {
    // Session methods
    setSession: jest.fn(async (key: string, data: any, ttl: number) => {
      const expiresAt = Date.now() + ttl * 1000;
      sessions.set(key, { data, expiresAt });
    }),
    getSession: jest.fn(async (key: string) => {
      const session = sessions.get(key);
      if (!session) return null;
      if (Date.now() > session.expiresAt) {
        sessions.delete(key);
        return null;
      }
      return session.data;
    }),
    deleteSession: jest.fn(async (key: string) => {
      return sessions.delete(key) ? 1 : 0;
    }),
    // Basic key-value methods
    set: jest.fn(async (key: string, value: string, ttl?: number) => {
      if (key.startsWith("refresh_token:")) {
        blacklistedTokens.add(key);
      }
      return "OK";
    }),
    get: jest.fn(async (key: string) => {
      if (key.startsWith("refresh_token:")) {
        return blacklistedTokens.has(key) ? "exists" : null;
      }
      const session = sessions.get(key);
      return session ? JSON.stringify(session.data) : null;
    }),
    del: jest.fn(async (key: string) => {
      if (key.startsWith("refresh_token:")) {
        const removed = blacklistedTokens.has(key);
        blacklistedTokens.delete(key);
        return removed ? 1 : 0;
      }
      return sessions.delete(key) ? 1 : 0;
    }),
    // Rate limiting
    checkRateLimit: jest.fn(
      async (key: string, limit: number, window: number) => {
        const now = Date.now();
        const windowKey = `${key}:${Math.floor(now / window)}`;
        const count = (rateLimitCounters.get(windowKey) || 0) + 1;
        rateLimitCounters.set(windowKey, count);
        return count <= limit;
      },
    ),
    // Blacklist token
    invalidateRefreshToken: jest.fn(async (token: string) => {
      blacklistedTokens.add(`invalidated:${token}`);
    }),
    isRefreshTokenInvalidated: jest.fn(async (token: string) => {
      return blacklistedTokens.has(`invalidated:${token}`);
    }),
    // Test helpers
    _addSession: (key: string, data: any, expiresInSeconds: number = 3600) => {
      sessions.set(key, {
        data,
        expiresAt: Date.now() + expiresInSeconds * 1000,
      });
    },
    _blacklistToken: (tokenId: string) => {
      blacklistedTokens.add(`refresh_token:${tokenId}`);
    },
    _clearSessions: () => {
      sessions.clear();
      blacklistedTokens.clear();
      rateLimitCounters.clear();
    },
    _getSessionCount: () => sessions.size,
    _getBlacklistSize: () => blacklistedTokens.size,
  };
}

/**
 * Create a mock audit logger
 */
export function createMockAuditLogger() {
  const logs: Array<{
    action: string;
    userId?: string;
    tenantId: string;
    details: Record<string, any>;
    timestamp: Date;
  }> = [];

  return {
    log: jest.fn(async (action: string, details: Record<string, any>) => {
      logs.push({
        action,
        userId: details.userId,
        tenantId: details.tenantId || "default",
        details,
        timestamp: new Date(),
      });
    }),
    logAuth: jest.fn(
      async (
        action: string,
        context: Record<string, any>,
        outcome: Record<string, any>,
      ) => {
        logs.push({
          action,
          userId: context.userId,
          tenantId: context.tenantId || "default",
          details: { ...context, ...outcome },
          timestamp: new Date(),
        });
      },
    ),
    logAuthorization: jest.fn(
      async (
        action: string,
        resource: string,
        context: Record<string, any>,
        outcome: Record<string, any>,
      ) => {
        logs.push({
          action,
          userId: context.userId,
          tenantId: context.tenantId || "default",
          details: { resource, ...context, ...outcome },
          timestamp: new Date(),
        });
      },
    ),
    getLogs: () => logs,
    _clearLogs: () => {
      logs.length = 0;
    },
    _getLogCount: () => logs.length,
  };
}

// Helper function to sign JWT with proper typing
function signJwt(
  payload: object,
  secret: string,
  options: SignOptions,
): string {
  return jwt.sign(payload, secret, options);
}

/**
 * Create an Express test application with mocked dependencies
 */
export function createTestApp(
  mockPrisma: any,
  mockRedis: any,
  mockAuditLogger: any = createMockAuditLogger(),
): Express {
  const app = express();
  app.use(express.json());

  // Login endpoint
  app.post("/api/auth/login", async (req, res) => {
    const { email, password, tenantId } = req.body;

    try {
      // Find user
      const user = await mockPrisma.user.findFirst({ where: { email } });
      if (!user) {
        return res
          .status(401)
          .json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
      }

      // Check status
      if (user.status !== "active") {
        return res.status(401).json({
          error:
            user.status === "suspended"
              ? "Account is suspended"
              : "Account is inactive",
          code:
            user.status === "suspended" ? "USER_SUSPENDED" : "USER_INACTIVE",
        });
      }

      // Verify password (simplified - in real app use argon2)
      const isValid = password === "validPassword123";
      if (!isValid) {
        await mockAuditLogger.logAuth(
          "login_failed",
          { userId: user.id, email, tenantId: tenantId || "default" },
          { outcome: "FAILURE", reason: "invalid_password" },
        );
        return res
          .status(401)
          .json({ error: "Invalid credentials", code: "INVALID_CREDENTIALS" });
      }

      // Generate tokens
      const accessToken = signJwt(
        {
          userId: user.id,
          email: user.email,
          roles: user.roles,
          tenantId: user.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" as any },
      );
      const refreshToken = signJwt(
        { userId: user.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "7d" as any },
      );

      await mockAuditLogger.logAuth(
        "login_success",
        { userId: user.id, email, tenantId: user.tenantId },
        { outcome: "SUCCESS" },
      );

      res.json({
        user: {
          id: user.id,
          email: user.email,
          roles: user.roles,
          tenantId: user.tenantId,
        },
        accessToken,
        refreshToken,
      });
    } catch (error) {
      res.status(500).json({ error: "Internal server error" });
    }
  });

  // Logout endpoint
  app.post("/api/auth/logout", async (req, res) => {
    const { refreshToken, tenantId } = req.body;
    const userId = (req as any).user?.id;

    try {
      if (refreshToken) {
        await mockRedis.del(`refresh_token:${refreshToken}`);
      }
      await mockAuditLogger.logAuth(
        "logout",
        { userId, tenantId: tenantId || "default" },
        { outcome: "SUCCESS" },
      );
      res.json({ success: true });
    } catch (error) {
      res.status(500).json({ error: "Logout failed" });
    }
  });

  // Refresh token endpoint
  app.post("/api/auth/refresh-token", async (req, res) => {
    const { refreshToken, tenantId } = req.body;

    try {
      const decoded = jwt.verify(refreshToken, config.jwtRefreshSecret) as any;

      if (decoded.tokenType !== "refresh") {
        return res
          .status(401)
          .json({ error: "Invalid token type", code: "REFRESH_TOKEN_INVALID" });
      }

      const user = await mockPrisma.user.findUnique({
        where: { id: decoded.userId },
      });
      if (!user || user.status !== "active") {
        return res
          .status(401)
          .json({
            error: "User not found or inactive",
            code: "USER_NOT_FOUND",
          });
      }

      const newAccessToken = signJwt(
        {
          userId: user.id,
          email: user.email,
          roles: user.roles,
          tenantId: user.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" as any },
      );
      const newRefreshToken = signJwt(
        { userId: user.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "7d" as any },
      );

      await mockAuditLogger.log("token_refresh", {
        userId: user.id,
        tenantId: user.tenantId,
      });

      res.json({
        user: {
          id: user.id,
          email: user.email,
          roles: user.roles,
          tenantId: user.tenantId,
        },
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      });
    } catch (error) {
      res
        .status(401)
        .json({
          error: "Invalid refresh token",
          code: "REFRESH_TOKEN_INVALID",
        });
    }
  });

  // Protected route middleware
  const authenticateToken = (req: any, res: any, next: any) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith("Bearer ")
      ? authHeader.substring(7)
      : null;

    if (!token) {
      return res
        .status(401)
        .json({ error: "Token missing", code: "TOKEN_MISSING" });
    }

    try {
      const decoded = jwt.verify(token, config.jwtSecret);
      req.user = decoded;
      next();
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        return res
          .status(401)
          .json({ error: "Token expired", code: "TOKEN_EXPIRED" });
      }
      return res
        .status(401)
        .json({ error: "Invalid token", code: "TOKEN_INVALID" });
    }
  };

  // Protected route example
  app.get("/api/protected", authenticateToken, (req: any, res) => {
    res.json({ message: "Access granted", user: req.user });
  });

  // Role-based authorization middleware
  const authorize = (...allowedRoles: string[]) => {
    return (req: any, res: any, next: any) => {
      if (!req.user) {
        return res
          .status(401)
          .json({ error: "Unauthorized", code: "TOKEN_MISSING" });
      }

      const hasRole = req.user.roles?.some((role: string) =>
        allowedRoles.includes(role),
      );
      if (!hasRole) {
        return res.status(403).json({
          error: "Forbidden",
          code: "INSUFFICIENT_PERMISSIONS",
          message: `Required role: ${allowedRoles.join(" or ")}`,
        });
      }

      next();
    };
  };

  // Admin-only route example
  app.get(
    "/api/admin",
    authenticateToken,
    authorize("ADMIN"),
    (req: any, res) => {
      res.json({ message: "Admin access granted", user: req.user });
    },
  );

  // Member-only route example
  app.get(
    "/api/member",
    authenticateToken,
    authorize("MEMBER", "ADMIN"),
    (req: any, res) => {
      res.json({ message: "Member access granted", user: req.user });
    },
  );

  return app;
}

/**
 * Generate a test JWT access token
 */
export function generateTestToken(
  payload: {
    userId: string;
    email: string;
    roles: string[];
    tenantId: string;
  },
  expiresIn: string = "15m",
): string {
  return signJwt(payload, config.jwtSecret, { expiresIn: expiresIn as any });
}

/**
 * Generate a test refresh token
 */
export function generateTestRefreshToken(userId: string): string {
  return signJwt({ userId, tokenType: "refresh" }, config.jwtRefreshSecret, {
    expiresIn: "7d" as any,
  });
}

/**
 * Generate an expired test token
 */
export function generateExpiredToken(payload: {
  userId: string;
  email: string;
  roles: string[];
  tenantId: string;
}): string {
  return signJwt(payload, config.jwtSecret, { expiresIn: "-1s" as any });
}

/**
 * Create a test user with hashed password
 */
export function createTestUser(overrides: Partial<MockUser> = {}): MockUser {
  return {
    id: `user-${Date.now()}`,
    email: "test@example.com",
    hashedPassword: "$argon2i$v=19$m=65536,t=3,p=4$validHashedPassword", // Mock hash
    roles: ["MEMBER"],
    status: "active",
    tenantId: "default",
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides,
  };
}

/**
 * Clean up test data after tests
 */
export function cleanupTestData(
  mockPrisma: any,
  mockRedis: any,
  mockAuditLogger: any,
): void {
  mockPrisma.user._clearTestUsers();
  mockRedis._clearSessions();
  mockAuditLogger._clearLogs();
}

/**
 * Wait for a specified duration (for testing time-based behavior)
 */
export function wait(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
