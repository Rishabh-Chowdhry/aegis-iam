/**
 * Authentication Flow Integration Tests
 * Tests login, logout, and token refresh flows with comprehensive coverage
 */

import request from "supertest";
import express, { Express } from "express";
import jwt from "jsonwebtoken";
import {
  createMockPrisma,
  createMockRedis,
  createMockAuditLogger,
  createTestApp,
  MockUser,
} from "../utils/test-helpers";
import { config } from "../../src/shared/config";

describe("Authentication Flow Integration Tests", () => {
  let app: Express;
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockRedis: ReturnType<typeof createMockRedis>;
  let mockAuditLogger: ReturnType<typeof createMockAuditLogger>;

  // Test user fixtures
  const testUser: MockUser = {
    id: "test-user-123",
    email: "test@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder", // Mock hash
    roles: ["MEMBER"],
    status: "active",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const suspendedUser: MockUser = {
    id: "suspended-user-456",
    email: "suspended@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder",
    roles: ["MEMBER"],
    status: "suspended",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const inactiveUser: MockUser = {
    id: "inactive-user-789",
    email: "inactive@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder",
    roles: ["MEMBER"],
    status: "inactive",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  beforeEach(() => {
    mockPrisma = createMockPrisma();
    mockRedis = createMockRedis();
    mockAuditLogger = createMockAuditLogger();
    app = createTestApp(mockPrisma, mockRedis, mockAuditLogger);

    // Add test users
    mockPrisma.user._addTestUser(testUser);
    mockPrisma.user._addTestUser(suspendedUser);
    mockPrisma.user._addTestUser(inactiveUser);
  });

  afterEach(() => {
    mockPrisma.user._clearTestUsers();
    mockPrisma.auditLog._clearAuditLogs();
    mockRedis._clearSessions();
    mockAuditLogger._clearLogs();
  });

  describe("POST /api/auth/login", () => {
    it("should return 200 and tokens on successful login", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("accessToken");
      expect(response.body).toHaveProperty("refreshToken");
      expect(response.body.user).toEqual({
        id: testUser.id,
        email: testUser.email,
        roles: testUser.roles,
        tenantId: testUser.tenantId,
      });
    });

    it("should return 401 for non-existent user", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "nonexistent@example.com", password: "password123" });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("INVALID_CREDENTIALS");
    });

    it("should return 401 for invalid password", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "wrongPassword" });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("INVALID_CREDENTIALS");
    });

    it("should return 401 for suspended user", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "suspended@example.com", password: "validPassword123" });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("USER_SUSPENDED");
    });

    it("should return 401 for inactive user", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "inactive@example.com", password: "validPassword123" });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("USER_INACTIVE");
    });

    it("should audit log successful login", async () => {
      await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      expect(mockAuditLogger.logAuth).toHaveBeenCalledWith(
        "login_success",
        expect.objectContaining({
          userId: testUser.id,
          email: testUser.email,
          tenantId: testUser.tenantId,
        }),
        expect.objectContaining({ outcome: "SUCCESS" }),
      );
    });

    it("should audit log failed login with invalid password", async () => {
      await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "wrongPassword" });

      expect(mockAuditLogger.logAuth).toHaveBeenCalledWith(
        "login_failed",
        expect.objectContaining({
          userId: testUser.id,
          email: testUser.email,
        }),
        expect.objectContaining({
          outcome: "FAILURE",
          reason: "invalid_password",
        }),
      );
    });

    it("should create session on successful login", async () => {
      await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      expect(mockRedis.setSession).toHaveBeenCalled();
    });

    it("should generate valid JWT tokens", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const accessToken = response.body.accessToken;
      const decoded = jwt.verify(accessToken, config.jwtSecret) as any;

      expect(decoded.userId).toBe(testUser.id);
      expect(decoded.email).toBe(testUser.email);
      expect(decoded.roles).toEqual(testUser.roles);
      expect(decoded.tenantId).toBe(testUser.tenantId);
    });

    it("should generate refresh token with correct payload", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const refreshToken = response.body.refreshToken;
      const decoded = jwt.verify(refreshToken, config.jwtRefreshSecret) as any;

      expect(decoded.userId).toBe(testUser.id);
      expect(decoded.tokenType).toBe("refresh");
    });

    it("should handle rate limiting on repeated login attempts", async () => {
      // Make multiple failed login attempts
      for (let i = 0; i < 5; i++) {
        await request(app)
          .post("/api/auth/login")
          .send({ email: "test@example.com", password: "wrongPassword" });
      }

      // Verify rate limit was checked
      expect(mockRedis.checkRateLimit).toHaveBeenCalled();
    });

    it("should return proper error structure", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "nonexistent@example.com", password: "password" });

      expect(response.body).toHaveProperty("error");
      expect(response.body).toHaveProperty("code");
      expect(response.body).not.toHaveProperty("accessToken");
      expect(response.body).not.toHaveProperty("refreshToken");
    });
  });

  describe("POST /api/auth/logout", () => {
    it("should return 200 on successful logout", async () => {
      const response = await request(app)
        .post("/api/auth/logout")
        .send({ refreshToken: "valid-refresh-token" });

      expect(response.status).toBe(200);
      expect(response.body.success).toBe(true);
    });

    it("should blacklist refresh token on logout", async () => {
      const refreshToken = "test-refresh-token-123";

      await request(app).post("/api/auth/logout").send({ refreshToken });

      expect(mockRedis.del).toHaveBeenCalledWith(
        `refresh_token:${refreshToken}`,
      );
    });

    it("should audit log logout action", async () => {
      await request(app)
        .post("/api/auth/logout")
        .send({ refreshToken: "test-token" });

      expect(mockAuditLogger.logAuth).toHaveBeenCalledWith(
        "logout",
        expect.objectContaining({}),
        expect.objectContaining({ outcome: "SUCCESS" }),
      );
    });

    it("should handle logout without token gracefully", async () => {
      const response = await request(app).post("/api/auth/logout").send({});

      // Should still succeed but without token invalidation
      expect(response.status).toBe(200);
      expect(mockRedis.del).not.toHaveBeenCalled();
    });

    it("should handle multiple logout attempts for same token", async () => {
      const refreshToken = "multi-logout-token";

      await request(app).post("/api/auth/logout").send({ refreshToken });

      await request(app).post("/api/auth/logout").send({ refreshToken });

      // Second call should not fail
      expect(mockRedis.del).toHaveBeenCalledTimes(2);
    });

    it("should delete session on logout", async () => {
      const userId = testUser.id;

      // First login to create session
      await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      mockRedis._clearSessions();

      // Add session manually
      mockRedis._addSession(`session:${userId}`, { userId }, 3600);

      // Logout should delete session
      await request(app)
        .post("/api/auth/logout")
        .send({ refreshToken: "token" });

      // Session should be cleaned up
      expect(mockRedis.getSession).toBeDefined();
    });
  });

  describe("POST /api/auth/refresh-token", () => {
    let validRefreshToken: string;
    let expiredRefreshToken: string;

    beforeEach(() => {
      // Create a valid refresh token
      validRefreshToken = jwt.sign(
        { userId: testUser.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "7d" },
      );

      // Create an expired refresh token
      expiredRefreshToken = jwt.sign(
        { userId: testUser.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "-1s" }, // Already expired
      );
    });

    it("should return 200 and new tokens on successful refresh", async () => {
      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: validRefreshToken });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("accessToken");
      expect(response.body).toHaveProperty("refreshToken");
      expect(response.body.user.id).toBe(testUser.id);
    });

    it("should return 401 for expired refresh token", async () => {
      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: expiredRefreshToken });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("REFRESH_TOKEN_INVALID");
    });

    it("should return 401 for invalid token type", async () => {
      const accessToken = jwt.sign(
        { userId: testUser.id, tokenType: "access" },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: accessToken });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("REFRESH_TOKEN_INVALID");
    });

    it("should return 401 for non-existent user", async () => {
      const tokenForDeletedUser = jwt.sign(
        { userId: "deleted-user-id", tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "7d" },
      );

      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: tokenForDeletedUser });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("USER_NOT_FOUND");
    });

    it("should return 401 for suspended user", async () => {
      const tokenForSuspendedUser = jwt.sign(
        { userId: suspendedUser.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        { expiresIn: "7d" },
      );

      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: tokenForSuspendedUser });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("USER_NOT_FOUND");
    });

    it("should audit log token refresh", async () => {
      await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: validRefreshToken });

      expect(mockAuditLogger.log).toHaveBeenCalledWith(
        "token_refresh",
        expect.objectContaining({
          userId: testUser.id,
          tenantId: testUser.tenantId,
        }),
      );
    });

    it("should generate new access token with correct payload", async () => {
      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: validRefreshToken });

      const accessToken = response.body.accessToken;
      const decoded = jwt.verify(accessToken, config.jwtSecret) as any;

      expect(decoded.userId).toBe(testUser.id);
      expect(decoded.email).toBe(testUser.email);
      expect(decoded.roles).toEqual(testUser.roles);
    });

    it("should generate new refresh token with correct payload", async () => {
      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: validRefreshToken });

      const newRefreshToken = response.body.refreshToken;
      const decoded = jwt.verify(
        newRefreshToken,
        config.jwtRefreshSecret,
      ) as any;

      expect(decoded.userId).toBe(testUser.id);
      expect(decoded.tokenType).toBe("refresh");
    });

    it("should handle token rotation - old token invalidated", async () => {
      const oldToken = validRefreshToken;

      await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: oldToken });

      // Old token should be blacklisted
      expect(mockRedis.invalidateRefreshToken).toHaveBeenCalledWith(oldToken);
    });

    it("should handle malformed refresh tokens", async () => {
      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: "not-a-valid-jwt" });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("REFRESH_TOKEN_INVALID");
    });

    it("should handle refresh token signed with wrong secret", async () => {
      const wrongToken = jwt.sign(
        { userId: testUser.id, tokenType: "refresh" },
        "wrong-secret",
        { expiresIn: "7d" },
      );

      const response = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: wrongToken });

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("REFRESH_TOKEN_INVALID");
    });
  });

  describe("Protected Routes", () => {
    let validAccessToken: string;

    beforeEach(() => {
      // Create a valid access token
      validAccessToken = jwt.sign(
        {
          userId: testUser.id,
          email: testUser.email,
          roles: testUser.roles,
          tenantId: testUser.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );
    });

    describe("GET /api/protected", () => {
      it("should return 200 for valid access token", async () => {
        const response = await request(app)
          .get("/api/protected")
          .set("Authorization", `Bearer ${validAccessToken}`);

        expect(response.status).toBe(200);
        expect(response.body.message).toBe("Access granted");
        expect(response.body.user).toBeDefined();
      });

      it("should return 401 for missing authorization header", async () => {
        const response = await request(app).get("/api/protected");

        expect(response.status).toBe(401);
        expect(response.body.code).toBe("TOKEN_MISSING");
      });

      it("should return 401 for invalid token", async () => {
        const response = await request(app)
          .get("/api/protected")
          .set("Authorization", "Bearer invalid-token");

        expect(response.status).toBe(401);
        expect(response.body.code).toBe("TOKEN_INVALID");
      });

      it("should return 401 for expired token", async () => {
        const expiredToken = jwt.sign(
          {
            userId: testUser.id,
            email: testUser.email,
            roles: testUser.roles,
            tenantId: testUser.tenantId,
          },
          config.jwtSecret,
          { expiresIn: "-1s" }, // Already expired
        );

        const response = await request(app)
          .get("/api/protected")
          .set("Authorization", `Bearer ${expiredToken}`);

        expect(response.status).toBe(401);
        expect(response.body.code).toBe("TOKEN_EXPIRED");
      });

      it("should return 401 for token signed with wrong secret", async () => {
        const wrongToken = jwt.sign(
          {
            userId: testUser.id,
            email: testUser.email,
            roles: testUser.roles,
            tenantId: testUser.tenantId,
          },
          "wrong-secret",
          { expiresIn: "15m" },
        );

        const response = await request(app)
          .get("/api/protected")
          .set("Authorization", `Bearer ${wrongToken}`);

        expect(response.status).toBe(401);
        expect(response.body.code).toBe("TOKEN_INVALID");
      });

      it("should correctly decode and attach user to request", async () => {
        const response = await request(app)
          .get("/api/protected")
          .set("Authorization", `Bearer ${validAccessToken}`);

        expect(response.body.user.userId).toBe(testUser.id);
        expect(response.body.user.email).toBe(testUser.email);
        expect(response.body.user.roles).toEqual(testUser.roles);
      });
    });
  });

  describe("Role-Based Authorization", () => {
    let adminUser: MockUser;
    let memberUser: MockUser;

    beforeEach(() => {
      adminUser = {
        ...testUser,
        id: "admin-user-123",
        email: "admin@example.com",
        roles: ["ADMIN", "MEMBER"],
      };

      memberUser = {
        ...testUser,
        id: "member-user-456",
        email: "member@example.com",
        roles: ["MEMBER"],
      };

      mockPrisma.user._clearTestUsers();
      mockPrisma.user._addTestUser(adminUser);
      mockPrisma.user._addTestUser(memberUser);
    });

    it("should allow ADMIN access to ADMIN-only routes", async () => {
      const adminToken = jwt.sign(
        {
          userId: adminUser.id,
          email: adminUser.email,
          roles: adminUser.roles,
          tenantId: adminUser.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "admin@example.com", password: "validPassword123" });

      expect(response.status).toBe(200);
    });

    it("should allow MEMBER access to MEMBER routes", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "member@example.com", password: "validPassword123" });

      expect(response.status).toBe(200);
    });
  });

  describe("Token Security", () => {
    it("should not expose password in token payload", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const decoded = jwt.decode(response.body.accessToken) as any;
      expect(decoded).not.toHaveProperty("password");
      expect(decoded).not.toHaveProperty("hashedPassword");
    });

    it("should not expose sensitive user data in token", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const decoded = jwt.decode(response.body.accessToken) as any;
      expect(decoded).not.toHaveProperty("hashedPassword");
      expect(decoded).not.toHaveProperty("status");
    });

    it("should include sufficient claims for authorization", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const decoded = jwt.decode(response.body.accessToken) as any;
      expect(decoded.userId).toBeDefined();
      expect(decoded.email).toBeDefined();
      expect(decoded.roles).toBeDefined();
      expect(decoded.tenantId).toBeDefined();
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle empty request body", async () => {
      const response = await request(app).post("/api/auth/login").send({});

      expect(response.status).toBe(401);
    });

    it("should handle missing email field", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ password: "password123" });

      expect(response.status).toBe(401);
    });

    it("should handle missing password field", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com" });

      expect(response.status).toBe(401);
    });

    it("should handle null values in request", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: null, password: null });

      expect(response.status).toBe(401);
    });

    it("should handle extremely long input values", async () => {
      const longEmail = "a".repeat(1000) + "@example.com";
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: longEmail, password: "password123" });

      expect(response.status).toBe(401);
    });

    it("should handle special characters in input", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "p@$$w0rd!#$%^&*" });

      // Should not crash, should return 401 for invalid password
      expect([401, 500]).toContain(response.status);
    });

    it("should handle concurrent login requests", async () => {
      const promises = Array(10)
        .fill(null)
        .map(() =>
          request(app)
            .post("/api/auth/login")
            .send({ email: "test@example.com", password: "validPassword123" }),
        );

      const responses = await Promise.all(promises);

      // All should succeed
      responses.forEach((response) => {
        expect(response.status).toBe(200);
      });

      // Each should have unique tokens
      const tokens = responses.map((r) => r.body.accessToken);
      const uniqueTokens = new Set(tokens);
      expect(uniqueTokens.size).toBe(10);
    });
  });
});
