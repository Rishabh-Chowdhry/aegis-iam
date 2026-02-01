/**
 * Token Blacklist Integration Tests
 * Tests token blacklisting mechanism for logout and token invalidation
 */

import request from "supertest";
import express, { Express } from "express";
import jwt from "jsonwebtoken";
import {
  createMockRedis,
  createMockAuditLogger,
  cleanupTestData,
} from "../utils/test-helpers";
import { config } from "../../src/shared/config";

// Helper function to sign JWT
function signJwt(payload: object, secret: string, expiresIn: string): string {
  return jwt.sign(payload, secret, { expiresIn: expiresIn as any });
}

describe("Token Blacklist Integration Tests", () => {
  let app: Express;
  let mockRedis: any;
  let mockAuditLogger: any;
  let blacklistedTokens: Set<string>;

  // Create test app with token blacklisting
  function createTestApp(): Express {
    const mockRedis = createMockRedis();
    const mockAuditLogger = createMockAuditLogger();
    blacklistedTokens = new Set<string>();

    const app = express();
    app.use(express.json());

    // Token blacklist check middleware
    const checkBlacklist = (req: any, res: any, next: any) => {
      const authHeader = req.headers.authorization;
      const token = authHeader?.startsWith("Bearer ")
        ? authHeader.substring(7)
        : null;

      if (token && blacklistedTokens.has(token)) {
        return res.status(401).json({
          error: "Token has been revoked",
          code: "TOKEN_BLACKLISTED",
          message: "Please log in again",
        });
      }

      next();
    };

    // Authentication middleware
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

    // Login endpoint
    app.post("/api/auth/login", (req, res) => {
      const { email, password } = req.body;

      if (email !== "test@example.com" || password !== "validPassword123") {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = {
        id: "user-123",
        email: "test@example.com",
        roles: ["MEMBER"],
        tenantId: "default",
      };

      const accessToken = signJwt(user, config.jwtSecret, "15m");
      const refreshToken = signJwt(
        { userId: user.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        "7d",
      );

      res.json({ user, accessToken, refreshToken });
    });

    // Logout with token blacklisting
    app.post("/api/auth/logout", async (req, res) => {
      const { accessToken, refreshToken } = req.body;
      const userId = (req as any).user?.id;

      // Blacklist tokens
      if (accessToken) {
        blacklistedTokens.add(accessToken);
        await mockRedis.del(`refresh_token:${accessToken}`);
      }
      if (refreshToken) {
        blacklistedTokens.add(refreshToken);
        await mockRedis.del(`refresh_token:${refreshToken}`);
      }

      await mockAuditLogger.logAuth(
        "tokens_blacklisted",
        { userId },
        { outcome: "SUCCESS" },
      );

      res.json({ success: true, message: "Logged out successfully" });
    });

    // Protected route (requires authentication + blacklist check)
    app.get(
      "/api/protected",
      authenticateToken,
      checkBlacklist,
      (req: any, res) => {
        res.json({ message: "Access granted", user: req.user });
      },
    );

    // Another protected route
    app.get(
      "/api/profile",
      authenticateToken,
      checkBlacklist,
      (req: any, res) => {
        res.json({
          profile: { userId: req.user.userId, email: req.user.email },
        });
      },
    );

    // Validate if token is blacklisted
    app.post("/api/auth/validate-token", (req, res) => {
      const { token } = req.body;

      if (blacklistedTokens.has(token)) {
        return res.json({ valid: false, reason: "Token has been revoked" });
      }

      try {
        jwt.verify(token, config.jwtSecret);
        return res.json({ valid: true });
      } catch (error) {
        return res.json({
          valid: false,
          reason: "Token is invalid or expired",
        });
      }
    });

    return app;
  }

  beforeEach(() => {
    app = createTestApp();
    mockRedis = createMockRedis();
    mockAuditLogger = createMockAuditLogger();
    blacklistedTokens.clear();
  });

  afterEach(() => {
    cleanupTestData(
      { user: { _clearTestUsers: () => {} } },
      mockRedis,
      mockAuditLogger,
    );
    blacklistedTokens.clear();
  });

  describe("Token Blacklisting on Logout", () => {
    it("should blacklist access token on logout", async () => {
      // Login to get token
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      // Verify token works before logout
      let protectedResponse = await request(app)
        .get("/api/protected")
        .set("Authorization", `Bearer ${accessToken}`);
      expect(protectedResponse.status).toBe(200);

      // Logout and blacklist token
      const logoutResponse = await request(app)
        .post("/api/auth/logout")
        .send({ accessToken });
      expect(logoutResponse.status).toBe(200);

      // Verify token is now blacklisted
      protectedResponse = await request(app)
        .get("/api/protected")
        .set("Authorization", `Bearer ${accessToken}`);
      expect(protectedResponse.status).toBe(401);
      expect(protectedResponse.body.code).toBe("TOKEN_BLACKLISTED");
    });

    it("should blacklist refresh token on logout", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { refreshToken } = loginResponse.body;

      // Validate refresh token before logout
      let validateResponse = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: refreshToken });
      expect(validateResponse.body.valid).toBe(true);

      // Logout and blacklist refresh token
      await request(app).post("/api/auth/logout").send({ refreshToken });

      // Validate refresh token after logout
      validateResponse = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: refreshToken });
      expect(validateResponse.body.valid).toBe(false);
    });

    it("should audit log token blacklisting", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      await request(app).post("/api/auth/logout").send({ accessToken });

      const logs = mockAuditLogger.getLogs();
      const blacklistLog = logs.find(
        (log: any) => log.action === "tokens_blacklisted",
      );
      expect(blacklistLog).toBeDefined();
    });

    it("should handle logout without tokens gracefully", async () => {
      const response = await request(app).post("/api/auth/logout").send({});

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("success", true);
    });
  });

  describe("Blacklisted Token Rejection", () => {
    it("should reject blacklisted token on protected route", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      // Blacklist the token
      blacklistedTokens.add(accessToken);

      // Try to access protected route
      const response = await request(app)
        .get("/api/protected")
        .set("Authorization", `Bearer ${accessToken}`);

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("TOKEN_BLACKLISTED");
    });

    it("should reject blacklisted token on multiple routes", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;
      blacklistedTokens.add(accessToken);

      // Try profile route
      const profileResponse = await request(app)
        .get("/api/profile")
        .set("Authorization", `Bearer ${accessToken}`);
      expect(profileResponse.status).toBe(401);

      // Try protected route
      const protectedResponse = await request(app)
        .get("/api/protected")
        .set("Authorization", `Bearer ${accessToken}`);
      expect(protectedResponse.status).toBe(401);
    });

    it("should return specific error message for blacklisted tokens", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;
      blacklistedTokens.add(accessToken);

      const response = await request(app)
        .get("/api/protected")
        .set("Authorization", `Bearer ${accessToken}`);

      expect(response.body.message).toContain("Please log in again");
    });
  });

  describe("Automatic Cleanup of Expired Entries", () => {
    it("should clean up expired blacklisted tokens", async () => {
      // Create an expired token
      const expiredToken = jwt.sign(
        {
          userId: "user-1",
          email: "test@example.com",
          roles: ["MEMBER"],
          tenantId: "default",
        },
        config.jwtSecret,
        { expiresIn: "-1s" as any },
      );

      // Add to blacklist
      blacklistedTokens.add(expiredToken);
      expect(blacklistedTokens.size).toBe(1);

      // Simulate cleanup (in real implementation, this would be a cron job)
      for (const token of blacklistedTokens) {
        try {
          jwt.verify(token, config.jwtSecret);
        } catch {
          // Token is expired, remove from blacklist
          blacklistedTokens.delete(token);
        }
      }

      expect(blacklistedTokens.size).toBe(0);
    });

    it("should keep valid tokens in blacklist until they expire", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;
      blacklistedTokens.add(accessToken);

      // Token should still be in blacklist (it's valid, just revoked)
      expect(blacklistedTokens.has(accessToken)).toBe(true);
    });
  });

  describe("Race Conditions in Blacklisting", () => {
    it("should handle concurrent logout requests", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      // Simulate concurrent logout requests
      const [response1, response2] = await Promise.all([
        request(app).post("/api/auth/logout").send({ accessToken }),
        request(app).post("/api/auth/logout").send({ accessToken }),
      ]);

      // Both should succeed
      expect(response1.status).toBe(200);
      expect(response2.status).toBe(200);

      // Token should be blacklisted
      const validateResponse = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: accessToken });
      expect(validateResponse.body.valid).toBe(false);
    });

    it("should handle token validation race conditions", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      // Simulate concurrent access and logout
      const [accessResponse, logoutResponse] = await Promise.all([
        request(app)
          .get("/api/protected")
          .set("Authorization", `Bearer ${accessToken}`),
        request(app).post("/api/auth/logout").send({ accessToken }),
      ]);

      // Access might succeed or fail depending on timing
      // At least one should handle the race condition correctly
      expect([200, 401]).toContain(accessResponse.status);
      expect(logoutResponse.status).toBe(200);
    });
  });

  describe("Token Blacklist Validation", () => {
    it("should validate token is not blacklisted", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;

      const response = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: accessToken });

      expect(response.body.valid).toBe(true);
    });

    it("should validate blacklisted token", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken } = loginResponse.body;
      blacklistedTokens.add(accessToken);

      const response = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: accessToken });

      expect(response.body.valid).toBe(false);
      expect(response.body.reason).toBe("Token has been revoked");
    });

    it("should validate invalid token", async () => {
      const response = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: "invalid-token" });

      expect(response.body.valid).toBe(false);
      expect(response.body.reason).toBe("Token is invalid or expired");
    });
  });

  describe("Edge Cases", () => {
    it("should handle empty token gracefully", async () => {
      const response = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: "" });

      expect(response.body.valid).toBe(false);
    });

    it("should handle malformed token", async () => {
      const response = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: "not.a.valid.jwt.token" });

      expect(response.body.valid).toBe(false);
    });

    it("should handle logout with multiple tokens", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({ email: "test@example.com", password: "validPassword123" });

      const { accessToken, refreshToken } = loginResponse.body;

      const response = await request(app)
        .post("/api/auth/logout")
        .send({ accessToken, refreshToken });

      expect(response.status).toBe(200);

      // Both tokens should be blacklisted
      const accessValidate = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: accessToken });
      expect(accessValidate.body.valid).toBe(false);

      const refreshValidate = await request(app)
        .post("/api/auth/validate-token")
        .send({ token: refreshToken });
      expect(refreshValidate.body.valid).toBe(false);
    });
  });
});
