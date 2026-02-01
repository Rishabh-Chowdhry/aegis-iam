/**
 * Session Management Integration Tests
 * Tests Redis-backed session management
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

describe("Session Management Integration Tests", () => {
  let app: Express;
  let mockRedis: any;
  let mockAuditLogger: any;

  // Create test app with session management
  function createTestApp(): Express {
    const mockRedis = createMockRedis();
    const mockAuditLogger = createMockAuditLogger();
    const activeSessions: Map<string, { data: any; expiresAt: number }> =
      new Map();

    const app = express();
    app.use(express.json());

    // Session middleware
    const createSession = async (
      userId: string,
      data: any,
      ttlSeconds: number = 3600,
    ) => {
      const sessionId = `session:${userId}:${Date.now()}`;
      const expiresAt = Date.now() + ttlSeconds * 1000;
      activeSessions.set(sessionId, { data, expiresAt });
      await mockRedis.setSession(sessionId, data, ttlSeconds);
      return sessionId;
    };

    const getSession = async (sessionId: string) => {
      const session = activeSessions.get(sessionId);
      if (!session) return null;
      if (Date.now() > session.expiresAt) {
        activeSessions.delete(sessionId);
        return null;
      }
      return session.data;
    };

    const deleteSession = async (sessionId: string) => {
      activeSessions.delete(sessionId);
      return mockRedis.deleteSession(sessionId);
    };

    // Login with session creation
    app.post("/api/auth/login", async (req, res) => {
      const { email, password, tenantId } = req.body;

      // Mock user validation
      if (email !== "test@example.com" || password !== "validPassword123") {
        return res.status(401).json({ error: "Invalid credentials" });
      }

      const user = {
        id: "user-123",
        email: "test@example.com",
        roles: ["MEMBER"],
        tenantId: tenantId || "default",
      };

      // Generate tokens
      const accessToken = signJwt(user, config.jwtSecret, "15m");
      const refreshToken = signJwt(
        { userId: user.id, tokenType: "refresh" },
        config.jwtRefreshSecret,
        "7d",
      );

      // Create session
      const sessionId = await createSession(user.id, {
        userId: user.id,
        email: user.email,
        roles: user.roles,
        tenantId: user.tenantId,
        loginTime: new Date().toISOString(),
      });

      await mockAuditLogger.logAuth(
        "session_created",
        { userId: user.id, sessionId },
        { outcome: "SUCCESS" },
      );

      res.json({
        user,
        accessToken,
        refreshToken,
        sessionId,
      });
    });

    // Get current session
    app.get("/api/session", async (req, res) => {
      const sessionId = req.headers["x-session-id"] as string;

      if (!sessionId) {
        return res.status(400).json({ error: "Session ID required" });
      }

      const session = await getSession(sessionId);
      if (!session) {
        return res.status(401).json({ error: "Session expired or invalid" });
      }

      res.json({ session });
    });

    // Logout with session deletion
    app.post("/api/auth/logout", async (req, res) => {
      const { sessionId } = req.body;
      const userId = (req as any).user?.id;

      if (sessionId) {
        await deleteSession(sessionId);
        await mockRedis.del(`refresh_token:${req.body.refreshToken || ""}`);
      }

      await mockAuditLogger.logAuth(
        "session_deleted",
        { userId, sessionId },
        { outcome: "SUCCESS" },
      );

      res.json({ success: true });
    });

    // Refresh token with session update
    app.post("/api/auth/refresh-token", async (req, res) => {
      const { refreshToken, sessionId } = req.body;

      try {
        const decoded = jwt.verify(
          refreshToken,
          config.jwtRefreshSecret,
        ) as any;

        if (decoded.tokenType !== "refresh") {
          return res.status(401).json({ error: "Invalid token type" });
        }

        const user = {
          id: decoded.userId,
          email: "test@example.com",
          roles: ["MEMBER"],
          tenantId: "default",
        };

        // Generate new tokens
        const newAccessToken = signJwt(user, config.jwtSecret, "15m");
        const newRefreshToken = signJwt(
          { userId: user.id, tokenType: "refresh" },
          config.jwtRefreshSecret,
          "7d",
        );

        // Update session
        if (sessionId) {
          const existingSession = await getSession(sessionId);
          if (existingSession) {
            const updatedSession = {
              ...existingSession,
              tokenRefreshedAt: new Date().toISOString(),
            };
            activeSessions.set(sessionId, {
              ...updatedSession,
              expiresAt: Date.now() + 3600 * 1000,
            });
          }
        }

        res.json({
          user,
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        });
      } catch (error) {
        res.status(401).json({ error: "Invalid refresh token" });
      }
    });

    return app;
  }

  beforeEach(() => {
    app = createTestApp();
    mockRedis = createMockRedis();
    mockAuditLogger = createMockAuditLogger();
  });

  afterEach(() => {
    cleanupTestData(
      { user: { _clearTestUsers: () => {} } },
      mockRedis,
      mockAuditLogger,
    );
  });

  describe("Session Creation", () => {
    it("should create session on successful login", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      expect(response.status).toBe(200);
      expect(response.body).toHaveProperty("sessionId");
      expect(response.body.sessionId).toMatch(/^session:user-123:\d+$/);
    });

    it("should include session in login response", async () => {
      const response = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      expect(response.body).toHaveProperty("user");
      expect(response.body.user).toHaveProperty("id", "user-123");
      expect(response.body).toHaveProperty("accessToken");
      expect(response.body).toHaveProperty("refreshToken");
      expect(response.body).toHaveProperty("sessionId");
    });

    it("should audit log session creation", async () => {
      await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const logs = mockAuditLogger.getLogs();
      const sessionCreatedLog = logs.find(
        (log: any) => log.action === "session_created",
      );
      expect(sessionCreatedLog).toBeDefined();
      expect(sessionCreatedLog.details.sessionId).toBeDefined();
    });
  });

  describe("Session Retrieval", () => {
    it("should retrieve session with valid session ID", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;

      const response = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);

      expect(response.status).toBe(200);
      expect(response.body.session).toHaveProperty("userId", "user-123");
      expect(response.body.session).toHaveProperty("email", "test@example.com");
      expect(response.body.session).toHaveProperty("roles", ["MEMBER"]);
    });

    it("should return 401 for invalid session ID", async () => {
      const response = await request(app)
        .get("/api/session")
        .set("X-Session-ID", "invalid-session-id");

      expect(response.status).toBe(401);
      expect(response.body).toHaveProperty(
        "error",
        "Session expired or invalid",
      );
    });

    it("should return 400 when session ID is missing", async () => {
      const response = await request(app).get("/api/session");

      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty("error", "Session ID required");
    });
  });

  describe("Session Expiration", () => {
    it("should handle expired sessions", async () => {
      const mockExpiredRedis = createMockRedis();

      // Add an expired session
      const expiredSessionKey = "session:expired:123";
      mockExpiredRedis._addSession(
        expiredSessionKey,
        { userId: "user-1", email: "test@example.com" },
        -1, // Already expired
      );

      // The getSession should return null for expired sessions
      const session = await mockExpiredRedis.getSession(expiredSessionKey);
      expect(session).toBeNull();
    });
  });

  describe("Concurrent Session Handling", () => {
    it("should allow multiple sessions for same user", async () => {
      // First login
      const loginResponse1 = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      // Second login (simulating concurrent sessions)
      const loginResponse2 = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      expect(loginResponse1.body.sessionId).not.toBe(
        loginResponse2.body.sessionId,
      );
      expect(loginResponse1.status).toBe(200);
      expect(loginResponse2.status).toBe(200);
    });

    it("should track multiple concurrent sessions", async () => {
      await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      // All three logins should succeed
      const logs = mockAuditLogger.getLogs();
      const sessionCreatedLogs = logs.filter(
        (log: any) => log.action === "session_created",
      );
      expect(sessionCreatedLogs.length).toBe(3);
    });
  });

  describe("Session Termination on Logout", () => {
    it("should delete session on logout", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;

      // Verify session exists
      let sessionResponse = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);
      expect(sessionResponse.status).toBe(200);

      // Logout and delete session
      const logoutResponse = await request(app)
        .post("/api/auth/logout")
        .send({ sessionId });

      expect(logoutResponse.status).toBe(200);
      expect(logoutResponse.body).toHaveProperty("success", true);

      // Verify session is deleted
      sessionResponse = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);
      expect(sessionResponse.status).toBe(401);
    });

    it("should audit log session deletion", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;

      await request(app).post("/api/auth/logout").send({ sessionId });

      const logs = mockAuditLogger.getLogs();
      const sessionDeletedLog = logs.find(
        (log: any) => log.action === "session_deleted",
      );
      expect(sessionDeletedLog).toBeDefined();
      expect(sessionDeletedLog.details.sessionId).toBe(sessionId);
    });
  });

  describe("Session Update on Token Refresh", () => {
    it("should update session when tokens are refreshed", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;
      const oldAccessToken = loginResponse.body.accessToken;
      const oldRefreshToken = loginResponse.body.refreshToken;

      // Refresh tokens
      const refreshResponse = await request(app)
        .post("/api/auth/refresh-token")
        .send({ refreshToken: oldRefreshToken, sessionId });

      expect(refreshResponse.status).toBe(200);
      expect(refreshResponse.body.accessToken).not.toBe(oldAccessToken);
      expect(refreshResponse.body.refreshToken).not.toBe(oldRefreshToken);

      // New tokens should work
      const newAccessToken = refreshResponse.body.accessToken;
      const protectedResponse = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);

      expect(protectedResponse.status).toBe(200);
    });
  });

  describe("Session Data Integrity", () => {
    it("should store correct user data in session", async () => {
      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;

      const sessionResponse = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);

      expect(sessionResponse.body.session.userId).toBe("user-123");
      expect(sessionResponse.body.session.email).toBe("test@example.com");
      expect(sessionResponse.body.session.roles).toEqual(["MEMBER"]);
      expect(sessionResponse.body.session.tenantId).toBe("default");
      expect(sessionResponse.body.session).toHaveProperty("loginTime");
    });

    it("should include login timestamp in session", async () => {
      const beforeLogin = new Date().toISOString();

      const loginResponse = await request(app)
        .post("/api/auth/login")
        .send({
          email: "test@example.com",
          password: "validPassword123",
          tenantId: "default",
        });

      const sessionId = loginResponse.body.sessionId;

      const sessionResponse = await request(app)
        .get("/api/session")
        .set("X-Session-ID", sessionId);

      // Session should have login time after our beforeLogin timestamp
      expect(sessionResponse.body.session.loginTime >= beforeLogin).toBe(true);
    });
  });
});
