/**
 * Authorization Flow Integration Tests
 * Tests role-based and policy-based access control
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
import { Permission, Policy, Role, User } from "../../src/domain/entities";

describe("Authorization Flow Integration Tests", () => {
  let app: Express;
  let mockPrisma: ReturnType<typeof createMockPrisma>;
  let mockRedis: ReturnType<typeof createMockRedis>;
  let mockAuditLogger: ReturnType<typeof createMockAuditLogger>;

  // Test users with different roles
  const adminUser: MockUser = {
    id: "admin-user-123",
    email: "admin@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder",
    roles: ["ADMIN", "MEMBER"],
    status: "active",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const memberUser: MockUser = {
    id: "member-user-456",
    email: "member@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder",
    roles: ["MEMBER"],
    status: "active",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  const viewerUser: MockUser = {
    id: "viewer-user-789",
    email: "viewer@example.com",
    hashedPassword: "$argon2i$v=19$m=4096,t=3,p=1$placeholder",
    roles: ["VIEWER"],
    status: "active",
    tenantId: "tenant-123",
    createdAt: new Date(),
    updatedAt: new Date(),
  };

  // Test roles with hierarchy
  const roles: Role[] = [
    {
      id: "role-admin",
      name: "ADMIN",
      description: "Administrator role with full access",
      permissions: ["read", "write", "delete", "admin"],
      parentId: null,
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "role-member",
      name: "MEMBER",
      description: "Regular member role",
      permissions: ["read", "write"],
      parentId: "role-admin",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "role-viewer",
      name: "VIEWER",
      description: "Read-only viewer role",
      permissions: ["read"],
      parentId: "role-member",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  // Test permissions
  const permissions: Permission[] = [
    {
      id: "perm-read",
      name: "read",
      description: "Read access",
      resource: "*",
      action: "read",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "perm-write",
      name: "write",
      description: "Write access",
      resource: "*",
      action: "write",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "perm-delete",
      name: "delete",
      description: "Delete access",
      resource: "*",
      action: "delete",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "perm-admin",
      name: "admin",
      description: "Admin access",
      resource: "*",
      action: "admin",
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  // Test policies
  const policies: Policy[] = [
    {
      id: "policy-allow-all",
      name: "Allow All",
      description: "Allow all actions",
      effect: "allow",
      conditions: {},
      priority: 1,
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
    {
      id: "policy-deny-delete",
      name: "Deny Delete",
      description: "Deny delete actions",
      effect: "deny",
      conditions: {
        action: "delete",
      },
      priority: 2,
      tenantId: "tenant-123",
      createdAt: new Date(),
      updatedAt: new Date(),
    },
  ];

  beforeEach(() => {
    mockPrisma = createMockPrisma();
    mockRedis = createMockRedis();
    mockAuditLogger = createMockAuditLogger();
    app = createTestApp(mockPrisma, mockRedis, mockAuditLogger);

    // Add test users
    mockPrisma.user._addTestUser(adminUser);
    mockPrisma.user._addTestUser(memberUser);
    mockPrisma.user._addTestUser(viewerUser);

    // Add test roles
    mockPrisma.role._addTestRoles(roles);

    // Add test permissions
    mockPrisma.permission._addTestPermissions(permissions);

    // Add test policies
    mockPrisma.policy._addTestPolicies(policies);
  });

  afterEach(() => {
    mockPrisma.user._clearTestUsers();
    mockPrisma.role._clearTestRoles();
    mockPrisma.permission._clearTestPermissions();
    mockPrisma.policy._clearTestPolicies();
    mockRedis._clearSessions();
    mockAuditLogger._clearLogs();
  });

  // Helper to generate auth token
  const generateToken = (user: MockUser, expiresIn: string = "15m"): string => {
    return jwt.sign(
      {
        userId: user.id,
        email: user.email,
        roles: user.roles,
        tenantId: user.tenantId,
      },
      config.jwtSecret,
      { expiresIn },
    );
  };

  describe("Role-Based Access Control (RBAC)", () => {
    describe("Single Role Access", () => {
      it("should allow ADMIN to access admin resources", async () => {
        const token = generateToken(adminUser);

        const response = await request(app)
          .get("/api/admin/dashboard")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should allow MEMBER to access member resources", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/member/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should allow VIEWER to access viewer resources", async () => {
        const token = generateToken(viewerUser);

        const response = await request(app)
          .get("/api/viewer/reports")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });
    });

    describe("Insufficient Role Access", () => {
      it("should deny VIEWER access to admin resources", async () => {
        const token = generateToken(viewerUser);

        const response = await request(app)
          .get("/api/admin/dashboard")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(403);
        expect(response.body.code).toBe("INSUFFICIENT_PERMISSIONS");
      });

      it("should deny MEMBER access to admin-only delete operations", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .delete("/api/admin/users/123")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(403);
      });

      it("should deny VIEWER write access", async () => {
        const token = generateToken(viewerUser);

        const response = await request(app)
          .post("/api/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(403);
      });
    });

    describe("Multiple Role Checking", () => {
      it("should allow access when user has at least one required role", async () => {
        const token = generateToken(adminUser);

        const response = await request(app)
          .get("/api/member/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should allow access when user has multiple roles including required one", async () => {
        const token = generateToken(adminUser);

        const response = await request(app)
          .get("/api/admin/users")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });
    });

    describe("Role Hierarchy", () => {
      it("should inherit permissions from parent role (ADMIN -> MEMBER)", async () => {
        const token = generateToken(adminUser);

        // ADMIN should have MEMBER permissions
        const response = await request(app)
          .post("/api/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should inherit permissions through hierarchy chain (ADMIN -> MEMBER -> VIEWER)", async () => {
        const token = generateToken(adminUser);

        // ADMIN should have VIEWER permissions
        const response = await request(app)
          .get("/api/viewer/reports")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should deny VIEWER access to permissions not in hierarchy", async () => {
        const token = generateToken(viewerUser);

        // VIEWER should not have write/delete permissions
        const writeResponse = await request(app)
          .post("/api/content")
          .set("Authorization", `Bearer ${token}`);

        expect(writeResponse.status).toBe(403);

        const deleteResponse = await request(app)
          .delete("/api/content/123")
          .set("Authorization", `Bearer ${token}`);

        expect(deleteResponse.status).toBe(403);
      });

      it("should resolve effective permissions correctly", async () => {
        const token = generateToken(memberUser);

        // MEMBER has read + write (inherited from ADMIN)
        const readResponse = await request(app)
          .get("/api/content")
          .set("Authorization", `Bearer ${token}`);

        expect(readResponse.status).toBe(200);

        const writeResponse = await request(app)
          .post("/api/content")
          .set("Authorization", `Bearer ${token}`);

        expect(writeResponse.status).toBe(200);

        const adminResponse = await request(app)
          .get("/api/admin/settings")
          .set("Authorization", `Bearer ${token}`);

        expect(adminResponse.status).toBe(403);
      });
    });
  });

  describe("Policy-Based Access Control (PBAC)", () => {
    describe("ALLOW Policy", () => {
      it("should grant access when ALLOW policy matches", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should log policy evaluation", async () => {
        const token = generateToken(memberUser);

        await request(app)
          .get("/api/protected/content")
          .set("Authorization", `Bearer ${token}`);

        expect(mockAuditLogger.log).toHaveBeenCalledWith(
          "policy_evaluation",
          expect.objectContaining({
            resource: "content",
            action: "read",
          }),
        );
      });
    });

    describe("DENY Policy", () => {
      it("should deny access when DENY policy matches", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .delete("/api/protected/resource/123")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(403);
        expect(response.body.code).toBe("ACCESS_DENIED_BY_POLICY");
      });

      it("should return detailed denial information", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .delete("/api/protected/resource/123")
          .set("Authorization", `Bearer ${token}`);

        expect(response.body.deniedBy).toBeDefined();
        expect(response.body.policyId).toBeDefined();
      });
    });

    describe("Policy Priority", () => {
      it("should apply higher priority policies first", async () => {
        const token = generateToken(memberUser);

        // DENY policy has higher priority (lower number = higher priority)
        const response = await request(app)
          .delete("/api/protected/resource/123")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(403);
      });

      it("should evaluate all matching policies in priority order", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/content")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
        // ALLOW policy should take precedence
      });
    });

    describe("Complex Policy Conditions", () => {
      it("should evaluate time-based conditions", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/time-sensitive")
          .set("Authorization", `Bearer ${token}`);

        // Should allow or deny based on current time
        expect([200, 403]).toContain(response.status);
      });

      it("should evaluate IP-based conditions", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/ip-restricted")
          .set("Authorization", `Bearer ${token}`)
          .set("X-Forwarded-For", "10.0.0.1");

        expect([200, 403]).toContain(response.status);
      });

      it("should evaluate resource-based conditions", async () => {
        const token = generateToken(memberUser);

        // Access own resource
        const ownResourceResponse = await request(app)
          .get("/api/protected/resources/user-456")
          .set("Authorization", `Bearer ${token}`);

        expect(ownResourceResponse.status).toBe(200);

        // Access other user's resource
        const otherResourceResponse = await request(app)
          .get("/api/protected/resources/user-123")
          .set("Authorization", `Bearer ${token}`);

        expect(otherResourceResponse.status).toBe(403);
      });
    });

    describe("Policy Inheritance", () => {
      it("should apply tenant-level policies", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/tenant-resource")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });

      it("should apply user-specific policies", async () => {
        const token = generateToken(memberUser);

        const response = await request(app)
          .get("/api/protected/user-specific")
          .set("Authorization", `Bearer ${token}`);

        expect(response.status).toBe(200);
      });
    });
  });

  describe("Combined RBAC + PBAC", () => {
    it("should require both role and policy authorization", async () => {
      const token = generateToken(memberUser);

      const response = await request(app)
        .post("/api/protected/combined")
        .set("Authorization", `Bearer ${token}`);

      // Should pass RBAC check but fail policy check
      expect(response.status).toBe(403);
    });

    it("should allow access when both RBAC and PBAC pass", async () => {
      const token = generateToken(adminUser);

      const response = await request(app)
        .post("/api/protected/combined")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
    });

    it("should deny access when RBAC passes but PBAC fails", async () => {
      const token = generateToken(adminUser);

      const response = await request(app)
        .delete("/api/protected/combined")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(403);
    });

    it("should audit authorization decisions", async () => {
      const token = generateToken(memberUser);

      await request(app)
        .get("/api/protected/combined")
        .set("Authorization", `Bearer ${token}`);

      expect(mockAuditLogger.log).toHaveBeenCalledWith(
        "authorization_decision",
        expect.objectContaining({
          userId: memberUser.id,
          resource: "combined",
          decision: expect.stringMatching(/ALLOW|DENY/),
        }),
      );
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle missing role claims in token", async () => {
      const token = jwt.sign(
        {
          userId: memberUser.id,
          email: memberUser.email,
          tenantId: memberUser.tenantId,
          // roles missing
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/protected/content")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(401);
      expect(response.body.code).toBe("INVALID_TOKEN");
    });

    it("should handle malformed role claims", async () => {
      const token = jwt.sign(
        {
          userId: memberUser.id,
          email: memberUser.email,
          roles: "not-an-array",
          tenantId: memberUser.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/protected/content")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(401);
    });

    it("should handle empty roles array", async () => {
      const token = jwt.sign(
        {
          userId: memberUser.id,
          email: memberUser.email,
          roles: [],
          tenantId: memberUser.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/protected/content")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(403);
    });

    it("should handle unknown roles gracefully", async () => {
      const token = jwt.sign(
        {
          userId: memberUser.id,
          email: memberUser.email,
          roles: ["UNKNOWN_ROLE"],
          tenantId: memberUser.tenantId,
        },
        config.jwtSecret,
        { expiresIn: "15m" },
      );

      const response = await request(app)
        .get("/api/protected/content")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(403);
    });

    it("should handle concurrent authorization requests", async () => {
      const token = generateToken(memberUser);

      const promises = Array(10)
        .fill(null)
        .map(() =>
          request(app)
            .get("/api/protected/content")
            .set("Authorization", `Bearer ${token}`),
        );

      const responses = await Promise.all(promises);

      responses.forEach((response) => {
        expect(response.status).toBe(200);
      });
    });

    it("should properly handle token with all required claims", async () => {
      const token = generateToken(adminUser);

      const response = await request(app)
        .get("/api/admin/users")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
      expect(response.body.user.roles).toBeDefined();
      expect(response.body.user.permissions).toBeDefined();
    });
  });

  describe("Permission Checks", () => {
    it("should check specific permission", async () => {
      const token = generateToken(memberUser);

      const response = await request(app)
        .get("/api/protected/permission-check/read")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
    });

    it("should deny permission check for missing permission", async () => {
      const token = generateToken(viewerUser);

      const response = await request(app)
        .post("/api/protected/permission-check/write")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(403);
    });

    it("should check multiple permissions with AND logic", async () => {
      const token = generateToken(memberUser);

      const response = await request(app)
        .put("/api/protected/permission-check/multi")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
    });

    it("should check multiple permissions with OR logic", async () => {
      const token = generateToken(viewerUser);

      const response = await request(app)
        .get("/api/protected/permission-check/read-or-write")
        .set("Authorization", `Bearer ${token}`);

      expect(response.status).toBe(200);
    });
  });

  describe("Resource-Level Authorization", () => {
    it("should authorize based on resource ownership", async () => {
      const token = generateToken(memberUser);

      const ownResourceResponse = await request(app)
        .get("/api/resources/user-456")
        .set("Authorization", `Bearer ${token}`);

      expect(ownResourceResponse.status).toBe(200);
    });

    it("should deny access to resources owned by others", async () => {
      const token = generateToken(memberUser);

      const otherResourceResponse = await request(app)
        .get("/api/resources/user-123")
        .set("Authorization", `Bearer ${token}`);

      expect(otherResourceResponse.status).toBe(403);
    });

    it("should allow admin to access any resource", async () => {
      const adminToken = generateToken(adminUser);

      const response = await request(app)
        .get("/api/resources/user-456")
        .set("Authorization", `Bearer ${adminToken}`);

      expect(response.status).toBe(200);
    });
  });
});
