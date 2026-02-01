/**
 * Policy Parser Unit Tests
 *
 * Tests for parsing and validating ABAC policy documents.
 */

import { PolicyParser } from "../src/modules/iam/policy/parser/PolicyParser";
import {
  ABACPolicy,
  PolicyEffect,
  PolicyVersion,
} from "../src/modules/iam/policy/models/types";

describe("PolicyParser", () => {
  let parser: PolicyParser;

  beforeEach(() => {
    parser = new PolicyParser();
  });

  describe("parse - Basic Parsing", () => {
    it("should parse a valid policy document", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);

      expect(policy.version).toBe("2026-01-01");
      expect(policy.tenantId).toBe("tenant-abc");
      expect(policy.statements).toHaveLength(1);
      expect(policy.statements[0].sid).toBe("Statement1");
      expect(policy.statements[0].effect).toBe("ALLOW");
    });

    it("should parse a policy with conditions", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["INVOICE_READ"] },
            resources: { types: ["invoice:*"] },
            conditions: {
              Bool: { "context.mfaAuthenticated": true },
            },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);

      expect(policy.statements[0].conditions).toBeDefined();
      expect(
        policy.statements[0].conditions?.Bool?.["context.mfaAuthenticated"],
      ).toBe(true);
    });

    it("should throw error when version is missing", () => {
      const rawPolicy = {
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });

    it("should throw error when tenantId is missing", () => {
      const rawPolicy = {
        version: "2026-01-01",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });

    it("should throw error when statements are missing", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });

    it("should throw error when statements is not an array", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: {},
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });

    it("should throw error when statements array is empty", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [],
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });
  });

  describe("parse - Effect Validation", () => {
    it("should parse ALLOW effect", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);
      expect(policy.statements[0].effect).toBe("ALLOW");
    });

    it("should parse DENY effect", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "DENY",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);
      expect(policy.statements[0].effect).toBe("DENY");
    });

    it("should throw error for invalid effect", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "MAYBE",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
      };

      expect(() => parser.parse(rawPolicy as any)).toThrow();
    });
  });

  describe("validate - Policy Validation", () => {
    it("should validate a valid policy", () => {
      const policy: ABACPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        id: "policy-123",
        name: "Test Policy",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"], excludes: [], groups: [] },
            resources: { types: ["*"], ids: [], paths: [], attributes: {} },
          },
        ],
        metadata: { description: "Test" },
        status: "ACTIVE",
      };

      const result = parser.validate(policy);
      expect(result.isValid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it("should report errors for invalid version format", () => {
      const policy: ABACPolicy = {
        version: "invalid-version" as PolicyVersion,
        tenantId: "tenant-abc",
        id: "policy-123",
        name: "Test Policy",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"], excludes: [], groups: [] },
            resources: { types: ["*"], ids: [], paths: [], attributes: {} },
          },
        ],
      };

      const result = parser.validate(policy);
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "INVALID_VERSION")).toBe(
        true,
      );
    });

    it("should report errors for missing tenantId", () => {
      const policy: ABACPolicy = {
        version: "2026-01-01",
        tenantId: "",
        id: "policy-123",
        name: "Test Policy",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"], excludes: [], groups: [] },
            resources: { types: ["*"], ids: [], paths: [], attributes: {} },
          },
        ],
      };

      const result = parser.validate(policy);
      expect(result.isValid).toBe(false);
    });

    it("should detect duplicate statement IDs", () => {
      const policy: ABACPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        id: "policy-123",
        name: "Test Policy",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"], excludes: [], groups: [] },
            resources: { types: ["*"], ids: [], paths: [], attributes: {} },
          },
          {
            sid: "Statement1",
            effect: "DENY",
            actions: { includes: ["*"], excludes: [], groups: [] },
            resources: { types: ["*"], ids: [], paths: [], attributes: {} },
          },
        ],
      };

      const result = parser.validate(policy);
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "DUPLICATE_SID")).toBe(true);
    });
  });

  describe("validateVersion - Version Validation", () => {
    it("should accept valid version format", () => {
      const result = parser.validateVersion("2026-01-01");
      expect(result.isValid).toBe(true);
    });

    it("should reject invalid version format", () => {
      const result = parser.validateVersion("invalid-version");
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "INVALID_VERSION")).toBe(
        true,
      );
    });

    it("should reject version without dashes", () => {
      const result = parser.validateVersion("20260101");
      expect(result.isValid).toBe(false);
    });

    it("should reject future version beyond 1 year", () => {
      const result = parser.validateVersion("2030-01-01");
      expect(result.isValid).toBe(false);
    });
  });

  describe("validateStatement - Statement Validation", () => {
    it("should validate a valid statement", () => {
      const statement = {
        sid: "Statement1",
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: ["*"], excludes: [], groups: [] },
        resources: { types: ["*"], ids: [], paths: [], attributes: {} },
      };

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(true);
    });

    it("should require SID", () => {
      const statement = {
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: ["*"], excludes: [], groups: [] },
        resources: { types: ["*"], ids: [], paths: [], attributes: {} },
      } as any;

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "MISSING_FIELD")).toBe(true);
    });

    it("should require actions", () => {
      const statement = {
        sid: "Statement1",
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: [], excludes: [], groups: [] },
        resources: { types: ["*"], ids: [], paths: [], attributes: {} },
      };

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "EMPTY_ACTIONS")).toBe(true);
    });

    it("should require resources", () => {
      const statement = {
        sid: "Statement1",
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: ["*"], excludes: [], groups: [] },
        resources: { types: [], ids: [], paths: [], attributes: {} },
      };

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(false);
      expect(result.errors.some((e) => e.code === "EMPTY_RESOURCES")).toBe(
        true,
      );
    });

    it("should validate action patterns", () => {
      const statement = {
        sid: "Statement1",
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: ["INVOICE_*"], excludes: [], groups: [] },
        resources: { types: ["*"], ids: [], paths: [], attributes: {} },
      };

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(true);
    });

    it("should validate resource patterns", () => {
      const statement = {
        sid: "Statement1",
        effect: "ALLOW" as PolicyEffect,
        actions: { includes: ["*"], excludes: [], groups: [] },
        resources: { types: ["invoice:*"], ids: [], paths: [], attributes: {} },
      };

      const result = parser.validateStatement(statement, 0);
      expect(result.isValid).toBe(true);
    });
  });

  describe("extractTenantId - Tenant ID Extraction", () => {
    it("should extract tenantId from policy object", () => {
      const policy = { tenantId: "tenant-abc" };
      const tenantId = parser.extractTenantId(policy as any);
      expect(tenantId).toBe("tenant-abc");
    });

    it("should throw error when tenantId is missing", () => {
      const policy = {};
      expect(() => parser.extractTenantId(policy as any)).toThrow();
    });

    it("should throw error when tenantId is not a string", () => {
      const policy = { tenantId: 123 };
      expect(() => parser.extractTenantId(policy as any)).toThrow();
    });
  });

  describe("Complex Policy Scenarios", () => {
    it("should parse policy with multiple statements", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "AllowRead",
            effect: "ALLOW",
            actions: { includes: ["*_READ"] },
            resources: { types: ["*"] },
          },
          {
            sid: "DenyDelete",
            effect: "DENY",
            actions: { includes: ["*_DELETE"] },
            resources: { types: ["sensitive:*"] },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);

      expect(policy.statements).toHaveLength(2);
      expect(policy.statements[0].sid).toBe("AllowRead");
      expect(policy.statements[1].sid).toBe("DenyDelete");
    });

    it("should parse policy with metadata", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["*"] },
            resources: { types: ["*"] },
          },
        ],
        metadata: {
          description: "Test policy",
          tags: { env: "production" },
        },
      };

      const policy = parser.parse(rawPolicy as any);

      expect(policy.metadata?.description).toBe("Test policy");
      expect(policy.metadata?.tags?.env).toBe("production");
    });

    it("should parse policy with conditions of multiple types", () => {
      const rawPolicy = {
        version: "2026-01-01",
        tenantId: "tenant-abc",
        statements: [
          {
            sid: "Statement1",
            effect: "ALLOW",
            actions: { includes: ["SENSITIVE_ACCESS"] },
            resources: { types: ["data:*"] },
            conditions: {
              Bool: { "context.mfaAuthenticated": true },
              StringEquals: { "context.environment": "production" },
              IpAddress: { "context.ipAddress": "10.0.0.0/8" },
            },
          },
        ],
      };

      const policy = parser.parse(rawPolicy as any);
      const conditions = policy.statements[0].conditions;

      expect(conditions?.Bool).toBeDefined();
      expect(conditions?.StringEquals).toBeDefined();
      expect(conditions?.IpAddress).toBeDefined();
    });
  });
});
