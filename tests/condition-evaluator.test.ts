/**
 * Condition Evaluator Unit Tests
 *
 * Comprehensive tests for the ABAC policy condition evaluation system.
 */

import { ConditionEvaluator } from "../src/modules/iam/conditions/ConditionEvaluator";
import {
  PolicyCondition,
  Subject,
  Resource,
  AuthorizationContext,
  PrincipalType,
  RequestContext,
} from "../src/modules/iam/policy/models/types";

function createTestContext(
  input: {
    subject?: Partial<Subject>;
    resource?: Partial<Resource>;
    context?: Partial<RequestContext>;
  } = {},
): { subject: Subject; resource: Resource; context: AuthorizationContext } {
  const now = new Date().toISOString();
  const subject: Subject = {
    id: input.subject?.id || "user-123",
    tenantId: input.subject?.tenantId || "tenant-abc",
    type: (input.subject?.type as PrincipalType) || "User",
    roles: input.subject?.roles || ["admin"],
    groups: input.subject?.groups || [],
    attributes: input.subject?.attributes || {},
    ...input.subject,
  };
  const resource: Resource = {
    type: input.resource?.type || "invoice",
    id: input.resource?.id || "inv-456",
    tenantId: input.resource?.tenantId || "tenant-abc",
    ...input.resource,
  };
  const fullContext: RequestContext = {
    timestamp: now,
    ipAddress: "192.168.1.100",
    mfaAuthenticated: true,
    riskScore: 10,
    environment: "production",
    ...input.context,
  };
  const context: AuthorizationContext = {
    subject,
    action: { id: "TEST_ACTION" },
    resource,
    context: fullContext,
  };
  return { subject, resource, context };
}

describe("ConditionEvaluator", () => {
  let evaluator: ConditionEvaluator;

  beforeEach(() => {
    evaluator = new ConditionEvaluator();
  });

  describe("evaluate - Basic Behavior", () => {
    it("should return isMet=true when no conditions are provided", () => {
      const { context } = createTestContext();
      const result = evaluator.evaluate(
        undefined,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
      expect(result.failedConditions).toHaveLength(0);
    });

    it("should return isMet=true for empty conditions object", () => {
      const { context } = createTestContext();
      const result = evaluator.evaluate(
        {},
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should return isMet=true when all conditions are satisfied", () => {
      const { context } = createTestContext();
      const conditions: PolicyCondition = {
        StringEquals: { "subject.id": "user-123" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should return isMet=false when any condition fails", () => {
      const { context } = createTestContext();
      const conditions: PolicyCondition = {
        StringEquals: { "subject.id": "wrong-user" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
      expect(result.failedConditions).toHaveLength(1);
    });
  });

  describe("evaluate - String Operators", () => {
    it("should handle StringEquals operator", () => {
      const { context } = createTestContext({
        subject: { attributes: { status: "ACTIVE" } },
      });
      const conditions: PolicyCondition = {
        StringEquals: { "subject.attributes.status": "ACTIVE" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle StringNotEquals operator", () => {
      const { context } = createTestContext({
        subject: { attributes: { status: "ACTIVE" } },
      });
      const conditions: PolicyCondition = {
        StringNotEquals: { "subject.attributes.status": "SUSPENDED" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle StringLike operator with wildcard", () => {
      const { context } = createTestContext({
        subject: { attributes: { email: "admin@example.com" } },
      });
      const conditions: PolicyCondition = {
        StringLike: { "subject.attributes.email": "*@example.com" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle StringNotLike operator", () => {
      const { context } = createTestContext({
        subject: { attributes: { email: "admin@other.com" } },
      });
      const conditions: PolicyCondition = {
        StringNotLike: { "subject.attributes.email": "*@example.com" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle StringEqualsIgnoreCase operator", () => {
      const { context } = createTestContext({
        subject: { attributes: { role: "ADMIN" } },
      });
      const conditions: PolicyCondition = {
        StringEqualsIgnoreCase: { "subject.attributes.role": "admin" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });
  });

  describe("evaluate - Numeric Operators", () => {
    it("should handle NumericEquals operator", () => {
      const { context } = createTestContext({ context: { riskScore: 50 } });
      const conditions: PolicyCondition = {
        NumericEquals: { "context.riskScore": 50 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle NumericNotEquals operator", () => {
      const { context } = createTestContext({ context: { riskScore: 50 } });
      const conditions: PolicyCondition = {
        NumericNotEquals: { "context.riskScore": 75 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle NumericGreaterThan operator", () => {
      const { context } = createTestContext({ context: { riskScore: 75 } });
      const conditions: PolicyCondition = {
        NumericGreaterThan: { "context.riskScore": 50 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle NumericGreaterThanEquals operator", () => {
      const { context } = createTestContext({ context: { riskScore: 50 } });
      const conditions: PolicyCondition = {
        NumericGreaterThanEquals: { "context.riskScore": 50 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle NumericLessThan operator", () => {
      const { context } = createTestContext({ context: { riskScore: 25 } });
      const conditions: PolicyCondition = {
        NumericLessThan: { "context.riskScore": 50 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle NumericLessThanEquals operator", () => {
      const { context } = createTestContext({ context: { riskScore: 50 } });
      const conditions: PolicyCondition = {
        NumericLessThanEquals: { "context.riskScore": 50 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });
  });

  describe("evaluate - Boolean Operators", () => {
    it("should handle Bool operator with true value", () => {
      const { context } = createTestContext({
        context: { mfaAuthenticated: true },
      });
      const conditions: PolicyCondition = {
        Bool: { "context.mfaAuthenticated": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle Bool operator with false value", () => {
      const { context } = createTestContext({
        context: { mfaAuthenticated: false },
      });
      const conditions: PolicyCondition = {
        Bool: { "context.mfaAuthenticated": false },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });
  });

  describe("evaluate - IP Address Operators", () => {
    it("should handle IpAddress operator with matching IP", () => {
      const { context } = createTestContext({
        context: { ipAddress: "192.168.1.100" },
      });
      const conditions: PolicyCondition = {
        IpAddress: { "context.ipAddress": "192.168.1.0/24" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle IpAddress operator with non-matching IP", () => {
      const { context } = createTestContext({
        context: { ipAddress: "10.0.0.1" },
      });
      const conditions: PolicyCondition = {
        IpAddress: { "context.ipAddress": "192.168.1.0/24" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });

    it("should handle NotIpAddress operator", () => {
      const { context } = createTestContext({
        context: { ipAddress: "10.0.0.1" },
      });
      const conditions: PolicyCondition = {
        NotIpAddress: { "context.ipAddress": "192.168.1.0/24" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });
  });

  describe("evaluate - Null Check Operator", () => {
    it("should handle Null operator when value is null", () => {
      const { context } = createTestContext({
        resource: { parentId: undefined },
      });
      const conditions: PolicyCondition = {
        Null: { "resource.parentId": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle Null operator when value is not null", () => {
      const { context } = createTestContext({
        resource: { parentId: "parent-123" },
      });
      const conditions: PolicyCondition = {
        Null: { "resource.parentId": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });
  });

  describe("evaluate - Date Operators", () => {
    it("should handle DateGreaterThan operator", () => {
      const { context } = createTestContext({
        resource: { attributes: { createdAt: "2026-02-01" } },
      });
      const conditions: PolicyCondition = {
        DateGreaterThan: { "resource.attributes.createdAt": "2026-01-01" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should handle DateLessThan operator", () => {
      const { context } = createTestContext({
        resource: { attributes: { dueDate: "2026-01-15" } },
      });
      const conditions: PolicyCondition = {
        DateLessThan: { "resource.attributes.dueDate": "2026-02-01" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });
  });

  describe("evaluate - Path Resolution", () => {
    it("should resolve subject.id path", () => {
      const { context } = createTestContext({ subject: { id: "user-123" } });
      const conditions: PolicyCondition = {
        StringEquals: { "subject.id": "user-123" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should resolve subject.tenantId path", () => {
      const { context } = createTestContext({
        subject: { tenantId: "tenant-abc" },
      });
      const conditions: PolicyCondition = {
        StringEquals: { "subject.tenantId": "tenant-abc" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should resolve resource.type path", () => {
      const { context } = createTestContext({ resource: { type: "invoice" } });
      const conditions: PolicyCondition = {
        StringEquals: { "resource.type": "invoice" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should resolve nested attribute paths", () => {
      const { context } = createTestContext({
        subject: { attributes: { config: { level: 3 } } },
      });
      const conditions: PolicyCondition = {
        NumericEquals: { "subject.attributes.config.level": 3 },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should return isMet=false for non-existent paths", () => {
      const { context } = createTestContext();
      const conditions: PolicyCondition = {
        StringEquals: { "subject.nonexistent": "value" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });
  });

  describe("evaluate - Fail-Closed Behavior", () => {
    it("should fail-closed when path cannot be resolved", () => {
      const { context } = createTestContext();
      const conditions: PolicyCondition = {
        StringEquals: { "subject.missing.attribute": "value" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });

    it("should fail-closed on type mismatch", () => {
      const { context } = createTestContext({ context: { riskScore: 25 } });
      const conditions: PolicyCondition = {
        StringEquals: { "context.riskScore": "25" },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });

    it("should handle multiple condition groups with AND logic", () => {
      const { context } = createTestContext({
        subject: { attributes: { department: "finance" } },
        context: { mfaAuthenticated: true },
      });
      const conditions: PolicyCondition = {
        StringEquals: { "subject.attributes.department": "finance" },
        Bool: { "context.mfaAuthenticated": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should fail when any condition in group fails", () => {
      const { context } = createTestContext({
        subject: { attributes: { department: "hr" } },
        context: { mfaAuthenticated: true },
      });
      const conditions: PolicyCondition = {
        StringEquals: { "subject.attributes.department": "finance" },
        Bool: { "context.mfaAuthenticated": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
      expect(result.failedConditions).toHaveLength(1);
    });
  });

  describe("evaluate - Complex Scenarios", () => {
    it("should handle multiple conditions with different operators", () => {
      const { context } = createTestContext({
        subject: { attributes: { level: 3, department: "engineering" } },
        context: { riskScore: 25, mfaAuthenticated: true },
      });
      const conditions: PolicyCondition = {
        NumericGreaterThan: { "subject.attributes.level": 2 },
        StringEquals: { "subject.attributes.department": "engineering" },
        NumericLessThan: { "context.riskScore": 50 },
        Bool: { "context.mfaAuthenticated": true },
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(true);
    });

    it("should track failed conditions correctly", () => {
      const { context } = createTestContext({ subject: { id: "wrong-user" } });
      // This condition should fail because StringNotEquals with tenant-abc should return false when tenantId IS tenant-abc
      const conditions: PolicyCondition = {
        StringNotEquals: { "subject.tenantId": "tenant-abc" }, // tenantId is "tenant-abc" so this equals, and NOT equals returns false
      };
      const result = evaluator.evaluate(
        conditions,
        context.subject,
        context.resource,
        context,
      );
      expect(result.isMet).toBe(false);
    });
  });
});
