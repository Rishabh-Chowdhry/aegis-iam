/**
 * Policy Engine Unit Tests
 *
 * Tests for the PolicyEngine authorize functionality.
 */

import { WildcardPattern } from "../src/modules/iam/conditions/WildcardMatcher";
import {
  ABACPolicy,
  PolicyStatement,
  PolicyCondition,
  Subject,
  Resource,
  Action,
  RequestContext,
  AuthorizationRequest,
  PolicyEffect,
  PolicyVersion,
  PrincipalType,
} from "../src/modules/iam/policy/models/types";

let PolicyEngine: any;
let ConditionEvaluator: any;

beforeAll(async () => {
  const { PolicyEngine: PE, ConditionEvaluator: CE } =
    await import("../src/modules/iam");
  PolicyEngine = PE;
  ConditionEvaluator = CE;
});

// Helper to create a complete request with all required fields
function createTestRequest(
  input: {
    subject?: Partial<Subject>;
    action?: Partial<Action>;
    resource?: Partial<Resource>;
    context?: Partial<RequestContext>;
  } = {},
): AuthorizationRequest {
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
  const action: Action = {
    id: input.action?.id || "INVOICE_READ",
    ...input.action,
  };
  const context: RequestContext = {
    timestamp: now,
    ...input.context,
  };
  return {
    requestId: `req-${Date.now()}`,
    subject,
    action,
    resource,
    context,
  };
}

// Helper to create a test policy
function createTestPolicy(
  input: {
    id?: string;
    tenantId?: string;
    effect?: PolicyEffect;
    actions?: string[];
    resources?: string[];
    conditions?: PolicyCondition;
    sid?: string;
  } = {},
): ABACPolicy {
  const statement: PolicyStatement = {
    sid: input.sid || "Statement1",
    effect: input.effect || "ALLOW",
    actions: { includes: input.actions || ["*"], excludes: [], groups: [] },
    resources: {
      types: input.resources || ["*"],
      ids: [],
      paths: [],
      attributes: {},
    },
    conditions: input.conditions,
  };
  return {
    version: "2026-01-01" as PolicyVersion,
    tenantId: input.tenantId || "tenant-abc",
    id: input.id || `policy-${Date.now()}`,
    name: "Test Policy",
    statements: [statement],
    metadata: { description: "Test policy" },
    status: "ACTIVE",
  };
}

describe("PolicyEngine", () => {
  let engine: any;
  let conditionEvaluator: any;

  beforeEach(() => {
    conditionEvaluator = new ConditionEvaluator();
    engine = new PolicyEngine(conditionEvaluator, undefined, {
      enableAuditLogging: false,
      defaultDecision: "DENY",
    });
  });

  describe("authorize - Basic Authorization", () => {
    it("should return DENY when no policies are provided", () => {
      const request = createTestRequest();
      const decision = engine.authorize(request, []);
      expect(decision.decision).toBe("DENY");
      expect(decision.matchedPolicies).toHaveLength(0);
    });

    it("should return ALLOW when matching ALLOW policy is found", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["INVOICE_READ"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        action: { id: "INVOICE_READ" },
        resource: { type: "invoice", id: "123" },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
      expect(decision.matchedPolicies).toContain(policy.id);
    });

    it("should return DENY when action does not match", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["INVOICE_READ"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        action: { id: "INVOICE_DELETE" },
        resource: { type: "invoice", id: "123" },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("DENY");
    });

    it("should return DENY when resource does not match", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["*"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        action: { id: "USER_READ" },
        resource: { type: "user", id: "123" },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("DENY");
    });
  });

  describe("authorize - Explicit DENY Short-Circuit", () => {
    it("should return DENY when explicit DENY policy matches", () => {
      const allowPolicy = createTestPolicy({
        id: "allow-policy",
        effect: "ALLOW",
        actions: ["*"],
        resources: ["*"],
      });
      const denyPolicy = createTestPolicy({
        id: "deny-policy",
        effect: "DENY",
        actions: ["INVOICE_DELETE"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        action: { id: "INVOICE_DELETE" },
        resource: { type: "invoice", id: "123" },
      });
      const decision = engine.authorize(request, [allowPolicy, denyPolicy]);
      expect(decision.decision).toBe("DENY");
      expect(decision.matchedPolicies).toContain("deny-policy");
    });

    it("should return ALLOW when only ALLOW policies match", () => {
      const allowPolicy = createTestPolicy({
        id: "allow-policy-1",
        effect: "ALLOW",
        actions: ["INVOICE_READ"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        action: { id: "INVOICE_READ" },
        resource: { type: "invoice", id: "123" },
      });
      const decision = engine.authorize(request, [allowPolicy]);
      expect(decision.decision).toBe("ALLOW");
    });
  });

  describe("authorize - Deterministic Evaluation", () => {
    it("should evaluate policies in consistent order", () => {
      const policies = [
        createTestPolicy({
          id: "policy-b",
          effect: "ALLOW",
          actions: ["READ"],
        }),
        createTestPolicy({ id: "policy-a", effect: "DENY", actions: ["READ"] }),
        createTestPolicy({
          id: "policy-c",
          effect: "ALLOW",
          actions: ["READ"],
        }),
      ];
      const request = createTestRequest({
        action: { id: "READ" },
        resource: { type: "doc", id: "1" },
      });
      const decisions = [
        engine.authorize(request, policies),
        engine.authorize(request, policies),
        engine.authorize(request, policies),
      ];
      decisions.forEach((decision) => {
        expect(decision.decision).toBe("DENY");
        expect(decision.matchedPolicies).toContain("policy-a");
      });
    });

    it("should evaluate policies regardless of input order", () => {
      const policies = [
        createTestPolicy({
          id: "policy-z",
          effect: "ALLOW",
          actions: ["ACCESS"],
        }),
        createTestPolicy({
          id: "policy-a",
          effect: "DENY",
          actions: ["ACCESS"],
        }),
      ];
      const request = createTestRequest({
        action: { id: "ACCESS" },
        resource: { type: "resource", id: "1" },
      });
      const decision1 = engine.authorize(request, [policies[0], policies[1]]);
      const decision2 = engine.authorize(request, [policies[1], policies[0]]);
      expect(decision1.decision).toBe("DENY");
      expect(decision2.decision).toBe("DENY");
    });
  });

  describe("authorize - Condition Evaluation", () => {
    it("should allow when all conditions are met", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["INVOICE_APPROVE"],
        resources: ["invoice:*"],
        conditions: { Bool: { "context.mfaAuthenticated": true } },
      });
      const request = createTestRequest({
        action: { id: "INVOICE_APPROVE" },
        resource: { type: "invoice", id: "123" },
        context: { mfaAuthenticated: true },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });

    it("should deny when condition is not met", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["INVOICE_APPROVE"],
        resources: ["invoice:*"],
        conditions: { Bool: { "context.mfaAuthenticated": true } },
      });
      const request = createTestRequest({
        action: { id: "INVOICE_APPROVE" },
        resource: { type: "invoice", id: "123" },
        context: { mfaAuthenticated: false },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("DENY");
    });

    it("should handle multiple conditions with AND logic", () => {
      const policy = createTestPolicy({
        effect: "ALLOW",
        actions: ["SENSITIVE_DATA_ACCESS"],
        resources: ["data:*"],
        conditions: {
          Bool: { "context.mfaAuthenticated": true },
          NumericLessThanEquals: { "context.riskScore": 50 },
        },
      });

      const allowRequest = createTestRequest({
        action: { id: "SENSITIVE_DATA_ACCESS" },
        resource: { type: "data", id: "secret-1" },
        context: { mfaAuthenticated: true, riskScore: 30 },
      });
      const allowDecision = engine.authorize(allowRequest, [policy]);

      const denyRequest = createTestRequest({
        action: { id: "SENSITIVE_DATA_ACCESS" },
        resource: { type: "data", id: "secret-1" },
        context: { mfaAuthenticated: true, riskScore: 80 },
      });
      const denyDecision = engine.authorize(denyRequest, [policy]);

      expect(allowDecision.decision).toBe("ALLOW");
      expect(denyDecision.decision).toBe("DENY");
    });
  });

  describe("authorizeWithTenantIsolation - Tenant Isolation", () => {
    it("should allow access within same tenant", () => {
      const policy = createTestPolicy({
        tenantId: "tenant-abc",
        effect: "ALLOW",
        actions: ["*"],
        resources: ["*"],
      });
      const request = createTestRequest({
        subject: { tenantId: "tenant-abc" },
        resource: { type: "invoice", id: "123", tenantId: "tenant-abc" },
      });
      const decision = engine.authorizeWithTenantIsolation(
        request,
        [policy],
        "tenant-abc",
      );
      expect(decision.decision).toBe("ALLOW");
    });

    it("should deny cross-tenant access", () => {
      const policy = createTestPolicy({
        tenantId: "tenant-abc",
        effect: "ALLOW",
        actions: ["*"],
        resources: ["*"],
      });
      const request = createTestRequest({
        subject: { tenantId: "tenant-xyz" },
        resource: { type: "invoice", id: "123", tenantId: "tenant-abc" },
      });
      const decision = engine.authorizeWithTenantIsolation(
        request,
        [policy],
        "tenant-xyz",
      );
      expect(decision.decision).toBe("DENY");
    });
  });

  describe("authorize - Wildcard Matching", () => {
    it("should match action with asterisk wildcard", () => {
      const policy = createTestPolicy({
        actions: ["INVOICE_*"],
        resources: ["*"],
      });
      const request = createTestRequest({ action: { id: "INVOICE_READ" } });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });

    it("should match action with ending wildcard", () => {
      const policy = createTestPolicy({
        actions: ["*_READ"],
        resources: ["*"],
      });
      const request = createTestRequest({ action: { id: "USER_READ" } });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });

    it("should match action with global wildcard", () => {
      const policy = createTestPolicy({ actions: ["*"], resources: ["*"] });
      const request = createTestRequest({ action: { id: "ANY_ACTION" } });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });

    it("should match resource with type wildcard", () => {
      const policy = createTestPolicy({
        actions: ["*"],
        resources: ["invoice:*"],
      });
      const request = createTestRequest({
        resource: { type: "invoice", id: "123" },
      });
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });
  });

  describe("authorize - Edge Cases", () => {
    it("should handle policy with no conditions", () => {
      const policy = createTestPolicy({ actions: ["TEST"], resources: ["*"] });
      const request = createTestRequest();
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("ALLOW");
    });

    it("should handle empty policy list", () => {
      const request = createTestRequest();
      const decision = engine.authorize(request, []);
      expect(decision.decision).toBe("DENY");
    });

    it("should handle disabled policies", () => {
      const policy = createTestPolicy({ id: "disabled-policy" });
      policy.status = "DISABLED";
      const request = createTestRequest();
      const decision = engine.authorize(request, [policy]);
      expect(decision.decision).toBe("DENY");
    });
  });

  describe("authorize - Performance", () => {
    it("should handle large policy sets efficiently", () => {
      const policies = Array.from({ length: 100 }, (_, i) =>
        createTestPolicy({
          id: `policy-${i}`,
          actions: [`ACTION_${i}`],
          resources: ["*"],
        }),
      );
      policies.push(
        createTestPolicy({
          id: "matching-policy",
          effect: "ALLOW",
          actions: ["TEST_ACTION"],
          resources: ["*"],
        }),
      );
      const request = createTestRequest({ action: { id: "TEST_ACTION" } });
      const startTime = Date.now();
      const decision = engine.authorize(request, policies);
      const duration = Date.now() - startTime;
      expect(decision.decision).toBe("ALLOW");
      expect(decision.matchedPolicies).toContain("matching-policy");
      expect(duration).toBeLessThan(100);
    });

    it("should handle concurrent requests", async () => {
      const policy = createTestPolicy({
        actions: ["CONCURRENT_TEST"],
        resources: ["*"],
      });
      const request = createTestRequest({ action: { id: "CONCURRENT_TEST" } });
      const promises = Array.from({ length: 50 }, () =>
        Promise.resolve(engine.authorize(request, [policy])),
      );
      const decisions = await Promise.all(promises);
      decisions.forEach((decision) => expect(decision.decision).toBe("ALLOW"));
    });
  });

  describe("authorize - Evaluation Metrics", () => {
    it("should include evaluation trace in decision", () => {
      const policy = createTestPolicy({ actions: ["TEST"], resources: ["*"] });
      const request = createTestRequest();
      const decision = engine.authorize(request, [policy]);
      expect(decision).toHaveProperty("evaluationTimeMs");
      expect(decision).toHaveProperty("trace");
    });

    it("should track matched policies", () => {
      const matchingPolicy = createTestPolicy({
        id: "matching-policy",
        effect: "ALLOW",
        actions: ["TEST"],
        resources: ["*"],
      });
      const request = createTestRequest({ action: { id: "TEST" } });
      const decision = engine.authorize(request, [matchingPolicy]);
      expect(decision.matchedPolicies).toContain("matching-policy");
    });
  });
});

describe("PolicyEngine - Custom Configuration", () => {
  let conditionEvaluator: any;

  beforeEach(() => {
    conditionEvaluator = new ConditionEvaluator();
  });

  it("should use ALLOW as default decision when configured", () => {
    const engine = new PolicyEngine(conditionEvaluator, undefined, {
      defaultDecision: "ALLOW",
      enableAuditLogging: false,
    });
    const request = createTestRequest();
    const decision = engine.authorize(request, []);
    expect(decision.decision).toBe("ALLOW");
  });
});

describe("PolicyEngine - Complex Conditions", () => {
  let engine: any;
  let conditionEvaluator: any;

  beforeEach(() => {
    conditionEvaluator = new ConditionEvaluator();
    engine = new PolicyEngine(conditionEvaluator, undefined, {
      enableAuditLogging: false,
      defaultDecision: "DENY",
    });
  });

  it("should handle StringLike condition with wildcards", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: {
        StringLike: { "subject.attributes.email": "*@example.com" },
      },
    });
    const allowRequest = createTestRequest({
      subject: { attributes: { email: "user@example.com" } },
    });
    expect(engine.authorize(allowRequest, [policy]).decision).toBe("ALLOW");
    const denyRequest = createTestRequest({
      subject: { attributes: { email: "user@other.com" } },
    });
    expect(engine.authorize(denyRequest, [policy]).decision).toBe("DENY");
  });

  it("should handle IpAddress condition", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: { IpAddress: { "context.ipAddress": "192.168.1.0/24" } },
    });
    const allowRequest = createTestRequest({
      context: { ipAddress: "192.168.1.100" },
    });
    expect(engine.authorize(allowRequest, [policy]).decision).toBe("ALLOW");
    const denyRequest = createTestRequest({
      context: { ipAddress: "10.0.0.1" },
    });
    expect(engine.authorize(denyRequest, [policy]).decision).toBe("DENY");
  });

  it("should handle InList condition", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: { InList: { "resource.type": "invoice" } },
    });
    const invoiceRequest = createTestRequest({ resource: { type: "invoice" } });
    expect(engine.authorize(invoiceRequest, [policy]).decision).toBe("ALLOW");
    const userRequest = createTestRequest({ resource: { type: "user" } });
    expect(engine.authorize(userRequest, [policy]).decision).toBe("DENY");
  });

  it("should handle Null condition", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: { Null: { "resource.parentId": true } },
    });
    const allowRequest = createTestRequest({
      resource: { type: "invoice", parentId: undefined },
    });
    expect(engine.authorize(allowRequest, [policy]).decision).toBe("ALLOW");
    const denyRequest = createTestRequest({
      resource: { type: "invoice", parentId: "parent-123" },
    });
    expect(engine.authorize(denyRequest, [policy]).decision).toBe("DENY");
  });

  it("should handle DateGreaterThan condition", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: {
        DateGreaterThan: { "resource.attributes.dueDate": "2026-06-01" },
      },
    });
    const allowRequest = createTestRequest({
      resource: { attributes: { dueDate: "2026-12-31" } },
    });
    expect(engine.authorize(allowRequest, [policy]).decision).toBe("ALLOW");
    const denyRequest = createTestRequest({
      resource: { attributes: { dueDate: "2026-01-01" } },
    });
    expect(engine.authorize(denyRequest, [policy]).decision).toBe("DENY");
  });

  it("should handle NumericGreaterThan condition", () => {
    const policy = createTestPolicy({
      actions: ["*"],
      resources: ["*"],
      conditions: { NumericGreaterThan: { "context.riskScore": 50 } },
    });
    const denyRequest = createTestRequest({ context: { riskScore: 75 } });
    expect(engine.authorize(denyRequest, [policy]).decision).toBe("DENY");
    const allowRequest = createTestRequest({ context: { riskScore: 25 } });
    expect(engine.authorize(allowRequest, [policy]).decision).toBe("ALLOW");
  });
});
