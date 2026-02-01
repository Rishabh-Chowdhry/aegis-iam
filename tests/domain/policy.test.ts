/**
 * Unit Tests for Policy Entity
 *
 * Tests cover:
 * - Policy creation with conditions
 * - Policy effect (ALLOW/DENY)
 * - Policy validation
 * - Policy condition structure
 */

import { Policy } from "../../src/domain/entities/Policy";

describe("Policy Entity", () => {
  // Valid test data
  const validPolicyId = "policy-123";
  const validPolicyName = "Admin Access Policy";
  const validPolicyDescription = "Policy for admin access to resources";
  const validTenantId = "tenant-456";
  const validConditions = {
    resource: "document",
    action: "read",
    role: "admin",
  };

  describe("Policy Creation", () => {
    describe("with valid data", () => {
      it("should create a policy with all required fields", () => {
        const policy = new Policy(
          validPolicyId,
          validPolicyName,
          validConditions,
          "allow",
          validPolicyDescription,
          validTenantId,
        );

        expect(policy.id).toBe(validPolicyId);
        expect(policy.name).toBe(validPolicyName);
        expect(policy.conditions).toEqual(validConditions);
        expect(policy.effect).toBe("allow");
        expect(policy.description).toBe(validPolicyDescription);
        expect(policy.tenantId).toBe(validTenantId);
      });

      it("should create a policy with DENY effect", () => {
        const policy = new Policy(
          validPolicyId,
          validPolicyName,
          validConditions,
          "deny",
          validPolicyDescription,
          validTenantId,
        );

        expect(policy.effect).toBe("deny");
      });

      it("should create a policy with empty conditions", () => {
        const policy = new Policy(
          validPolicyId,
          validPolicyName,
          {},
          "allow",
          validPolicyDescription,
          validTenantId,
        );

        expect(policy.conditions).toEqual({});
      });

      it("should create a policy with empty description", () => {
        const policy = new Policy(
          validPolicyId,
          validPolicyName,
          validConditions,
          "allow",
          "",
          validTenantId,
        );

        expect(policy.description).toBe("");
      });

      it("should create a policy with complex nested conditions", () => {
        const complexConditions = {
          resource: "document",
          action: "delete",
          ownerId: "${context.user.id}",
          department: "${context.user.department}",
          timeRange: {
            start: "09:00",
            end: "17:00",
          },
        };

        const policy = new Policy(
          validPolicyId,
          validPolicyName,
          complexConditions,
          "allow",
          validPolicyDescription,
          validTenantId,
        );

        expect(policy.conditions).toEqual(complexConditions);
      });
    });

    describe("with invalid data", () => {
      it("should throw error when policy ID is empty", () => {
        expect(() => {
          new Policy(
            "",
            validPolicyName,
            validConditions,
            "allow",
            validPolicyDescription,
            validTenantId,
          );
        }).toThrow("Policy ID is required");
      });

      it("should throw error when policy ID is null", () => {
        expect(() => {
          new Policy(
            null as any,
            validPolicyName,
            validConditions,
            "allow",
            validPolicyDescription,
            validTenantId,
          );
        }).toThrow("Policy ID is required");
      });

      it("should throw error when policy name is empty", () => {
        expect(() => {
          new Policy(
            validPolicyId,
            "",
            validConditions,
            "allow",
            validPolicyDescription,
            validTenantId,
          );
        }).toThrow("Policy name is required");
      });

      it("should throw error when policy name is only whitespace", () => {
        expect(() => {
          new Policy(
            validPolicyId,
            "   ",
            validConditions,
            "allow",
            validPolicyDescription,
            validTenantId,
          );
        }).toThrow("Policy name is required");
      });

      it("should throw error when tenant ID is empty", () => {
        expect(() => {
          new Policy(
            validPolicyId,
            validPolicyName,
            validConditions,
            "allow",
            validPolicyDescription,
            "",
          );
        }).toThrow("Tenant ID is required");
      });
    });
  });

  describe("evaluate", () => {
    let policy: Policy;

    beforeEach(() => {
      policy = new Policy(
        validPolicyId,
        validPolicyName,
        { resource: "document", action: "read" },
        "allow",
        validPolicyDescription,
        validTenantId,
      );
    });

    it("should return true when all conditions match the context", () => {
      const context = { resource: "document", action: "read" };
      expect(policy.evaluate(context)).toBe(true);
    });

    it("should return false when any condition does not match", () => {
      const context = { resource: "document", action: "write" };
      expect(policy.evaluate(context)).toBe(false);
    });

    it("should return false when condition key is missing from context", () => {
      const context = { resource: "document" };
      expect(policy.evaluate(context)).toBe(false);
    });

    it("should return true for empty conditions with any context", () => {
      const emptyPolicy = new Policy(
        "policy-empty",
        "Empty Policy",
        {},
        "allow",
        "No conditions",
        validTenantId,
      );

      expect(emptyPolicy.evaluate({})).toBe(true);
      expect(emptyPolicy.evaluate({ resource: "anything" })).toBe(true);
    });

    it("should handle nested condition matching", () => {
      const nestedPolicy = new Policy(
        "nested-policy",
        "Nested Policy",
        { "nested.field": "value" },
        "allow",
        "Nested conditions",
        validTenantId,
      );

      const context = { "nested.field": "value" };
      expect(nestedPolicy.evaluate(context)).toBe(true);
    });
  });

  describe("updateConditions", () => {
    let policy: Policy;

    beforeEach(() => {
      policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );
    });

    it("should update the policy's conditions", () => {
      const newConditions = { resource: "file", action: "write" };
      policy.updateConditions(newConditions);

      expect(policy.conditions).toEqual(newConditions);
    });

    it("should replace existing conditions with empty object", () => {
      policy.updateConditions({});
      expect(policy.conditions).toEqual({});
    });

    it("should update conditions to complex nested structure", () => {
      const complexConditions = {
        user: {
          role: "admin",
          department: "engineering",
        },
        resource: {
          type: "document",
          sensitivity: "high",
        },
      };

      policy.updateConditions(complexConditions);
      expect(policy.conditions).toEqual(complexConditions);
    });
  });

  describe("updateName", () => {
    let policy: Policy;

    beforeEach(() => {
      policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );
    });

    it("should update the policy's name", () => {
      policy.updateName("Updated Policy Name");
      expect(policy.name).toBe("Updated Policy Name");
    });

    it("should throw error when new name is empty", () => {
      expect(() => {
        policy.updateName("");
      }).toThrow("Policy name is required");
    });

    it("should throw error when new name is only whitespace", () => {
      expect(() => {
        policy.updateName("   ");
      }).toThrow("Policy name is required");
    });
  });

  describe("updateDescription", () => {
    let policy: Policy;

    beforeEach(() => {
      policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );
    });

    it("should update the policy's description", () => {
      policy.updateDescription("Updated policy description");
      expect(policy.description).toBe("Updated policy description");
    });

    it("should allow empty description", () => {
      policy.updateDescription("");
      expect(policy.description).toBe("");
    });
  });

  describe("Policy Effect", () => {
    it("should store ALLOW effect correctly", () => {
      const policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );

      expect(policy.effect).toBe("allow");
    });

    it("should store DENY effect correctly", () => {
      const policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "deny",
        validPolicyDescription,
        validTenantId,
      );

      expect(policy.effect).toBe("deny");
    });
  });

  describe("Defensive Copying", () => {
    it("should return defensive copy of conditions object", () => {
      const policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );

      const conditions = policy.conditions;
      conditions["hacker"] = "value";

      expect(policy.conditions).not.toHaveProperty("hacker");
    });
  });

  describe("Tenant Isolation", () => {
    it("should store and return tenant ID correctly", () => {
      const policy = new Policy(
        validPolicyId,
        validPolicyName,
        validConditions,
        "allow",
        validPolicyDescription,
        validTenantId,
      );

      expect(policy.tenantId).toBe(validTenantId);
      expect(policy.tenantId).not.toBe("different-tenant");
    });

    it("should prevent creation without tenant ID", () => {
      expect(() => {
        new Policy(
          validPolicyId,
          validPolicyName,
          validConditions,
          "allow",
          validPolicyDescription,
          "",
        );
      }).toThrow("Tenant ID is required");
    });
  });
});
