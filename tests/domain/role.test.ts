/**
 * Unit Tests for Role Entity
 *
 * Tests cover:
 * - Role creation with hierarchy support
 * - Parent-child role relationships
 * - Permission assignment to roles
 * - Role validation (name required, etc.)
 * - Role hierarchy traversal
 */

import { Role } from "../../src/domain/entities/Role";

describe("Role Entity", () => {
  // Valid test data
  const validRoleId = "role-123";
  const validRoleName = "Admin";
  const validRoleDescription = "Administrator role with full access";
  const validTenantId = "tenant-456";
  const validPermissions = ["perm-1", "perm-2", "perm-3"];
  const validCreatedAt = new Date("2024-01-01T00:00:00Z");
  const validUpdatedAt = new Date("2024-01-02T00:00:00Z");

  describe("Role Creation", () => {
    describe("with valid data", () => {
      it("should create a role with all required fields", () => {
        const role = new Role(
          validRoleId,
          validRoleName,
          validRoleDescription,
          null,
          validPermissions,
          validTenantId,
          validCreatedAt,
          validUpdatedAt,
        );

        expect(role.id).toBe(validRoleId);
        expect(role.name).toBe(validRoleName);
        expect(role.description).toBe(validRoleDescription);
        expect(role.parentId).toBeNull();
        expect(role.permissions).toEqual(validPermissions);
        expect(role.tenantId).toBe(validTenantId);
      });

      it("should create a role with parent role", () => {
        const parentRoleId = "parent-role-123";
        const role = new Role(
          validRoleId,
          validRoleName,
          validRoleDescription,
          parentRoleId,
          validPermissions,
          validTenantId,
          validCreatedAt,
          validUpdatedAt,
        );

        expect(role.parentId).toBe(parentRoleId);
      });

      it("should create a role with empty permissions array", () => {
        const role = new Role(
          validRoleId,
          validRoleName,
          validRoleDescription,
          null,
          [],
          validTenantId,
          validCreatedAt,
          validUpdatedAt,
        );

        expect(role.permissions).toHaveLength(0);
      });

      it("should use default timestamps when not provided", () => {
        const role = new Role(
          validRoleId,
          validRoleName,
          validRoleDescription,
          null,
          [],
          validTenantId,
        );

        expect(role.createdAt).toBeInstanceOf(Date);
        expect(role.updatedAt).toBeInstanceOf(Date);
      });
    });

    describe("with invalid data", () => {
      it("should throw error when role ID is empty", () => {
        expect(() => {
          new Role(
            "",
            validRoleName,
            validRoleDescription,
            null,
            validPermissions,
            validTenantId,
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Role ID is required");
      });

      it("should throw error when role ID is null", () => {
        expect(() => {
          new Role(
            null as any,
            validRoleName,
            validRoleDescription,
            null,
            validPermissions,
            validTenantId,
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Role ID is required");
      });

      it("should throw error when role name is empty", () => {
        expect(() => {
          new Role(
            validRoleId,
            "",
            validRoleDescription,
            null,
            validPermissions,
            validTenantId,
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Role name is required");
      });

      it("should throw error when role name is only whitespace", () => {
        expect(() => {
          new Role(
            validRoleId,
            "   ",
            validRoleDescription,
            null,
            validPermissions,
            validTenantId,
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Role name is required");
      });

      it("should throw error when tenant ID is empty", () => {
        expect(() => {
          new Role(
            validRoleId,
            validRoleName,
            validRoleDescription,
            null,
            validPermissions,
            "",
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Tenant ID is required");
      });

      it("should throw error when role is its own parent", () => {
        expect(() => {
          new Role(
            validRoleId,
            validRoleName,
            validRoleDescription,
            validRoleId, // Same as ID
            validPermissions,
            validTenantId,
            validCreatedAt,
            validUpdatedAt,
          );
        }).toThrow("Role cannot be its own parent");
      });
    });
  });

  describe("Permission Management", () => {
    let role: Role;

    beforeEach(() => {
      role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        ["read"],
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );
    });

    describe("addPermission", () => {
      it("should add a new permission to the role", () => {
        const initialPermissionsCount = role.permissions.length;
        role.addPermission("write");

        expect(role.permissions).toHaveLength(initialPermissionsCount + 1);
        expect(role.hasPermission("write")).toBe(true);
      });

      it("should not add duplicate permission", () => {
        role.addPermission("read");
        const initialPermissionsCount = role.permissions.length;
        role.addPermission("read");

        expect(role.permissions).toHaveLength(initialPermissionsCount);
      });
    });

    describe("removePermission", () => {
      it("should remove an existing permission from the role", () => {
        role.addPermission("write");
        role.removePermission("write");

        expect(role.hasPermission("write")).toBe(false);
      });

      it("should handle removing non-existent permission gracefully", () => {
        const initialPermissionsCount = role.permissions.length;
        role.removePermission("non-existent");

        expect(role.permissions).toHaveLength(initialPermissionsCount);
      });
    });

    describe("hasPermission", () => {
      it("should return true when role has the permission", () => {
        expect(role.hasPermission("read")).toBe(true);
      });

      it("should return false when role does not have the permission", () => {
        expect(role.hasPermission("admin")).toBe(false);
      });
    });
  });

  describe("Parent-Child Role Relationships", () => {
    let parentRole: Role;
    let childRole: Role;

    beforeEach(() => {
      parentRole = new Role(
        "parent-role",
        "Parent Role",
        "Parent role description",
        null,
        ["parent-perm"],
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );

      childRole = new Role(
        "child-role",
        "Child Role",
        "Child role description",
        "parent-role",
        ["child-perm"],
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );
    });

    describe("setParentRole", () => {
      it("should set parent role for a role", () => {
        const newRole = new Role(
          "new-role",
          "New Role",
          "New role description",
          null,
          [],
          validTenantId,
          validCreatedAt,
          validUpdatedAt,
        );

        newRole.setParentRole("parent-role");

        expect(newRole.parentId).toBe("parent-role");
      });

      it("should throw error when setting role as its own parent", () => {
        expect(() => {
          parentRole.setParentRole(parentRole.id);
        }).toThrow("Role cannot be its own parent");
      });

      it("should update parent role", () => {
        childRole.setParentRole("another-parent");
        expect(childRole.parentId).toBe("another-parent");
      });

      it("should set parent role to null", () => {
        childRole.setParentRole(null);
        expect(childRole.parentId).toBeNull();
      });
    });

    describe("parent role retrieval", () => {
      it("should return parent role ID", () => {
        expect(childRole.parentId).toBe("parent-role");
      });

      it("should return null when no parent role", () => {
        expect(parentRole.parentId).toBeNull();
      });
    });
  });

  describe("Role Description Management", () => {
    let role: Role;

    beforeEach(() => {
      role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        validPermissions,
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );
    });

    describe("updateDescription", () => {
      it("should update the role's description", () => {
        role.updateDescription("Updated description");
        expect(role.description).toBe("Updated description");
      });

      it("should allow empty description", () => {
        role.updateDescription("");
        expect(role.description).toBe("");
      });
    });
  });

  describe("Defensive Copying", () => {
    it("should return defensive copy of permissions array", () => {
      const role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        validPermissions,
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );

      const permissions = role.permissions;
      permissions.push("hacker-perm");

      expect(role.permissions).not.toContain("hacker-perm");
    });
  });

  describe("Tenant Isolation", () => {
    it("should store and return tenant ID correctly", () => {
      const role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        validPermissions,
        validTenantId,
        validCreatedAt,
        validUpdatedAt,
      );

      expect(role.tenantId).toBe(validTenantId);
      expect(role.tenantId).not.toBe("different-tenant");
    });

    it("should prevent creation without tenant ID", () => {
      expect(() => {
        new Role(
          validRoleId,
          validRoleName,
          validRoleDescription,
          null,
          validPermissions,
          "",
          validCreatedAt,
          validUpdatedAt,
        );
      }).toThrow("Tenant ID is required");
    });
  });

  describe("Audit Timestamps", () => {
    it("should store createdAt timestamp", () => {
      const createdAt = new Date("2024-01-01T12:00:00Z");
      const role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        validPermissions,
        validTenantId,
        createdAt,
        validUpdatedAt,
      );

      expect(role.createdAt).toEqual(createdAt);
    });

    it("should store updatedAt timestamp", () => {
      const updatedAt = new Date("2024-01-02T12:00:00Z");
      const role = new Role(
        validRoleId,
        validRoleName,
        validRoleDescription,
        null,
        validPermissions,
        validTenantId,
        validCreatedAt,
        updatedAt,
      );

      expect(role.updatedAt).toEqual(updatedAt);
    });
  });
});
