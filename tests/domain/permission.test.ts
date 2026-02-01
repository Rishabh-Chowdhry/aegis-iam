/**
 * Unit Tests for Permission Entity
 *
 * Tests cover:
 * - Permission creation (resource, action)
 * - Permission validation
 * - Permission comparison
 */

import { Permission } from "../../src/domain/entities/Permission";

describe("Permission Entity", () => {
  // Valid test data
  const validPermissionId = "perm-123";
  const validPermissionName = "Read Documents";
  const validResource = "document";
  const validAction = "read";
  const validDescription = "Permission to read documents";
  const validTenantId = "tenant-456";

  describe("Permission Creation", () => {
    describe("with valid data", () => {
      it("should create a permission with all required fields", () => {
        const permission = new Permission(
          validPermissionId,
          validPermissionName,
          validResource,
          validAction,
          validDescription,
          validTenantId,
        );

        expect(permission.id).toBe(validPermissionId);
        expect(permission.name).toBe(validPermissionName);
        expect(permission.resource).toBe(validResource);
        expect(permission.action).toBe(validAction);
        expect(permission.description).toBe(validDescription);
        expect(permission.tenantId).toBe(validTenantId);
      });

      it("should create a permission with empty description", () => {
        const permission = new Permission(
          validPermissionId,
          validPermissionName,
          validResource,
          validAction,
          "",
          validTenantId,
        );

        expect(permission.description).toBe("");
      });

      it("should create a permission with wildcard action", () => {
        const permission = new Permission(
          validPermissionId,
          "All Actions",
          validResource,
          "*",
          "Permission to perform all actions on resource",
          validTenantId,
        );

        expect(permission.action).toBe("*");
      });

      it("should create a permission with wildcard resource", () => {
        const permission = new Permission(
          validPermissionId,
          "Admin All",
          "*",
          validAction,
          "Permission to perform action on all resources",
          validTenantId,
        );

        expect(permission.resource).toBe("*");
      });
    });

    describe("with invalid data", () => {
      it("should throw error when permission ID is empty", () => {
        expect(() => {
          new Permission(
            "",
            validPermissionName,
            validResource,
            validAction,
            validDescription,
            validTenantId,
          );
        }).toThrow("Permission ID is required");
      });

      it("should throw error when permission ID is null", () => {
        expect(() => {
          new Permission(
            null as any,
            validPermissionName,
            validResource,
            validAction,
            validDescription,
            validTenantId,
          );
        }).toThrow("Permission ID is required");
      });

      it("should throw error when permission name is empty", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            "",
            validResource,
            validAction,
            validDescription,
            validTenantId,
          );
        }).toThrow("Permission name is required");
      });

      it("should throw error when permission name is only whitespace", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            "   ",
            validResource,
            validAction,
            validDescription,
            validTenantId,
          );
        }).toThrow("Permission name is required");
      });

      it("should throw error when resource is empty", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            validPermissionName,
            "",
            validAction,
            validDescription,
            validTenantId,
          );
        }).toThrow("Resource is required");
      });

      it("should throw error when action is empty", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            validPermissionName,
            validResource,
            "",
            validDescription,
            validTenantId,
          );
        }).toThrow("Action is required");
      });

      it("should throw error when action is only whitespace", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            validPermissionName,
            validResource,
            "   ",
            validDescription,
            validTenantId,
          );
        }).toThrow("Action is required");
      });

      it("should throw error when tenant ID is empty", () => {
        expect(() => {
          new Permission(
            validPermissionId,
            validPermissionName,
            validResource,
            validAction,
            validDescription,
            "",
          );
        }).toThrow("Tenant ID is required");
      });
    });
  });

  describe("matches", () => {
    let permission: Permission;

    beforeEach(() => {
      permission = new Permission(
        validPermissionId,
        validPermissionName,
        "document",
        "read",
        validDescription,
        validTenantId,
      );
    });

    it("should return true when resource and action match exactly", () => {
      expect(permission.matches("document", "read")).toBe(true);
    });

    it("should return false when resource does not match", () => {
      expect(permission.matches("file", "read")).toBe(false);
    });

    it("should return false when action does not match", () => {
      expect(permission.matches("document", "write")).toBe(false);
    });

    it("should return false when neither resource nor action match", () => {
      expect(permission.matches("file", "delete")).toBe(false);
    });

    it("should be case-sensitive for resource", () => {
      expect(permission.matches("Document", "read")).toBe(false);
    });

    it("should be case-sensitive for action", () => {
      expect(permission.matches("document", "READ")).toBe(false);
    });
  });

  describe("updateName", () => {
    let permission: Permission;

    beforeEach(() => {
      permission = new Permission(
        validPermissionId,
        validPermissionName,
        validResource,
        validAction,
        validDescription,
        validTenantId,
      );
    });

    it("should update the permission's name", () => {
      permission.updateName("Updated Permission Name");
      expect(permission.name).toBe("Updated Permission Name");
    });

    it("should throw error when new name is empty", () => {
      expect(() => {
        permission.updateName("");
      }).toThrow("Permission name is required");
    });

    it("should throw error when new name is only whitespace", () => {
      expect(() => {
        permission.updateName("   ");
      }).toThrow("Permission name is required");
    });

    it("should allow name with special characters", () => {
      permission.updateName("Permission: Create/Update (Full Access)");
      expect(permission.name).toBe("Permission: Create/Update (Full Access)");
    });
  });

  describe("Tenant Isolation", () => {
    it("should store and return tenant ID correctly", () => {
      const permission = new Permission(
        validPermissionId,
        validPermissionName,
        validResource,
        validAction,
        validDescription,
        validTenantId,
      );

      expect(permission.tenantId).toBe(validTenantId);
      expect(permission.tenantId).not.toBe("different-tenant");
    });

    it("should prevent creation without tenant ID", () => {
      expect(() => {
        new Permission(
          validPermissionId,
          validPermissionName,
          validResource,
          validAction,
          validDescription,
          "",
        );
      }).toThrow("Tenant ID is required");
    });
  });

  describe("Permission Identity", () => {
    it("should have unique ID", () => {
      const permission1 = new Permission(
        "perm-1",
        "Permission 1",
        "document",
        "read",
        "Description 1",
        validTenantId,
      );

      const permission2 = new Permission(
        "perm-2",
        "Permission 2",
        "document",
        "read",
        "Description 2",
        validTenantId,
      );

      expect(permission1.id).not.toBe(permission2.id);
    });

    it("should differentiate permissions by resource and action", () => {
      const readPermission = new Permission(
        "perm-1",
        "Read",
        "document",
        "read",
        "Read permission",
        validTenantId,
      );

      const writePermission = new Permission(
        "perm-2",
        "Write",
        "document",
        "write",
        "Write permission",
        validTenantId,
      );

      expect(readPermission.matches("document", "read")).toBe(true);
      expect(writePermission.matches("document", "write")).toBe(true);
      expect(readPermission.matches("document", "write")).toBe(false);
      expect(writePermission.matches("document", "read")).toBe(false);
    });
  });
});
