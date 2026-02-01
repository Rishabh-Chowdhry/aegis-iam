/**
 * Unit Tests for User Entity
 *
 * Tests cover:
 * - User creation with valid/invalid data
 * - Password hash validation
 * - Role assignment and management
 * - User status transitions
 * - Tenant isolation
 * - Audit timestamps
 */

import { User, UserStatus } from "../../src/domain/entities/User";
import { Email } from "../../src/domain/value-objects/Email";
import { PasswordHash } from "../../src/domain/value-objects/PasswordHash";

describe("User Entity", () => {
  // Valid test data
  const validUserId = "user-123";
  const validTenantId = "tenant-456";
  const validEmail = new Email("test@example.com");
  const validPasswordHash = new PasswordHash(
    "$argon2id$v=19$m=65536,t=3,p=4$testHash",
  );
  const validRoles = ["admin", "user"];
  const validCreatedAt = new Date("2024-01-01T00:00:00Z");
  const validUpdatedAt = new Date("2024-01-02T00:00:00Z");

  describe("User Creation", () => {
    describe("with valid data", () => {
      it("should create a user with all required fields", () => {
        const user = new User(
          validUserId,
          validEmail,
          validPasswordHash,
          validRoles,
          UserStatus.ACTIVE,
          validCreatedAt,
          validUpdatedAt,
          validTenantId,
        );

        expect(user.id).toBe(validUserId);
        expect(user.email.value).toBe("test@example.com");
        expect(user.roles).toEqual(validRoles);
        expect(user.status).toBe(UserStatus.ACTIVE);
        expect(user.tenantId).toBe(validTenantId);
        expect(user.createdAt).toEqual(validCreatedAt);
        expect(user.updatedAt).toEqual(validUpdatedAt);
      });

      it("should create a user with empty roles array", () => {
        const user = new User(
          validUserId,
          validEmail,
          validPasswordHash,
          [],
          UserStatus.ACTIVE,
          validCreatedAt,
          validUpdatedAt,
          validTenantId,
        );

        expect(user.roles).toHaveLength(0);
      });

      it("should create a user with single role", () => {
        const user = new User(
          validUserId,
          validEmail,
          validPasswordHash,
          ["admin"],
          UserStatus.ACTIVE,
          validCreatedAt,
          validUpdatedAt,
          validTenantId,
        );

        expect(user.roles).toHaveLength(1);
        expect(user.roles).toContain("admin");
      });

      it("should create a user with INACTIVE status", () => {
        const user = new User(
          validUserId,
          validEmail,
          validPasswordHash,
          validRoles,
          UserStatus.INACTIVE,
          validCreatedAt,
          validUpdatedAt,
          validTenantId,
        );

        expect(user.status).toBe(UserStatus.INACTIVE);
        expect(user.isActive()).toBe(false);
      });

      it("should create a user with SUSPENDED status", () => {
        const user = new User(
          validUserId,
          validEmail,
          validPasswordHash,
          validRoles,
          UserStatus.SUSPENDED,
          validCreatedAt,
          validUpdatedAt,
          validTenantId,
        );

        expect(user.status).toBe(UserStatus.SUSPENDED);
        expect(user.isActive()).toBe(false);
      });
    });

    describe("with invalid data", () => {
      it("should throw error when user ID is empty", () => {
        expect(() => {
          new User(
            "",
            validEmail,
            validPasswordHash,
            validRoles,
            UserStatus.ACTIVE,
            validCreatedAt,
            validUpdatedAt,
            validTenantId,
          );
        }).toThrow("User ID is required");
      });

      it("should throw error when user ID is null", () => {
        expect(() => {
          new User(
            null as any,
            validEmail,
            validPasswordHash,
            validRoles,
            UserStatus.ACTIVE,
            validCreatedAt,
            validUpdatedAt,
            validTenantId,
          );
        }).toThrow("User ID is required");
      });

      it("should throw error when tenant ID is empty", () => {
        expect(() => {
          new User(
            validUserId,
            validEmail,
            validPasswordHash,
            validRoles,
            UserStatus.ACTIVE,
            validCreatedAt,
            validUpdatedAt,
            "",
          );
        }).toThrow("Tenant ID is required");
      });

      it("should throw error when createdAt is after updatedAt", () => {
        expect(() => {
          new User(
            validUserId,
            validEmail,
            validPasswordHash,
            validRoles,
            UserStatus.ACTIVE,
            validUpdatedAt, // After
            validCreatedAt, // Before
            validTenantId,
          );
        }).toThrow("CreatedAt cannot be after UpdatedAt");
      });
    });
  });

  describe("Role Management", () => {
    let user: User;

    beforeEach(() => {
      user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        ["user"],
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );
    });

    describe("addRole", () => {
      it("should add a new role to the user", () => {
        const initialRolesCount = user.roles.length;
        user.addRole("admin");

        expect(user.roles).toHaveLength(initialRolesCount + 1);
        expect(user.hasRole("admin")).toBe(true);
      });

      it("should not add duplicate role", () => {
        user.addRole("admin");
        const initialRolesCount = user.roles.length;
        user.addRole("admin");

        expect(user.roles).toHaveLength(initialRolesCount);
      });

      it("should update updatedAt when adding role", () => {
        const originalUpdatedAt = user.updatedAt;
        user.addRole("admin");

        expect(user.updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt.getTime(),
        );
      });
    });

    describe("removeRole", () => {
      it("should remove an existing role from the user", () => {
        user.addRole("admin");
        user.removeRole("admin");

        expect(user.hasRole("admin")).toBe(false);
      });

      it("should handle removing non-existent role gracefully", () => {
        const initialRolesCount = user.roles.length;
        user.removeRole("non-existent");

        expect(user.roles).toHaveLength(initialRolesCount);
      });

      it("should update updatedAt when removing role", () => {
        const originalUpdatedAt = user.updatedAt;
        user.removeRole("user");

        expect(user.updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt.getTime(),
        );
      });
    });

    describe("hasRole", () => {
      it("should return true when user has the role", () => {
        expect(user.hasRole("user")).toBe(true);
      });

      it("should return false when user does not have the role", () => {
        expect(user.hasRole("admin")).toBe(false);
      });
    });
  });

  describe("Status Transitions", () => {
    let user: User;

    beforeEach(() => {
      user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );
    });

    describe("changeStatus", () => {
      it("should transition from ACTIVE to INACTIVE", () => {
        user.changeStatus(UserStatus.INACTIVE);

        expect(user.status).toBe(UserStatus.INACTIVE);
        expect(user.isActive()).toBe(false);
      });

      it("should transition from ACTIVE to SUSPENDED", () => {
        user.changeStatus(UserStatus.SUSPENDED);

        expect(user.status).toBe(UserStatus.SUSPENDED);
        expect(user.isActive()).toBe(false);
      });

      it("should transition from SUSPENDED to ACTIVE", () => {
        user.changeStatus(UserStatus.SUSPENDED);
        user.changeStatus(UserStatus.ACTIVE);

        expect(user.status).toBe(UserStatus.ACTIVE);
        expect(user.isActive()).toBe(true);
      });

      it("should transition from INACTIVE to ACTIVE", () => {
        user.changeStatus(UserStatus.INACTIVE);
        user.changeStatus(UserStatus.ACTIVE);

        expect(user.status).toBe(UserStatus.ACTIVE);
        expect(user.isActive()).toBe(true);
      });

      it("should update updatedAt when changing status", () => {
        const originalUpdatedAt = user.updatedAt;
        user.changeStatus(UserStatus.SUSPENDED);

        expect(user.updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt.getTime(),
        );
      });
    });

    describe("isActive", () => {
      it("should return true when status is ACTIVE", () => {
        expect(user.isActive()).toBe(true);
      });

      it("should return false when status is INACTIVE", () => {
        user.changeStatus(UserStatus.INACTIVE);
        expect(user.isActive()).toBe(false);
      });

      it("should return false when status is SUSPENDED", () => {
        user.changeStatus(UserStatus.SUSPENDED);
        expect(user.isActive()).toBe(false);
      });
    });
  });

  describe("Email Management", () => {
    let user: User;

    beforeEach(() => {
      user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );
    });

    describe("updateEmail", () => {
      it("should update the user's email address", () => {
        const newEmail = new Email("newemail@example.com");
        user.updateEmail(newEmail);

        expect(user.email.value).toBe("newemail@example.com");
      });

      it("should update updatedAt when changing email", () => {
        const originalUpdatedAt = user.updatedAt;
        const newEmail = new Email("newemail@example.com");
        user.updateEmail(newEmail);

        expect(user.updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt.getTime(),
        );
      });
    });
  });

  describe("Password Management", () => {
    let user: User;

    beforeEach(() => {
      user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );
    });

    describe("updatePassword", () => {
      it("should update the user's password hash", () => {
        const newPasswordHash = new PasswordHash(
          "$argon2id$v=19$m=65536,t=3,p=4$newHash",
        );
        user.updatePassword(newPasswordHash);

        expect(user.hashedPassword.hash).toBe(newPasswordHash.hash);
      });

      it("should update updatedAt when changing password", () => {
        const originalUpdatedAt = user.updatedAt;
        const newPasswordHash = new PasswordHash(
          "$argon2id$v=19$m=65536,t=3,p=4$newHash",
        );
        user.updatePassword(newPasswordHash);

        expect(user.updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt.getTime(),
        );
      });
    });
  });

  describe("Tenant Isolation", () => {
    it("should store and return tenant ID correctly", () => {
      const user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );

      expect(user.tenantId).toBe(validTenantId);
      expect(user.tenantId).not.toBe("different-tenant");
    });

    it("should prevent creation without tenant ID", () => {
      expect(() => {
        new User(
          validUserId,
          validEmail,
          validPasswordHash,
          validRoles,
          UserStatus.ACTIVE,
          validCreatedAt,
          validUpdatedAt,
          "",
        );
      }).toThrow("Tenant ID is required");
    });
  });

  describe("Audit Timestamps", () => {
    it("should store createdAt timestamp", () => {
      const createdAt = new Date("2024-01-01T12:00:00Z");
      const user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        createdAt,
        validUpdatedAt,
        validTenantId,
      );

      expect(user.createdAt).toEqual(createdAt);
    });

    it("should store updatedAt timestamp", () => {
      const updatedAt = new Date("2024-01-02T12:00:00Z");
      const user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        updatedAt,
        validTenantId,
      );

      expect(user.updatedAt).toEqual(updatedAt);
    });

    it("should return defensive copies of roles array", () => {
      const user = new User(
        validUserId,
        validEmail,
        validPasswordHash,
        validRoles,
        UserStatus.ACTIVE,
        validCreatedAt,
        validUpdatedAt,
        validTenantId,
      );

      const originalRoles = user.roles;
      originalRoles.push("hacker");

      expect(user.roles).not.toContain("hacker");
    });
  });
});
