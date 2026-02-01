import { User, UserStatus } from "../../domain/entities/User";
import { Email } from "../../domain/value-objects/Email";
import { PasswordHash } from "../../domain/value-objects/PasswordHash";
import { PasswordService } from "../auth/services/PasswordService";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { AppError, ErrorCode } from "../../shared/errors/AppError";
import { logger } from "../../shared/logger";

// Initialize password service instance
const passwordService = PasswordService.getInstance();

export interface CreateUserRequest {
  email: string;
  password: string;
  roles?: string[];
  tenantId: string;
}

export interface UpdateUserRequest {
  email?: string;
  roles?: string[];
  status?: "active" | "inactive" | "suspended";
  tenantId: string;
}

export interface ChangePasswordRequest {
  currentPassword: string;
  newPassword: string;
  tenantId: string;
}

export class UserService {
  private userRepository: IUserRepository;
  private auditLogRepository: IAuditLogRepository;

  constructor(
    userRepository: IUserRepository,
    auditLogRepository: IAuditLogRepository,
  ) {
    this.userRepository = userRepository;
    this.auditLogRepository = auditLogRepository;
  }

  /**
   * Create a new user
   */
  async createUser(request: CreateUserRequest): Promise<User> {
    try {
      const email = new Email(request.email);

      // Check if user already exists
      const existingUser = await this.userRepository.findByEmail(
        email.value,
        request.tenantId,
      );
      if (existingUser) {
        throw AppError.fromErrorCode(
          ErrorCode.RESOURCE_ALREADY_EXISTS,
          "User with this email already exists",
        );
      }

      // Hash password
      const hashedPassword = await passwordService.hash(request.password);
      const passwordHash = new PasswordHash(hashedPassword);

      // Generate a unique ID for the user
      const userId = `user_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

      // Create user
      const user = new User(
        userId,
        email,
        passwordHash,
        request.roles || [],
        UserStatus.ACTIVE,
        new Date(),
        new Date(),
        request.tenantId,
      );

      await this.userRepository.save(user);

      await this.logAudit(
        "user_created",
        user.id,
        "user",
        user.id,
        request.tenantId,
        {
          email: request.email,
          roles: request.roles,
        },
      );

      logger.info("User created successfully", {
        userId: user.id,
        email: request.email,
        tenantId: request.tenantId,
      });

      return user;
    } catch (error) {
      logger.error("Failed to create user", {
        email: request.email,
        tenantId: request.tenantId,
        error: (error as Error).message,
      });
      throw error;
    }
  }

  /**
   * Get user by ID
   */
  async getUserById(userId: string, tenantId: string): Promise<User> {
    const user = await this.userRepository.findById(userId, tenantId);
    if (!user) {
      throw AppError.fromErrorCode(ErrorCode.USER_NOT_FOUND);
    }
    return user;
  }

  /**
   * Get all users for a tenant
   */
  async getAllUsers(tenantId: string): Promise<User[]> {
    return await this.userRepository.findAll(tenantId);
  }

  /**
   * Update user
   */
  async updateUser(userId: string, request: UpdateUserRequest): Promise<User> {
    const user = await this.getUserById(userId, request.tenantId);

    // Update email if provided
    if (request.email && request.email !== user.email.value) {
      const newEmail = new Email(request.email);
      // Check if new email is already taken
      const existingUser = await this.userRepository.findByEmail(
        newEmail.value,
        request.tenantId,
      );
      if (existingUser && existingUser.id !== userId) {
        throw AppError.fromErrorCode(
          ErrorCode.RESOURCE_ALREADY_EXISTS,
          "Email already in use",
        );
      }
      user.updateEmail(newEmail);
    }

    // Update roles if provided
    if (request.roles !== undefined) {
      // Clear existing roles and add new ones
      // Note: In a real implementation, you might want to validate role existence
      // For now, we'll use the existing roles methods
      const currentRoles = user.roles;
      currentRoles.forEach((roleId) => user.removeRole(roleId));
      request.roles.forEach((roleId) => user.addRole(roleId));
    }

    // Update status if provided
    if (request.status) {
      user.changeStatus(request.status as any);
    }

    await this.userRepository.update(user);

    await this.logAudit(
      "user_updated",
      userId,
      "user",
      userId,
      request.tenantId,
      {
        changes: request,
      },
    );

    logger.info("User updated successfully", {
      userId,
      tenantId: request.tenantId,
      changes: request,
    });

    return user;
  }

  /**
   * Delete user
   */
  async deleteUser(userId: string, tenantId: string): Promise<void> {
    const user = await this.getUserById(userId, tenantId);

    await this.userRepository.delete(userId, tenantId);

    await this.logAudit("user_deleted", userId, "user", userId, tenantId, {
      email: user.email.value,
    });

    logger.info("User deleted successfully", {
      userId,
      tenantId,
      email: user.email.value,
    });
  }

  /**
   * Change user password
   */
  async changeUserPassword(
    userId: string,
    request: ChangePasswordRequest,
  ): Promise<void> {
    const user = await this.getUserById(userId, request.tenantId);

    // Verify current password
    const isCurrentPasswordValid = await passwordService.verify(
      request.currentPassword,
      user.hashedPassword.hash,
    );

    if (!isCurrentPasswordValid) {
      await this.logAudit(
        "password_change_failed",
        userId,
        "user",
        userId,
        request.tenantId,
        {
          reason: "invalid_current_password",
        },
      );
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_CREDENTIALS,
        "Current password is incorrect",
      );
    }

    // Hash new password
    const newHashedPassword = await passwordService.hash(request.newPassword);
    const newPasswordHash = new PasswordHash(newHashedPassword);

    // Update user password
    user.updatePassword(newPasswordHash);
    await this.userRepository.update(user);

    await this.logAudit(
      "password_changed",
      userId,
      "user",
      userId,
      request.tenantId,
      undefined,
    );

    logger.info("User password changed successfully", {
      userId,
      tenantId: request.tenantId,
    });
  }

  /**
   * Assign role to user
   */
  async assignRoleToUser(
    userId: string,
    roleId: string,
    tenantId: string,
  ): Promise<User> {
    const user = await this.getUserById(userId, tenantId);

    if (!user.roles.includes(roleId)) {
      user.addRole(roleId);
      await this.userRepository.update(user);

      await this.logAudit("role_assigned", userId, "user", userId, tenantId, {
        roleId,
      });

      logger.info("Role assigned to user", {
        userId,
        roleId,
        tenantId,
      });

      return user;
    }

    return user;
  }

  /**
   * Remove role from user
   */
  async removeRoleFromUser(
    userId: string,
    roleId: string,
    tenantId: string,
  ): Promise<User> {
    const user = await this.getUserById(userId, tenantId);

    user.removeRole(roleId);
    await this.userRepository.update(user);

    await this.logAudit("role_removed", userId, "user", userId, tenantId, {
      roleId,
    });

    logger.info("Role removed from user", {
      userId,
      roleId,
      tenantId,
    });

    return user;
  }

  /**
   * Log audit event
   */
  private async logAudit(
    action: string,
    userId: string | undefined,
    resource: string,
    resourceId: string | undefined,
    tenantId: string,
    details?: any,
  ): Promise<void> {
    try {
      const auditEntry = new AuditLogEntry(
        userId || "system",
        action,
        new Date(),
        {
          resource,
          resourceId,
          ...details,
        },
        tenantId,
      );

      await this.auditLogRepository.save(auditEntry);
    } catch (error) {
      // Don't fail the main operation if audit logging fails
      logger.error("Failed to log audit event", {
        error: (error as Error).message,
      });
    }
  }
}
