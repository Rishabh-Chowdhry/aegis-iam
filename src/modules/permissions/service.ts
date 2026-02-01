import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IUserRepository } from "../../infrastructure/repositories/IUserRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export class PermissionService {
  constructor(
    private permissionRepository: IPermissionRepository,
    private roleRepository: IRoleRepository,
    private userRepository: IUserRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async checkPermission(
    resource: string,
    action: string,
    tenantId: string,
    userId?: string,
  ): Promise<boolean> {
    try {
      if (!userId) {
        return false; // No user, no permission
      }

      const user = await this.userRepository.findById(userId, tenantId);
      if (!user || !user.isActive()) {
        return false;
      }

      // Get all permissions for user's roles
      const userPermissions = new Set<string>();
      for (const roleId of user.roles) {
        const role = await this.roleRepository.findById(roleId, tenantId);
        if (role) {
          // Add direct permissions
          role.permissions.forEach((permId) => userPermissions.add(permId));

          // Add permissions from parent roles (recursive)
          await this.addParentPermissions(role, userPermissions, tenantId);
        }
      }

      // Check if any permission matches the required resource:action
      for (const permId of userPermissions) {
        const permission = await this.permissionRepository.findById(
          permId,
          tenantId,
        );
        if (permission && permission.matches(resource, action)) {
          return true;
        }
      }

      return false;
    } catch (error) {
      console.error("Error checking permission:", error);
      return false; // Fail-closed
    }
  }

  private async addParentPermissions(
    role: any,
    permissions: Set<string>,
    tenantId: string,
  ): Promise<void> {
    if (role.parentId) {
      const parentRole = await this.roleRepository.findById(
        role.parentId,
        tenantId,
      );
      if (parentRole) {
        parentRole.permissions.forEach((permId) => permissions.add(permId));
        await this.addParentPermissions(parentRole, permissions, tenantId);
      }
    }
  }

  // Additional methods for controller
  async createPermission(request: any) {
    const { CreatePermissionUseCase } =
      await import("../../application/use-cases/CreatePermissionUseCase");
    const useCase = new CreatePermissionUseCase(
      this.permissionRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async updatePermission(request: any) {
    // Implementation would use UpdatePermissionUseCase
    throw new Error("Not implemented");
  }

  async deletePermission(request: any) {
    // Implementation would use DeletePermissionUseCase
    throw new Error("Not implemented");
  }

  async getPermission(request: any) {
    const { GetPermissionUseCase } =
      await import("../../application/use-cases/GetPermissionUseCase");
    const useCase = new GetPermissionUseCase(this.permissionRepository);
    return useCase.execute(request);
    throw new Error("Not implemented");
  }

  async getAllPermissions(request: any) {
    const { GetAllPermissionsUseCase } =
      await import("../../application/use-cases/GetAllPermissionsUseCase");
    const useCase = new GetAllPermissionsUseCase(this.permissionRepository);
    return useCase.execute(request);
  }
}
