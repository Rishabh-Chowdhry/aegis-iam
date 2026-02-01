import { CreateRoleUseCase } from "../../application/use-cases/CreateRoleUseCase";
import { UpdateRoleUseCase } from "../../application/use-cases/UpdateRoleUseCase";
import { DeleteRoleUseCase } from "../../application/use-cases/DeleteRoleUseCase";
import { AssignPermissionToRoleUseCase } from "../../application/use-cases/AssignPermissionToRoleUseCase";
import { RemovePermissionFromRoleUseCase } from "../../application/use-cases/RemovePermissionFromRoleUseCase";
import { GetRoleHierarchyUseCase } from "../../application/use-cases/GetRoleHierarchyUseCase";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export class RoleService {
  constructor(
    private roleRepository: IRoleRepository,
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async createRole(request: Parameters<CreateRoleUseCase["execute"]>[0]) {
    const useCase = new CreateRoleUseCase(
      this.roleRepository,
      this.permissionRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async updateRole(request: Parameters<UpdateRoleUseCase["execute"]>[0]) {
    const useCase = new UpdateRoleUseCase(
      this.roleRepository,
      this.permissionRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async deleteRole(request: Parameters<DeleteRoleUseCase["execute"]>[0]) {
    const useCase = new DeleteRoleUseCase(
      this.roleRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async assignPermissionToRole(
    request: Parameters<AssignPermissionToRoleUseCase["execute"]>[0],
  ) {
    const useCase = new AssignPermissionToRoleUseCase(
      this.roleRepository,
      this.permissionRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async removePermissionFromRole(
    request: Parameters<RemovePermissionFromRoleUseCase["execute"]>[0],
  ) {
    const useCase = new RemovePermissionFromRoleUseCase(
      this.roleRepository,
      this.permissionRepository,
      this.auditLogRepository,
    );
    return useCase.execute(request);
  }

  async getRoleHierarchy(
    request: Parameters<GetRoleHierarchyUseCase["execute"]>[0],
  ) {
    const useCase = new GetRoleHierarchyUseCase(this.roleRepository);
    return useCase.execute(request);
  }

  async getRoleById(roleId: string, tenantId: string) {
    return this.roleRepository.findById(roleId, tenantId);
  }

  async getAllRoles(tenantId: string) {
    return this.roleRepository.findAll(tenantId);
  }

  async checkPermission(
    roleId: string,
    permissionId: string,
    tenantId: string,
  ): Promise<boolean> {
    const role = await this.roleRepository.findById(roleId, tenantId);
    if (!role) return false;

    // Check direct permissions
    if (role.hasPermission(permissionId)) return true;

    // Check inherited permissions
    return this.checkInheritedPermission(
      role,
      permissionId,
      tenantId,
      new Set(),
    );
  }

  private async checkInheritedPermission(
    role: any,
    permissionId: string,
    tenantId: string,
    visited: Set<string>,
  ): Promise<boolean> {
    if (visited.has(role.id)) return false; // Prevent cycles
    visited.add(role.id);

    if (!role.parentRoleId) return false;

    const parentRole = await this.roleRepository.findById(
      role.parentRoleId,
      tenantId,
    );
    if (!parentRole) return false;

    if (parentRole.hasPermission(permissionId)) return true;

    return this.checkInheritedPermission(
      parentRole,
      permissionId,
      tenantId,
      visited,
    );
  }
}
