import { Role } from "../../domain/entities/Role";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface UpdateRoleRequest {
  roleId: string;
  name?: string;
  description?: string;
  parentRoleId?: string | null;
  permissions?: string[];
  tenantId: string;
  performedBy: string;
}

export interface UpdateRoleResponse {
  role: Role;
}

export class UpdateRoleUseCase {
  constructor(
    private roleRepository: IRoleRepository,
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: UpdateRoleRequest): Promise<UpdateRoleResponse> {
    const {
      roleId,
      name,
      description,
      parentRoleId,
      permissions,
      tenantId,
      performedBy,
    } = request;

    const role = await this.roleRepository.findById(roleId, tenantId);
    if (!role) {
      throw new Error("Role not found");
    }

    // Validate new name if provided
    if (name && name !== role.name) {
      const existingRole = await this.roleRepository.findByName(name, tenantId);
      if (existingRole && existingRole.id !== roleId) {
        throw new Error("Role with this name already exists");
      }
    }

    // Validate parent role if provided
    if (parentRoleId !== undefined) {
      if (parentRoleId) {
        const parentRole = await this.roleRepository.findById(
          parentRoleId,
          tenantId,
        );
        if (!parentRole) {
          throw new Error("Parent role not found");
        }
        if (parentRoleId === roleId) {
          throw new Error("Role cannot be its own parent");
        }
      }
      role.setParentRole(parentRoleId);
    }

    // Validate permissions if provided
    if (permissions) {
      for (const permId of permissions) {
        const exists = await this.permissionRepository.exists(permId, tenantId);
        if (!exists) {
          throw new Error(`Permission ${permId} does not exist`);
        }
      }
      // Update permissions
      role.permissions.forEach((p) => role.removePermission(p));
      permissions.forEach((p) => role.addPermission(p));
    }

    // Note: Role entity doesn't allow direct name changes after creation for immutability
    // Name changes should be handled via domain events or recreation
    if (description) role.updateDescription(description);

    await this.roleRepository.update(role);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "UPDATE_ROLE",
      new Date(),
      {
        roleId,
        changes: { name, description, parentRoleId, permissions },
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return { role };
  }
}
