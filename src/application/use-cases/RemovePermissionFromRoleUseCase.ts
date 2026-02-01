import { Role } from "../../domain/entities/Role";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface RemovePermissionFromRoleRequest {
  roleId: string;
  permissionId: string;
  tenantId: string;
  performedBy: string;
}

export interface RemovePermissionFromRoleResponse {
  role: Role;
}

export class RemovePermissionFromRoleUseCase {
  constructor(
    private roleRepository: IRoleRepository,
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(
    request: RemovePermissionFromRoleRequest,
  ): Promise<RemovePermissionFromRoleResponse> {
    const { roleId, permissionId, tenantId, performedBy } = request;

    const role = await this.roleRepository.findById(roleId, tenantId);
    if (!role) {
      throw new Error("Role not found");
    }

    if (!role.hasPermission(permissionId)) {
      throw new Error("Role does not have this permission");
    }

    role.removePermission(permissionId);
    await this.roleRepository.update(role);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "REMOVE_PERMISSION_FROM_ROLE",
      new Date(),
      {
        roleId,
        permissionId,
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return { role };
  }
}
