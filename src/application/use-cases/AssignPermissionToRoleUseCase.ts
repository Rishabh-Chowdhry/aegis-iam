import { Role } from "../../domain/entities/Role";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface AssignPermissionToRoleRequest {
  roleId: string;
  permissionId: string;
  tenantId: string;
  performedBy: string;
}

export interface AssignPermissionToRoleResponse {
  role: Role;
}

export class AssignPermissionToRoleUseCase {
  constructor(
    private roleRepository: IRoleRepository,
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(
    request: AssignPermissionToRoleRequest,
  ): Promise<AssignPermissionToRoleResponse> {
    const { roleId, permissionId, tenantId, performedBy } = request;

    const role = await this.roleRepository.findById(roleId, tenantId);
    if (!role) {
      throw new Error("Role not found");
    }

    const permissionExists = await this.permissionRepository.exists(
      permissionId,
      tenantId,
    );
    if (!permissionExists) {
      throw new Error("Permission not found");
    }

    if (role.hasPermission(permissionId)) {
      throw new Error("Role already has this permission");
    }

    role.addPermission(permissionId);
    await this.roleRepository.update(role);

    // Propagate to child roles
    await this.propagatePermissionToChildren(roleId, permissionId, tenantId);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "ASSIGN_PERMISSION_TO_ROLE",
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

  private async propagatePermissionToChildren(
    parentRoleId: string,
    permissionId: string,
    tenantId: string,
  ): Promise<void> {
    const allRoles = await this.roleRepository.findAll(tenantId);
    const childRoles = allRoles.filter((r) => r.parentId === parentRoleId);

    for (const childRole of childRoles) {
      if (!childRole.hasPermission(permissionId)) {
        childRole.addPermission(permissionId);
        await this.roleRepository.update(childRole);
        // Recursively propagate to grandchildren
        await this.propagatePermissionToChildren(
          childRole.id,
          permissionId,
          tenantId,
        );
      }
    }
  }
}
