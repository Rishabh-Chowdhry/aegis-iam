import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface DeleteRoleRequest {
  roleId: string;
  tenantId: string;
  performedBy: string;
}

export interface DeleteRoleResponse {
  success: boolean;
}

export class DeleteRoleUseCase {
  constructor(
    private roleRepository: IRoleRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: DeleteRoleRequest): Promise<DeleteRoleResponse> {
    const { roleId, tenantId, performedBy } = request;

    const role = await this.roleRepository.findById(roleId, tenantId);
    if (!role) {
      throw new Error("Role not found");
    }

    // Check for child roles
    const allRoles = await this.roleRepository.findAll(tenantId);
    const hasChildren = allRoles.some((r) => r.parentId === roleId);
    if (hasChildren) {
      throw new Error(
        "Cannot delete role with child roles. Reassign children first.",
      );
    }

    await this.roleRepository.delete(roleId, tenantId);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "DELETE_ROLE",
      new Date(),
      {
        roleId,
        name: role.name,
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return { success: true };
  }
}
