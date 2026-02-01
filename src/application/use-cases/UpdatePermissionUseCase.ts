import { Permission } from "../../domain/entities/Permission";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export class UpdatePermissionUseCase {
  constructor(
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: {
    id: string;
    name?: string;
    resource?: string;
    action?: string;
    description?: string;
    tenantId: string;
    performedBy: string;
  }): Promise<Permission> {
    const { id, name, resource, action, description, tenantId, performedBy } =
      request;

    const existing = await this.permissionRepository.findById(id, tenantId);
    if (!existing) {
      throw new Error("Permission not found");
    }

    const updatedPermission = new Permission(
      id,
      name || existing.name,
      resource || existing.resource,
      action || existing.action,
      description || existing.description,
      tenantId,
    );

    await this.permissionRepository.update(updatedPermission);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "UPDATE_PERMISSION",
      new Date(),
      {
        permissionId: id,
        changes: { resource, action, description },
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return updatedPermission;
  }
}
