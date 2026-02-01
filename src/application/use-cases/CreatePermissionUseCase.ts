import { Permission } from "../../domain/entities/Permission";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export class CreatePermissionUseCase {
  constructor(
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: {
    id: string;
    name: string;
    resource: string;
    action: string;
    description: string;
    tenantId: string;
    performedBy: string;
  }): Promise<Permission> {
    const { id, name, resource, action, description, tenantId, performedBy } =
      request;

    // Check if permission already exists
    const existing = await this.permissionRepository.findById(id, tenantId);
    if (existing) {
      throw new Error("Permission already exists");
    }

    const permission = new Permission(
      id,
      name,
      resource,
      action,
      description,
      tenantId,
    );
    await this.permissionRepository.create(permission);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "CREATE_PERMISSION",
      new Date(),
      { permissionId: id, resource, action },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return permission;
  }
}
