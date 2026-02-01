import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export class DeletePermissionUseCase {
  constructor(
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: {
    id: string;
    tenantId: string;
    performedBy: string;
  }): Promise<void> {
    const { id, tenantId, performedBy } = request;

    const existing = await this.permissionRepository.findById(id, tenantId);
    if (!existing) {
      throw new Error("Permission not found");
    }

    await this.permissionRepository.delete(id, tenantId);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "DELETE_PERMISSION",
      new Date(),
      { permissionId: id },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);
  }
}
