import { Role } from "../../domain/entities/Role";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IRoleRepository } from "../../infrastructure/repositories/IRoleRepository";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface CreateRoleRequest {
  name: string;
  description: string;
  parentRoleId?: string;
  permissions?: string[];
  tenantId: string;
  performedBy: string;
}

export interface CreateRoleResponse {
  role: Role;
}

export class CreateRoleUseCase {
  constructor(
    private roleRepository: IRoleRepository,
    private permissionRepository: IPermissionRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: CreateRoleRequest): Promise<CreateRoleResponse> {
    const {
      name,
      description,
      parentRoleId,
      permissions = [],
      tenantId,
      performedBy,
    } = request;

    // Check if role already exists
    const existingRole = await this.roleRepository.findByName(name, tenantId);
    if (existingRole) {
      throw new Error("Role with this name already exists");
    }

    // Validate parent role if provided
    if (parentRoleId) {
      const parentRole = await this.roleRepository.findById(
        parentRoleId,
        tenantId,
      );
      if (!parentRole) {
        throw new Error("Parent role not found");
      }
    }

    // Validate permissions
    for (const permId of permissions) {
      const exists = await this.permissionRepository.exists(permId, tenantId);
      if (!exists) {
        throw new Error(`Permission ${permId} does not exist`);
      }
    }

    // Generate unique ID
    const roleId = `role-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const role = new Role(
      roleId,
      name,
      description,
      parentRoleId || null,
      permissions,
      tenantId,
    );

    await this.roleRepository.save(role);

    // Audit log
    const auditEntry = new AuditLogEntry(
      performedBy,
      "CREATE_ROLE",
      new Date(),
      {
        roleId,
        name,
        description,
        parentRoleId,
        permissions,
      },
      tenantId,
    );
    await this.auditLogRepository.save(auditEntry);

    return { role };
  }
}
