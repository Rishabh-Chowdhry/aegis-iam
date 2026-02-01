import { Permission } from "../../domain/entities/Permission";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";

export class GetAllPermissionsUseCase {
  constructor(private permissionRepository: IPermissionRepository) {}

  async execute(request: { tenantId: string }): Promise<Permission[]> {
    const { tenantId } = request;
    return this.permissionRepository.findAll(tenantId);
  }
}
