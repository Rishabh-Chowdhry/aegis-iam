import { Permission } from "../../domain/entities/Permission";
import { IPermissionRepository } from "../../infrastructure/repositories/IPermissionRepository";

export class GetPermissionUseCase {
  constructor(private permissionRepository: IPermissionRepository) {}

  async execute(request: {
    id: string;
    tenantId: string;
  }): Promise<Permission | null> {
    const { id, tenantId } = request;
    return this.permissionRepository.findById(id, tenantId);
  }
}
