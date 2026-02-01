import { Permission } from "../../domain/entities/Permission";

export interface IPermissionRepository {
  findById(id: string, tenantId: string): Promise<Permission | null>;
  findAll(tenantId: string): Promise<Permission[]>;
  exists(id: string, tenantId: string): Promise<boolean>;
  create(permission: Permission): Promise<void>;
  update(permission: Permission): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  findByName(name: string, tenantId: string): Promise<Permission | null>;
}
