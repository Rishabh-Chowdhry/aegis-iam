import { Role } from "../../domain/entities/Role";

export interface IRoleRepository {
  findById(id: string, tenantId: string): Promise<Role | null>;
  findByName(name: string, tenantId: string): Promise<Role | null>;
  findAll(tenantId: string): Promise<Role[]>;
  save(role: Role): Promise<void>;
  update(role: Role): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  exists(id: string, tenantId: string): Promise<boolean>;
}
