import { User } from "../../domain/entities/User";

export interface IUserRepository {
  findById(id: string, tenantId: string): Promise<User | null>;
  findByEmail(email: string, tenantId: string): Promise<User | null>;
  findAll(tenantId: string): Promise<User[]>;
  save(user: User): Promise<void>;
  update(user: User): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  exists(id: string, tenantId: string): Promise<boolean>;
}
