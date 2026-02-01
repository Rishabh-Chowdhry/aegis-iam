import { PrismaClient } from "@prisma/client";
import { Role } from "../../domain/entities/Role";
import { IRoleRepository } from "./IRoleRepository";

export class PrismaRoleRepository implements IRoleRepository {
  constructor(private prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Role | null> {
    const roleData = await this.prisma.role.findFirst({
      where: { id, tenantId },
    });
    if (!roleData) return null;
    return this.mapToDomain(roleData);
  }

  async findByName(name: string, tenantId: string): Promise<Role | null> {
    const roleData = await this.prisma.role.findFirst({
      where: { name, tenantId },
    });
    if (!roleData) return null;
    return this.mapToDomain(roleData);
  }

  async findAll(tenantId: string): Promise<Role[]> {
    const rolesData = await this.prisma.role.findMany({
      where: { tenantId },
    });
    return rolesData.map(this.mapToDomain);
  }

  async save(role: Role): Promise<void> {
    await this.prisma.role.create({
      data: {
        id: role.id,
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        parentRoleId: role.parentId, // Map domain 'parentId' to Prisma 'parentRoleId'
        tenantId: role.tenantId,
        hierarchyLevel: 0,
      } as any,
    });
  }

  async update(role: Role): Promise<void> {
    await this.prisma.role.update({
      where: { id: role.id },
      data: {
        name: role.name,
        description: role.description,
        permissions: role.permissions,
        parentRoleId: role.parentId,
        updatedAt: role.updatedAt,
      } as any,
    });
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.role.deleteMany({
      where: { id, tenantId },
    });
  }

  async exists(id: string, tenantId: string): Promise<boolean> {
    const count = await this.prisma.role.count({
      where: { id, tenantId },
    });
    return count > 0;
  }

  private mapToDomain(roleData: any): Role {
    return new Role(
      roleData.id,
      roleData.name,
      roleData.description,
      roleData.parentRoleId, // Map Prisma 'parentRoleId' to domain 'parentId'
      roleData.permissions,
      roleData.tenantId,
      roleData.createdAt,
      roleData.updatedAt,
    );
  }
}
