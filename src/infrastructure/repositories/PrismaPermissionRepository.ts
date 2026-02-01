import { PrismaClient } from "@prisma/client";
import { Permission } from "../../domain/entities/Permission";
import { IPermissionRepository } from "./IPermissionRepository";

export class PrismaPermissionRepository implements IPermissionRepository {
  constructor(private prisma: PrismaClient) {}

  async findById(id: string, tenantId: string): Promise<Permission | null> {
    const permissionData = await this.prisma.permission.findFirst({
      where: { id, tenantId },
    });
    if (!permissionData) return null;
    return this.mapToDomain(permissionData);
  }

  async findAll(tenantId: string): Promise<Permission[]> {
    const permissionsData = await this.prisma.permission.findMany({
      where: { tenantId },
      orderBy: { createdAt: "desc" },
    });
    return permissionsData.map(this.mapToDomain);
  }

  async exists(id: string, tenantId: string): Promise<boolean> {
    const count = await this.prisma.permission.count({
      where: { id, tenantId },
    });
    return count > 0;
  }

  async create(permission: Permission): Promise<void> {
    await this.prisma.permission.create({
      data: {
        id: permission.id,
        action: permission.name, // Map domain 'name' to Prisma 'action'
        resourceType: permission.resource, // Map domain 'resource' to Prisma 'resourceType'
        description: permission.description,
        tenantId: permission.tenantId,
      } as any,
    });
  }

  async update(permission: Permission): Promise<void> {
    await this.prisma.permission.update({
      where: { id: permission.id },
      data: {
        action: permission.name,
        resourceType: permission.resource,
        description: permission.description,
      } as any,
    });
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.permission.deleteMany({
      where: { id, tenantId },
    });
  }

  async findByName(name: string, tenantId: string): Promise<Permission | null> {
    const permissionData = await this.prisma.permission.findFirst({
      where: { action: name, tenantId },
    });
    if (!permissionData) return null;
    return this.mapToDomain(permissionData);
  }

  async findByResourceAndAction(
    resource: string,
    action: string,
    tenantId: string,
  ): Promise<Permission[]> {
    const permissionsData = await this.prisma.permission.findMany({
      where: { resourceType: resource, action, tenantId },
    });
    return permissionsData.map(this.mapToDomain);
  }

  private mapToDomain(permissionData: any): Permission {
    return new Permission(
      permissionData.id,
      permissionData.action, // Map Prisma 'action' to domain 'name'
      permissionData.resourceType, // Map Prisma 'resourceType' to domain 'resource'
      permissionData.action,
      permissionData.description || "",
      permissionData.tenantId,
    );
  }
}
