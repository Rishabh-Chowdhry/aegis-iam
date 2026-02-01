import { PrismaClient } from "@prisma/client";
import {
  ITenantRepository,
  CreateTenantDTO,
  UpdateTenantDTO,
  TenantFilterDTO,
  TenantWithStats,
} from "../../modules/iam/repositories/ITenantRepository";

export class PrismaTenantRepository implements ITenantRepository {
  constructor(private prisma: PrismaClient) {}

  async create(data: CreateTenantDTO): Promise<any> {
    return (this.prisma as any).tenant.create({
      data: {
        name: data.name,
        settings: data.settings || {},
        status: data.status || "PENDING",
      },
    });
  }

  async findById(id: string): Promise<any | null> {
    return (this.prisma as any).tenant.findUnique({
      where: { id },
    });
  }

  async findByName(name: string): Promise<any | null> {
    return (this.prisma as any).tenant.findUnique({
      where: { name },
    });
  }

  async findAll(filter?: TenantFilterDTO): Promise<any[]> {
    const where: any = {};

    if (filter?.status) {
      where.status = filter.status;
    }

    const orderBy: any = {};
    if (filter?.sortBy) {
      orderBy[filter.sortBy] = filter.sortOrder || "asc";
    } else {
      orderBy.createdAt = "desc";
    }

    const skip =
      filter?.page && filter?.limit
        ? (filter.page - 1) * filter.limit
        : undefined;
    const take = filter?.limit;

    return (this.prisma as any).tenant.findMany({
      where,
      orderBy,
      skip,
      take,
    });
  }

  async update(id: string, data: UpdateTenantDTO): Promise<any> {
    return (this.prisma as any).tenant.update({
      where: { id },
      data: {
        ...(data.name !== undefined && { name: data.name }),
        ...(data.settings !== undefined && { settings: data.settings }),
        ...(data.status !== undefined && { status: data.status }),
      },
    });
  }

  async updateStatus(id: string, status: any): Promise<any> {
    return (this.prisma as any).tenant.update({
      where: { id },
      data: { status },
    });
  }

  async delete(id: string): Promise<boolean> {
    const result = await (this.prisma as any).tenant.deleteMany({
      where: { id },
    });
    return result.count > 0;
  }

  async exists(id: string): Promise<boolean> {
    const count = await (this.prisma as any).tenant.count({
      where: { id },
    });
    return count > 0;
  }

  async count(status?: any): Promise<number> {
    return (this.prisma as any).tenant.count({
      where: status ? { status } : undefined,
    });
  }

  async findByIdWithStats(id: string): Promise<TenantWithStats | null> {
    const tenant = await (this.prisma as any).tenant.findUnique({
      where: { id },
      include: {
        _count: {
          select: {
            users: true,
            policies: true,
          },
        },
      },
    });

    if (!tenant) return null;

    return {
      ...tenant,
      userCount: tenant._count.users,
      policyCount: tenant._count.policies,
    };
  }

  async findChildren(parentId: string): Promise<any[]> {
    return (this.prisma as any).tenant.findMany({
      where: { parentId },
      orderBy: { createdAt: "asc" },
    });
  }

  async findHierarchy(id: string): Promise<any[]> {
    const tenant = await (this.prisma as any).tenant.findUnique({
      where: { id },
    });

    if (!tenant) return [];

    const hierarchy: any[] = [tenant];
    let currentParentId = tenant.parentId;

    while (currentParentId) {
      const parent = await (this.prisma as any).tenant.findUnique({
        where: { id: currentParentId },
      });

      if (!parent) break;

      hierarchy.unshift(parent);
      currentParentId = parent.parentId;
    }

    return hierarchy;
  }

  async terminate(id: string): Promise<any> {
    return (this.prisma as any).tenant.update({
      where: { id },
      data: {
        status: "TERMINATED",
        terminatedAt: new Date(),
      },
    });
  }

  async findByStatus(status: any): Promise<any[]> {
    return (this.prisma as any).tenant.findMany({
      where: { status },
      orderBy: { createdAt: "desc" },
    });
  }
}
