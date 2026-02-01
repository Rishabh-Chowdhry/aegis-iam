import { PrismaClient } from "@prisma/client";
import { Policy as DomainPolicy } from "../../domain/entities/Policy";
import {
  IPolicyRepository,
  CreatePolicyInput,
  CreatePolicyLegacyInput,
  UpdatePolicyInput,
  ListOptions,
} from "./IPolicyRepository";

export class PrismaPolicyRepository implements IPolicyRepository {
  constructor(private prisma: PrismaClient) {}

  async save(policy: DomainPolicy): Promise<DomainPolicy> {
    await this.prisma.policy.create({
      data: {
        id: policy.id,
        name: policy.name,
        document: policy.conditions as any,
        description: policy.description,
        tenantId: policy.tenantId,
        createdBy: "system",
        status: "DRAFT",
      } as any,
    });
    return policy;
  }

  async create(
    data: CreatePolicyInput | CreatePolicyLegacyInput,
  ): Promise<DomainPolicy> {
    // Handle legacy format with conditions and effect
    if ("conditions" in data && "effect" in data) {
      const legacyData = data as CreatePolicyLegacyInput;
      const saved = await this.prisma.policy.create({
        data: {
          name: legacyData.name,
          document: {
            conditions: legacyData.conditions,
            effect: legacyData.effect,
          } as any,
          description: legacyData.description,
          tenantId: legacyData.tenantId,
          createdBy: legacyData.createdBy,
          status: "DRAFT",
        } as any,
      });
      return this.mapToDomain(saved);
    }

    // Handle new format with document
    const newData = data as CreatePolicyInput;
    const saved = await this.prisma.policy.create({
      data: {
        name: newData.name,
        document: newData.document as any,
        description: newData.description,
        tenantId: newData.tenantId,
        createdBy: newData.createdBy,
        status: newData.status || "DRAFT",
        version: newData.version,
        tags: newData.tags as any,
      } as any,
    });
    return this.mapToDomain(saved);
  }

  async findById(id: string, tenantId: string): Promise<DomainPolicy | null> {
    const policyData = await this.prisma.policy.findFirst({
      where: { id, tenantId },
    });
    if (!policyData) return null;
    return this.mapToDomain(policyData);
  }

  async findByName(
    name: string,
    tenantId: string,
  ): Promise<DomainPolicy | null> {
    const policyData = await this.prisma.policy.findFirst({
      where: { name, tenantId },
    });
    if (!policyData) return null;
    return this.mapToDomain(policyData);
  }

  async findAll(
    tenantId: string,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }> {
    const where: any = { tenantId };

    if (options?.status) {
      where.status = options.status;
    }

    const [policiesData, total] = await Promise.all([
      this.prisma.policy.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
        take: options?.limit || 10,
      }),
      this.prisma.policy.count({ where }),
    ]);

    return {
      policies: policiesData.map(this.mapToDomain),
      total,
    };
  }

  async findByStatus(
    tenantId: string,
    status: string,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }> {
    return this.findAll(tenantId, { ...options, status: status as any });
  }

  async update(id: string, data: UpdatePolicyInput): Promise<DomainPolicy> {
    const updated = await this.prisma.policy.update({
      where: { id },
      data: {
        name: data.name,
        description: data.description,
        document: data.document as any,
        tags: data.tags as any,
        status: data.status,
      } as any,
    });
    return this.mapToDomain(updated);
  }

  async delete(id: string, tenantId: string): Promise<void> {
    await this.prisma.policy.deleteMany({
      where: { id, tenantId },
    });
  }

  async softDelete(
    id: string,
    deletedBy: string,
    tenantId: string,
  ): Promise<DomainPolicy> {
    const updated = await this.prisma.policy.update({
      where: { id },
      data: {
        deletedAt: new Date(),
        deletedBy,
      },
    });
    return this.mapToDomain(updated);
  }

  async restore(id: string, tenantId: string): Promise<DomainPolicy> {
    const updated = await this.prisma.policy.update({
      where: { id },
      data: {
        deletedAt: null,
        deletedBy: null,
      },
    });
    return this.mapToDomain(updated);
  }

  async findActiveByTenant(tenantId: string): Promise<DomainPolicy[]> {
    const policiesData = await this.prisma.policy.findMany({
      where: { tenantId, status: "ACTIVE" },
      orderBy: { createdAt: "desc" },
    });
    return policiesData.map(this.mapToDomain);
  }

  async getVersionHistory(policyId: string): Promise<DomainPolicy[]> {
    const policy = await this.prisma.policy.findUnique({
      where: { id: policyId },
    });
    if (!policy || !policy.versionHistory) return [];

    const versions = policy.versionHistory as any[];
    return versions.map(
      (v: any) =>
        new DomainPolicy(
          v.id,
          v.name,
          v.conditions || v.document?.conditions || {},
          v.effect || v.document?.effect || "deny",
          v.description,
          v.tenantId,
        ),
    );
  }

  async createVersion(
    id: string,
    data: CreatePolicyInput,
    tenantId: string,
  ): Promise<DomainPolicy> {
    const current = await this.prisma.policy.findUnique({
      where: { id },
    });

    if (current) {
      // Add current version to history
      const history = (current.versionHistory as any[]) || [];
      history.push({
        id: current.id,
        name: current.name,
        document: current.document,
        createdAt: current.createdAt,
      });

      // Update with new version
      const updated = await this.prisma.policy.update({
        where: { id },
        data: {
          name: data.name || current.name,
          document: data.document as any,
          description: data.description || current.description,
          versionHistory: history,
        } as any,
      });
      return this.mapToDomain(updated);
    }

    throw new Error("Policy not found");
  }

  async getVersion(
    id: string,
    versionNumber: number,
  ): Promise<DomainPolicy | null> {
    const policy = await this.prisma.policy.findUnique({
      where: { id },
    });
    if (!policy) return null;

    const versions = policy.versionHistory as any[];
    if (!versions || versions.length < versionNumber) return null;

    const version = versions[versionNumber - 1];
    return new DomainPolicy(
      version.id,
      version.name,
      version.conditions || version.document?.conditions || {},
      version.effect || version.document?.effect || "deny",
      version.description,
      version.tenantId,
    );
  }

  async rollbackToVersion(
    policyId: string,
    versionNumber: number,
    rolledBackBy: string,
    tenantId: string,
  ): Promise<DomainPolicy> {
    const policy = await this.prisma.policy.findUnique({
      where: { id: policyId },
    });

    if (!policy) throw new Error("Policy not found");

    const versions = policy.versionHistory as any[];
    if (!versions || versions.length < versionNumber) {
      throw new Error("Version not found");
    }

    const version = versions[versionNumber - 1];

    // Update the policy with the version data
    await this.prisma.policy.update({
      where: { id: policyId },
      data: {
        name: version.name,
        document: version.document,
        description: version.description,
      } as any,
    });

    return this.findById(policyId, tenantId) as Promise<DomainPolicy>;
  }

  async compareVersions(
    policyId: string,
    version1: number,
    version2: number,
  ): Promise<{
    version1: DomainPolicy;
    version2: DomainPolicy;
    differences: { field: string; oldValue: unknown; newValue: unknown }[];
  }> {
    const policy = await this.prisma.policy.findUnique({
      where: { id: policyId },
    });

    if (!policy) throw new Error("Policy not found");

    const versions = policy.versionHistory as any[];
    if (!versions || versions.length < Math.max(version1, version2)) {
      throw new Error("Version not found");
    }

    const v1 = versions[version1 - 1];
    const v2 = versions[version2 - 1];

    const v1Policy = new DomainPolicy(
      v1.id,
      v1.name,
      v1.conditions || v1.document?.conditions || {},
      v1.effect || v1.document?.effect || "deny",
      v1.description,
      v1.tenantId,
    );

    const v2Policy = new DomainPolicy(
      v2.id,
      v2.name,
      v2.conditions || v2.document?.conditions || {},
      v2.effect || v2.document?.effect || "deny",
      v2.description,
      v2.tenantId,
    );

    const differences: {
      field: string;
      oldValue: unknown;
      newValue: unknown;
    }[] = [];

    if (v1.name !== v2.name) {
      differences.push({ field: "name", oldValue: v1.name, newValue: v2.name });
    }
    if (JSON.stringify(v1.document) !== JSON.stringify(v2.document)) {
      differences.push({
        field: "document",
        oldValue: v1.document,
        newValue: v2.document,
      });
    }

    return { version1: v1Policy, version2: v2Policy, differences };
  }

  async addTags(
    id: string,
    tags: Record<string, string>,
    tenantId: string,
  ): Promise<DomainPolicy> {
    const policy = await this.prisma.policy.findFirst({
      where: { id, tenantId },
    });

    if (!policy) throw new Error("Policy not found");

    const currentTags = (policy.tags as Record<string, string>) || {};
    const updated = await this.prisma.policy.update({
      where: { id },
      data: {
        tags: { ...currentTags, ...tags },
      } as any,
    });
    return this.mapToDomain(updated);
  }

  async removeTags(
    id: string,
    tagKeys: string[],
    tenantId: string,
  ): Promise<DomainPolicy> {
    const policy = await this.prisma.policy.findFirst({
      where: { id, tenantId },
    });

    if (!policy) throw new Error("Policy not found");

    const currentTags = (policy.tags as Record<string, string>) || {};
    tagKeys.forEach((key) => delete currentTags[key]);

    const updated = await this.prisma.policy.update({
      where: { id },
      data: {
        tags: currentTags,
      } as any,
    });
    return this.mapToDomain(updated);
  }

  async search(
    tenantId: string,
    query: string,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }> {
    const where: any = {
      tenantId,
      OR: [{ name: { contains: query } }, { description: { contains: query } }],
    };

    const [policiesData, total] = await Promise.all([
      this.prisma.policy.findMany({
        where,
        orderBy: { createdAt: "desc" },
        skip: options?.page ? (options.page - 1) * (options.limit || 10) : 0,
        take: options?.limit || 10,
      }),
      this.prisma.policy.count({ where }),
    ]);

    return {
      policies: policiesData.map(this.mapToDomain),
      total,
    };
  }

  async getStatistics(tenantId: string): Promise<{
    total: number;
    active: number;
    draft: number;
    inactive: number;
    deleted: number;
    recentChanges: number;
  }> {
    const [total, active, draft, inactive, deleted] = await Promise.all([
      this.prisma.policy.count({ where: { tenantId } }),
      this.prisma.policy.count({ where: { tenantId, status: "ACTIVE" } }),
      this.prisma.policy.count({ where: { tenantId, status: "DRAFT" } }),
      this.prisma.policy.count({ where: { tenantId, status: "INACTIVE" } }),
      this.prisma.policy.count({
        where: { tenantId, deletedAt: { not: null } },
      }),
    ]);

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);
    const recentChanges = await this.prisma.policy.count({
      where: {
        tenantId,
        updatedAt: { gte: thirtyDaysAgo },
      },
    });

    return { total, active, draft, inactive, deleted, recentChanges };
  }

  private mapToDomain(policyData: any): DomainPolicy {
    const document = (policyData.document as Record<string, unknown>) || {};
    return new DomainPolicy(
      policyData.id,
      policyData.name,
      (document.conditions || {}) as Record<string, unknown>,
      (document.effect as "allow" | "deny") || "deny",
      policyData.description || "",
      policyData.tenantId,
    );
  }
}
