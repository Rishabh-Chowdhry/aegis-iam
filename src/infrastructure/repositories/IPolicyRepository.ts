import { Policy as DomainPolicy } from "../../domain/entities/Policy";

// Define PolicyStatus locally (same as in schema)
export enum PolicyStatus {
  DRAFT = "DRAFT",
  ACTIVE = "ACTIVE",
  INACTIVE = "INACTIVE",
}

// Pagination and filtering options
export interface ListOptions {
  page?: number;
  limit?: number;
  sortBy?: string;
  sortOrder?: "asc" | "desc";
  status?: PolicyStatus;
  includeDeleted?: boolean;
}

// Filter criteria
export interface PolicyFilter {
  tenantId: string;
  status?: PolicyStatus;
  name?: string;
  tags?: Record<string, string>;
  createdBy?: string;
  startDate?: Date;
  endDate?: Date;
}

// Create policy input (new format with document)
export interface CreatePolicyInput {
  tenantId: string;
  name: string;
  description?: string;
  document: Record<string, unknown>;
  version?: string;
  tags?: Record<string, string>;
  createdBy: string;
  status?: PolicyStatus;
}

// Create policy input (legacy format with conditions and effect)
export interface CreatePolicyLegacyInput {
  tenantId: string;
  name: string;
  conditions: Record<string, unknown>;
  effect: "allow" | "deny";
  description?: string;
  createdBy: string;
}

// Update policy input
export interface UpdatePolicyInput {
  name?: string;
  description?: string;
  document?: Record<string, unknown>;
  tags?: Record<string, string>;
  status?: PolicyStatus;
}

// Create version input
export interface CreateVersionInput {
  name?: string;
  description?: string;
  document: Record<string, unknown>;
  tags?: Record<string, string>;
  createdBy: string;
}

export interface IPolicyRepository {
  // Backward compatibility - accepts legacy domain Policy
  save(policy: DomainPolicy): Promise<DomainPolicy>;

  // CRUD operations
  create(
    data: CreatePolicyInput | CreatePolicyLegacyInput,
  ): Promise<DomainPolicy>;
  update(id: string, data: UpdatePolicyInput): Promise<DomainPolicy>;
  delete(id: string, tenantId: string): Promise<void>;

  // Soft delete operations
  softDelete(
    id: string,
    deletedBy: string,
    tenantId: string,
  ): Promise<DomainPolicy>;
  restore(id: string, tenantId: string): Promise<DomainPolicy>;

  // Read operations
  findById(id: string, tenantId: string): Promise<DomainPolicy | null>;
  findByName(name: string, tenantId: string): Promise<DomainPolicy | null>;

  // List operations
  findAll(
    tenantId: string,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }>;
  findByStatus(
    tenantId: string,
    status: PolicyStatus,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }>;

  // Active policies (for enforcement)
  findActiveByTenant(tenantId: string): Promise<DomainPolicy[]>;

  // Versioning operations
  getVersionHistory(policyId: string): Promise<DomainPolicy[]>;
  createVersion(
    id: string,
    data: CreateVersionInput,
    tenantId: string,
  ): Promise<DomainPolicy>;
  getVersion(id: string, versionNumber: number): Promise<DomainPolicy | null>;
  rollbackToVersion(
    policyId: string,
    versionNumber: number,
    rolledBackBy: string,
    tenantId: string,
  ): Promise<DomainPolicy>;

  // Comparison operations
  compareVersions(
    policyId: string,
    version1: number,
    version2: number,
  ): Promise<{
    version1: DomainPolicy;
    version2: DomainPolicy;
    differences: {
      field: string;
      oldValue: unknown;
      newValue: unknown;
    }[];
  }>;

  // Tag operations
  addTags(
    id: string,
    tags: Record<string, string>,
    tenantId: string,
  ): Promise<DomainPolicy>;
  removeTags(
    id: string,
    tagKeys: string[],
    tenantId: string,
  ): Promise<DomainPolicy>;

  // Search operations
  search(
    tenantId: string,
    query: string,
    options?: ListOptions,
  ): Promise<{ policies: DomainPolicy[]; total: number }>;

  // Statistics
  getStatistics(tenantId: string): Promise<{
    total: number;
    active: number;
    draft: number;
    inactive: number;
    deleted: number;
    recentChanges: number;
  }>;
}
