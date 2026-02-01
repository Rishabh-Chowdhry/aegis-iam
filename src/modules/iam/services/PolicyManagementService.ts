/**
 * Policy Management Service
 *
 * Handles policy CRUD operations with versioning support.
 */

import { ABACPolicy, PolicyStatement } from "../policy/models/types";
import { parsePolicy } from "../policy/parser/PolicyParser";

/**
 * Policy version info
 */
export interface PolicyVersionInfo {
  /** Version number */
  version: number;

  /** Whether this is the active version */
  isActive: boolean;

  /** Created at */
  createdAt: string;

  /** Created by */
  createdBy: string;

  /** Change description */
  changeDescription?: string;
}

/**
 * Policy create request
 */
export interface CreatePolicyRequest {
  /** Tenant ID */
  tenantId: string;

  /** Policy name */
  name: string;

  /** Policy document (JSON) */
  document: string;

  /** Description */
  description?: string;

  /** Created by */
  createdBy: string;
}

/**
 * Policy update request
 */
export interface UpdatePolicyRequest {
  /** Policy document (JSON) */
  document: string;

  /** Description */
  description?: string;

  /** Updated by */
  updatedBy: string;

  /** Change description */
  changeDescription?: string;
}

/**
 * Policy list options
 */
export interface ListPoliciesOptions {
  /** Tenant ID */
  tenantId: string;

  /** Filter by status */
  status?: "ACTIVE" | "DEPRECATED" | "DISABLED" | "DRAFT";

  /** Filter by tag */
  tag?: { key: string; value: string };

  /** Pagination */
  limit?: number;

  /** Pagination */
  offset?: number;
}

/**
 * Policy list result
 */
export interface ListPoliciesResult {
  /** Policies */
  policies: ABACPolicy[];

  /** Total count */
  total: number;
}

/**
 * Policy Management Service Interface
 */
export interface IPolicyManagementService {
  /**
   * Create a new policy
   */
  create(request: CreatePolicyRequest): Promise<ABACPolicy>;

  /**
   * Get a policy by ID
   */
  getById(policyId: string, tenantId: string): Promise<ABACPolicy | null>;

  /**
   * Get a policy by name
   */
  getByName(name: string, tenantId: string): Promise<ABACPolicy | null>;

  /**
   * Update a policy (creates new version)
   */
  update(
    policyId: string,
    request: UpdatePolicyRequest,
    tenantId: string,
  ): Promise<ABACPolicy>;

  /**
   * Delete a policy
   */
  delete(policyId: string, tenantId: string): Promise<void>;

  /**
   * Enable a policy
   */
  enable(policyId: string, tenantId: string): Promise<void>;

  /**
   * Disable a policy
   */
  disable(policyId: string, tenantId: string): Promise<void>;

  /**
   * Deprecate a policy
   */
  deprecate(
    policyId: string,
    tenantId: string,
    replacementPolicyId?: string,
  ): Promise<void>;

  /**
   * List policies
   */
  list(options: ListPoliciesOptions): Promise<ListPoliciesResult>;

  /**
   * Get policy version history
   */
  getVersionHistory(
    policyId: string,
    tenantId: string,
  ): Promise<PolicyVersionInfo[]>;

  /**
   * Validate a policy document
   */
  validate(document: string): Promise<{ valid: boolean; errors: string[] }>;
}

/**
 * Policy Management Service Implementation
 */
export class PolicyManagementService implements IPolicyManagementService {
  constructor(
    private policyRepository: IPolicyRepository,
    private policyVersionRepository: IPolicyVersionRepository,
    private policyCache: IPolicyCache,
  ) {}

  /**
   * Create a new policy
   */
  async create(request: CreatePolicyRequest): Promise<ABACPolicy> {
    // Parse and validate the policy document
    const policy = parsePolicy(JSON.parse(request.document));

    // Set tenant ID and metadata
    policy.tenantId = request.tenantId;
    policy.name = request.name;
    policy.status = "ACTIVE";
    policy.metadata = {
      ...policy.metadata,
      description: request.description,
      createdBy: request.createdBy,
      createdAt: new Date().toISOString(),
      version: 1,
    };

    // Create the policy
    await this.policyRepository.create(policy);

    // Create initial version record
    await this.policyVersionRepository.create({
      policyId: policy.id,
      tenantId: request.tenantId,
      version: 1,
      content: policy as unknown as Record<string, unknown>,
      createdBy: request.createdBy,
      changeDescription: "Initial version",
    });

    // Invalidate cache
    await this.policyCache.invalidate(request.tenantId);

    return policy;
  }

  /**
   * Get a policy by ID
   */
  async getById(
    policyId: string,
    tenantId: string,
  ): Promise<ABACPolicy | null> {
    return this.policyRepository.findById(policyId, tenantId);
  }

  /**
   * Get a policy by name
   */
  async getByName(name: string, tenantId: string): Promise<ABACPolicy | null> {
    return this.policyRepository.findByName(name, tenantId);
  }

  /**
   * Update a policy (creates new version)
   */
  async update(
    policyId: string,
    request: UpdatePolicyRequest,
    tenantId: string,
  ): Promise<ABACPolicy> {
    // Get existing policy
    const existingPolicy = await this.policyRepository.findById(
      policyId,
      tenantId,
    );
    if (!existingPolicy) {
      throw new Error("Policy not found");
    }

    // Parse new policy document
    const updatedPolicy = parsePolicy(JSON.parse(request.document));

    // Create new version
    const newVersion = (existingPolicy.metadata?.version ?? 1) + 1;

    // Update policy fields
    updatedPolicy.id = policyId;
    updatedPolicy.tenantId = tenantId;
    updatedPolicy.name = existingPolicy.name;
    updatedPolicy.status = existingPolicy.status;
    updatedPolicy.metadata = {
      ...existingPolicy.metadata,
      description: request.description ?? existingPolicy.metadata?.description,
      updatedBy: request.updatedBy,
      updatedAt: new Date().toISOString(),
      version: newVersion,
    };

    // Update the policy
    await this.policyRepository.update(policyId, updatedPolicy);

    // Create version record
    await this.policyVersionRepository.create({
      policyId,
      tenantId,
      version: newVersion,
      content: updatedPolicy as unknown as Record<string, unknown>,
      createdBy: request.updatedBy,
      changeDescription: request.changeDescription ?? `Version ${newVersion}`,
    });

    // Invalidate cache
    await this.policyCache.invalidate(tenantId);

    return updatedPolicy;
  }

  /**
   * Delete a policy
   */
  async delete(policyId: string, tenantId: string): Promise<void> {
    await this.policyRepository.delete(policyId, tenantId);
    await this.policyCache.invalidate(tenantId);
  }

  /**
   * Enable a policy
   */
  async enable(policyId: string, tenantId: string): Promise<void> {
    await this.policyRepository.updateStatus(policyId, tenantId, "ACTIVE");
    await this.policyCache.invalidate(tenantId);
  }

  /**
   * Disable a policy
   */
  async disable(policyId: string, tenantId: string): Promise<void> {
    await this.policyRepository.updateStatus(policyId, tenantId, "DISABLED");
    await this.policyCache.invalidate(tenantId);
  }

  /**
   * Deprecate a policy
   */
  async deprecate(
    policyId: string,
    tenantId: string,
    replacementPolicyId?: string,
  ): Promise<void> {
    await this.policyRepository.updateStatus(policyId, tenantId, "DEPRECATED");
    await this.policyCache.invalidate(tenantId);
  }

  /**
   * List policies
   */
  async list(options: ListPoliciesOptions): Promise<ListPoliciesResult> {
    return this.policyRepository.list(options);
  }

  /**
   * Get policy version history
   */
  async getVersionHistory(
    policyId: string,
    tenantId: string,
  ): Promise<PolicyVersionInfo[]> {
    const versions = await this.policyVersionRepository.findByPolicyId(
      policyId,
      tenantId,
    );
    return versions.map((v) => ({
      version: v.version,
      isActive: true, // All versions are considered active for history
      createdAt: v.createdAt,
      createdBy: v.createdBy,
      changeDescription: v.changeDescription,
    }));
  }

  /**
   * Validate a policy document
   */
  async validate(
    document: string,
  ): Promise<{ valid: boolean; errors: string[] }> {
    try {
      const policy = JSON.parse(document);
      parsePolicy(policy);
      return { valid: true, errors: [] };
    } catch (error) {
      return {
        valid: false,
        errors: [error instanceof Error ? error.message : "Invalid JSON"],
      };
    }
  }
}

// Repository interfaces
interface IPolicyRepository {
  create(policy: ABACPolicy): Promise<void>;
  findById(id: string, tenantId: string): Promise<ABACPolicy | null>;
  findByName(name: string, tenantId: string): Promise<ABACPolicy | null>;
  update(id: string, policy: ABACPolicy): Promise<void>;
  updateStatus(id: string, tenantId: string, status: string): Promise<void>;
  delete(id: string, tenantId: string): Promise<void>;
  list(options: ListPoliciesOptions): Promise<ListPoliciesResult>;
}

interface IPolicyVersionRepository {
  create(data: {
    policyId: string;
    tenantId: string;
    version: number;
    content: Record<string, unknown>;
    createdBy: string;
    changeDescription: string;
  }): Promise<void>;
  findByPolicyId(
    policyId: string,
    tenantId: string,
  ): Promise<
    {
      version: number;
      createdAt: string;
      createdBy: string;
      changeDescription: string;
    }[]
  >;
}

interface IPolicyCache {
  invalidate(tenantId: string): Promise<void>;
}
