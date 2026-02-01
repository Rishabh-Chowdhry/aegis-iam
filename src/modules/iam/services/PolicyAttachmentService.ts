/**
 * Policy Attachment Service
 *
 * Handles attaching policies to subjects (users, roles, services).
 */

import { ABACPolicy } from "../policy/models/types";

/**
 * Policy attachment request
 */
export interface AttachPolicyRequest {
  /** Policy ID */
  policyId: string;

  /** Subject type */
  subjectType: "User" | "Role" | "Service";

  /** Subject ID */
  subjectId: string;

  /** Tenant ID */
  tenantId: string;

  /** Attached by */
  attachedBy: string;
}

/**
 * Policy attachment
 */
export interface PolicyAttachment {
  /** Attachment ID */
  id: string;

  /** Policy ID */
  policyId: string;

  /** Subject type */
  subjectType: "User" | "Role" | "Service";

  /** Subject ID */
  subjectId: string;

  /** Tenant ID */
  tenantId: string;

  /** Attached at */
  attachedAt: string;

  /** Attached by */
  attachedBy: string;
}

/**
 * Detach policy request
 */
export interface DetachPolicyRequest {
  /** Policy ID */
  policyId: string;

  /** Subject type */
  subjectType: "User" | "Role" | "Service";

  /** Subject ID */
  subjectId: string;

  /** Tenant ID */
  tenantId: string;
}

/**
 * Policy Attachment Service Interface
 */
export interface IPolicyAttachmentService {
  /**
   * Attach a policy to a subject
   */
  attach(request: AttachPolicyRequest): Promise<PolicyAttachment>;

  /**
   * Detach a policy from a subject
   */
  detach(request: DetachPolicyRequest): Promise<void>;

  /**
   * Get all attachments for a policy
   */
  getAttachmentsForPolicy(
    policyId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]>;

  /**
   * Get all attachments for a subject
   */
  getAttachmentsForSubject(
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]>;

  /**
   * Get all effective policies for a subject
   */
  getEffectivePolicies(
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<ABACPolicy[]>;

  /**
   * Check if a policy is attached to a subject
   */
  isAttached(
    policyId: string,
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<boolean>;

  /**
   * Bulk attach policies to a subject
   */
  bulkAttach(
    subjectType: string,
    subjectId: string,
    policyIds: string[],
    tenantId: string,
    attachedBy: string,
  ): Promise<void>;

  /**
   * Bulk detach policies from a subject
   */
  bulkDetach(
    subjectType: string,
    subjectId: string,
    policyIds: string[],
    tenantId: string,
  ): Promise<void>;
}

/**
 * Policy Attachment Service Implementation
 */
export class PolicyAttachmentService implements IPolicyAttachmentService {
  constructor(
    private attachmentRepository: IPolicyAttachmentRepository,
    private policyRepository: IPolicyRepository,
    private policyCache: IPolicyCache,
  ) {}

  /**
   * Attach a policy to a subject
   */
  async attach(request: AttachPolicyRequest): Promise<PolicyAttachment> {
    // Verify policy exists and belongs to tenant
    const policy = await this.policyRepository.findById(
      request.policyId,
      request.tenantId,
    );
    if (!policy) {
      throw new Error("Policy not found");
    }

    // Check if already attached
    const existing = await this.attachmentRepository.findOne(
      request.policyId,
      request.subjectType,
      request.subjectId,
      request.tenantId,
    );

    if (existing) {
      throw new Error("Policy is already attached to this subject");
    }

    // Create attachment
    const attachment = await this.attachmentRepository.create({
      policyId: request.policyId,
      subjectType: request.subjectType,
      subjectId: request.subjectId,
      tenantId: request.tenantId,
      attachedBy: request.attachedBy,
      attachedAt: new Date().toISOString(),
    });

    // Invalidate cache
    await this.policyCache.invalidate(request.tenantId);

    return attachment;
  }

  /**
   * Detach a policy from a subject
   */
  async detach(request: DetachPolicyRequest): Promise<void> {
    await this.attachmentRepository.delete(
      request.policyId,
      request.subjectType,
      request.subjectId,
      request.tenantId,
    );

    // Invalidate cache
    await this.policyCache.invalidate(request.tenantId);
  }

  /**
   * Get all attachments for a policy
   */
  async getAttachmentsForPolicy(
    policyId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]> {
    return this.attachmentRepository.findByPolicyId(policyId, tenantId);
  }

  /**
   * Get all attachments for a subject
   */
  async getAttachmentsForSubject(
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]> {
    return this.attachmentRepository.findBySubject(
      subjectType,
      subjectId,
      tenantId,
    );
  }

  /**
   * Get all effective policies for a subject
   */
  async getEffectivePolicies(
    subjectType: "User" | "Role" | "Service",
    subjectId: string,
    tenantId: string,
  ): Promise<ABACPolicy[]> {
    // Get all attachments for the subject
    const attachments = await this.attachmentRepository.findBySubject(
      subjectType,
      subjectId,
      tenantId,
    );

    // Get all policies
    const policies: ABACPolicy[] = [];
    for (const attachment of attachments) {
      const policy = await this.policyRepository.findById(
        attachment.policyId,
        tenantId,
      );
      if (policy && policy.status === "ACTIVE") {
        policies.push(policy);
      }
    }

    return policies;
  }

  /**
   * Check if a policy is attached to a subject
   */
  async isAttached(
    policyId: string,
    subjectType: "User" | "Role" | "Service",
    subjectId: string,
    tenantId: string,
  ): Promise<boolean> {
    const attachment = await this.attachmentRepository.findOne(
      policyId,
      subjectType,
      subjectId,
      tenantId,
    );
    return attachment !== null;
  }

  /**
   * Bulk attach policies to a subject
   */
  async bulkAttach(
    subjectType: "User" | "Role" | "Service",
    subjectId: string,
    policyIds: string[],
    tenantId: string,
    attachedBy: string,
  ): Promise<void> {
    for (const policyId of policyIds) {
      try {
        await this.attach({
          policyId,
          subjectType,
          subjectId,
          tenantId,
          attachedBy,
        });
      } catch (error) {
        // Skip already attached policies
        if (
          !(
            error instanceof Error && error.message.includes("already attached")
          )
        ) {
          throw error;
        }
      }
    }
  }

  /**
   * Bulk detach policies from a subject
   */
  async bulkDetach(
    subjectType: "User" | "Role" | "Service",
    subjectId: string,
    policyIds: string[],
    tenantId: string,
  ): Promise<void> {
    for (const policyId of policyIds) {
      try {
        await this.detach({
          policyId,
          subjectType,
          subjectId,
          tenantId,
        });
      } catch {
        // Ignore errors for already detached policies
      }
    }
  }
}

// Repository interfaces
interface IPolicyAttachmentRepository {
  create(data: {
    policyId: string;
    subjectType: string;
    subjectId: string;
    tenantId: string;
    attachedBy: string;
    attachedAt: string;
  }): Promise<PolicyAttachment>;
  findOne(
    policyId: string,
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<PolicyAttachment | null>;
  findByPolicyId(
    policyId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]>;
  findBySubject(
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<PolicyAttachment[]>;
  delete(
    policyId: string,
    subjectType: string,
    subjectId: string,
    tenantId: string,
  ): Promise<void>;
}

interface IPolicyRepository {
  findById(id: string, tenantId: string): Promise<ABACPolicy | null>;
}

interface IPolicyCache {
  invalidate(tenantId: string): Promise<void>;
}
