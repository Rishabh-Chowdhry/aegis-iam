import { Policy } from "../../domain/entities/Policy";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import {
  IPolicyRepository,
  UpdatePolicyInput,
} from "../../infrastructure/repositories/IPolicyRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface UpdatePolicyRequest {
  id: string;
  name?: string;
  conditions?: Record<string, any>;
  effect?: "allow" | "deny";
  description?: string;
  tenantId: string;
  performedBy: string;
}

export interface UpdatePolicyResponse {
  policy: Policy;
}

export class UpdatePolicyUseCase {
  constructor(
    private policyRepository: IPolicyRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: UpdatePolicyRequest): Promise<UpdatePolicyResponse> {
    const { id, name, conditions, effect, description, tenantId, performedBy } =
      request;

    const policy = await this.policyRepository.findById(id, tenantId);
    if (!policy) {
      throw new Error("Policy not found");
    }

    // Build update input
    const updateData: UpdatePolicyInput = {};
    if (name !== undefined) {
      updateData.name = name;
      policy.updateName(name);
    }
    if (conditions !== undefined) {
      updateData.document = conditions;
      policy.updateConditions(conditions);
    }
    if (description !== undefined) {
      updateData.description = description;
      policy.updateDescription(description);
    }

    // Update using repository
    await this.policyRepository.update(id, updateData);

    // Log update
    await this.auditLogRepository.save(
      new AuditLogEntry(
        performedBy,
        "update_policy",
        new Date(),
        {
          policyId: id,
          name,
          effect,
        },
        request.tenantId,
      ),
    );

    // Return updated policy
    const updatedPolicy = await this.policyRepository.findById(id, tenantId);
    return { policy: updatedPolicy! };
  }
}
