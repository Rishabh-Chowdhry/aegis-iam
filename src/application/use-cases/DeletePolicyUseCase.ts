import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IPolicyRepository } from "../../infrastructure/repositories/IPolicyRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface DeletePolicyRequest {
  id: string;
  tenantId: string;
  performedBy: string;
}

export interface DeletePolicyResponse {
  success: boolean;
}

export class DeletePolicyUseCase {
  constructor(
    private policyRepository: IPolicyRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: DeletePolicyRequest): Promise<DeletePolicyResponse> {
    const { id, tenantId, performedBy } = request;

    const policy = await this.policyRepository.findById(id, tenantId);
    if (!policy) {
      throw new Error("Policy not found");
    }

    await this.policyRepository.delete(id, tenantId);

    // Log deletion
    await this.auditLogRepository.save(
      new AuditLogEntry(
        performedBy,
        "delete_policy",
        new Date(),
        {
          policyId: id,
          name: policy.name,
        },
        request.tenantId,
      ),
    );

    return { success: true };
  }
}
