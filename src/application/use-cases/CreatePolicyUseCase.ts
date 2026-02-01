import { Policy } from "../../domain/entities/Policy";
import { AuditLogEntry } from "../../domain/value-objects/AuditLogEntry";
import { IPolicyRepository } from "../../infrastructure/repositories/IPolicyRepository";
import { IAuditLogRepository } from "../../infrastructure/repositories/IAuditLogRepository";

export interface CreatePolicyRequest {
  name: string;
  conditions: Record<string, any>;
  effect: "allow" | "deny";
  description: string;
  tenantId: string;
  performedBy: string;
}

export interface CreatePolicyResponse {
  policy: Policy;
}

export class CreatePolicyUseCase {
  constructor(
    private policyRepository: IPolicyRepository,
    private auditLogRepository: IAuditLogRepository,
  ) {}

  async execute(request: CreatePolicyRequest): Promise<CreatePolicyResponse> {
    const { name, conditions, effect, description, tenantId, performedBy } =
      request;

    // Check if policy already exists
    const existingPolicy = await this.policyRepository.findByName(
      name,
      tenantId,
    );
    if (existingPolicy) {
      throw new Error("Policy with this name already exists");
    }

    // Generate unique ID
    const policyId = `policy-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    const policy = new Policy(
      policyId,
      name,
      conditions,
      effect,
      description,
      tenantId,
    );

    await this.policyRepository.save(policy);

    // Log creation
    await this.auditLogRepository.save(
      new AuditLogEntry(
        performedBy,
        "create_policy",
        new Date(),
        {
          policyId,
          name,
          effect,
        },
        request.tenantId,
      ),
    );

    return { policy };
  }
}
