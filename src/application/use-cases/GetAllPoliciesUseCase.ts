import { Policy } from "../../domain/entities/Policy";
import { IPolicyRepository } from "../../infrastructure/repositories/IPolicyRepository";

export interface GetAllPoliciesRequest {
  tenantId: string;
}

export interface GetAllPoliciesResponse {
  policies: Policy[];
}

export class GetAllPoliciesUseCase {
  constructor(private policyRepository: IPolicyRepository) {}

  async execute(
    request: GetAllPoliciesRequest,
  ): Promise<GetAllPoliciesResponse> {
    const { tenantId } = request;

    const result = await this.policyRepository.findAll(tenantId);

    return { policies: result.policies };
  }
}
