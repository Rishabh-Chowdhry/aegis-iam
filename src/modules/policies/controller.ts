import { Request, Response } from "express";
import { CreatePolicyUseCase } from "../../application/use-cases/CreatePolicyUseCase";
import { UpdatePolicyUseCase } from "../../application/use-cases/UpdatePolicyUseCase";
import { DeletePolicyUseCase } from "../../application/use-cases/DeletePolicyUseCase";
import { GetAllPoliciesUseCase } from "../../application/use-cases/GetAllPoliciesUseCase";
import {
  CreatePolicyInput,
  UpdatePolicyInput,
  DeletePolicyInput,
  GetAllPoliciesInput,
} from "./schemas";
import { StatusMapping } from "../../shared/errors/StatusMapping";
import { ResponseStatus } from "../../shared/errors/ResponseStatus";

export class PoliciesController {
  constructor(
    private createPolicyUseCase: CreatePolicyUseCase,
    private updatePolicyUseCase: UpdatePolicyUseCase,
    private deletePolicyUseCase: DeletePolicyUseCase,
    private getAllPoliciesUseCase: GetAllPoliciesUseCase,
  ) {}

  async createPolicy(req: Request<{}, {}, CreatePolicyInput>, res: Response) {
    try {
      const { name, conditions, effect, description, tenantId } = req.body;
      const performedBy = (req as any).user?.userId;

      const result = await this.createPolicyUseCase.execute({
        name,
        conditions,
        effect,
        description: description || "",
        tenantId,
        performedBy,
      });

      res.status(ResponseStatus.CREATED).json(
        StatusMapping.createResponse(ResponseStatus.CREATED, {
          policy: {
            id: result.policy.id,
            name: result.policy.name,
            conditions: result.policy.conditions,
            effect: result.policy.effect,
            description: result.policy.description,
          },
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Failed to create policy",
          ),
        );
    }
  }

  async updatePolicy(
    req: Request<{ id: string }, {}, UpdatePolicyInput>,
    res: Response,
  ) {
    try {
      const { id } = req.params;
      const { name, conditions, effect, description, tenantId } = req.body;
      const performedBy = (req as any).user?.userId;

      const result = await this.updatePolicyUseCase.execute({
        id,
        name,
        conditions,
        effect,
        description,
        tenantId,
        performedBy,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          policy: {
            id: result.policy.id,
            name: result.policy.name,
            conditions: result.policy.conditions,
            effect: result.policy.effect,
            description: result.policy.description,
          },
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Failed to update policy",
          ),
        );
    }
  }

  async deletePolicy(
    req: Request<{ id: string }, {}, DeletePolicyInput>,
    res: Response,
  ) {
    try {
      const { id } = req.params;
      const { tenantId } = req.body;
      const performedBy = (req as any).user?.userId;

      await this.deletePolicyUseCase.execute({
        id,
        tenantId,
        performedBy,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          message: "Policy deleted successfully",
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Failed to delete policy",
          ),
        );
    }
  }

  async getAllPolicies(
    req: Request<{}, {}, {}, GetAllPoliciesInput>,
    res: Response,
  ) {
    try {
      const { tenantId } = req.query;

      const result = await this.getAllPoliciesUseCase.execute({
        tenantId,
      });

      res.status(ResponseStatus.OK).json(
        StatusMapping.createResponse(ResponseStatus.OK, {
          policies: result.policies.map((policy) => ({
            id: policy.id,
            name: policy.name,
            conditions: policy.conditions,
            effect: policy.effect,
            description: policy.description,
          })),
        }),
      );
    } catch (error) {
      res
        .status(ResponseStatus.BAD_REQUEST)
        .json(
          StatusMapping.createErrorResponse(
            ResponseStatus.BAD_REQUEST,
            error instanceof Error ? error.message : "Failed to get policies",
          ),
        );
    }
  }
}
