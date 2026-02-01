import { z } from "zod";

export const createPolicySchema = z.object({
  body: z.object({
    name: z.string().min(1),
    conditions: z.record(z.any()),
    effect: z.enum(["allow", "deny"]),
    description: z.string().optional(),
    tenantId: z.string(),
  }),
});

export const updatePolicySchema = z.object({
  params: z.object({
    id: z.string(),
  }),
  body: z.object({
    name: z.string().min(1).optional(),
    conditions: z.record(z.any()).optional(),
    effect: z.enum(["allow", "deny"]).optional(),
    description: z.string().optional(),
    tenantId: z.string(),
  }),
});

export const deletePolicySchema = z.object({
  params: z.object({
    id: z.string(),
  }),
  body: z.object({
    tenantId: z.string(),
  }),
});

export const getAllPoliciesSchema = z.object({
  query: z.object({
    tenantId: z.string(),
  }),
});

export type CreatePolicyInput = z.infer<typeof createPolicySchema>["body"];
export type UpdatePolicyInput = z.infer<typeof updatePolicySchema>["body"] & {
  id: string;
};
export type DeletePolicyInput = z.infer<typeof deletePolicySchema>["body"] & {
  id: string;
};
export type GetAllPoliciesInput = z.infer<typeof getAllPoliciesSchema>["query"];
