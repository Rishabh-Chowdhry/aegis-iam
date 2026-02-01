import { z } from "zod";

export const CreateUserSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  roles: z.array(z.string()).optional(),
  tenantId: z.string(),
});

export const UpdateUserSchema = z.object({
  email: z.string().email().optional(),
  roles: z.array(z.string()).optional(),
  status: z.enum(["active", "inactive", "suspended"]).optional(),
});

export const AssignRoleSchema = z.object({
  roleId: z.string(),
});

export const RemoveRoleSchema = z.object({
  roleId: z.string(),
});

export const ChangeStatusSchema = z.object({
  status: z.enum(["active", "inactive", "suspended"]),
});

export type CreateUserDto = z.infer<typeof CreateUserSchema>;
export type UpdateUserDto = z.infer<typeof UpdateUserSchema>;
export type AssignRoleDto = z.infer<typeof AssignRoleSchema>;
export type RemoveRoleDto = z.infer<typeof RemoveRoleSchema>;
export type ChangeStatusDto = z.infer<typeof ChangeStatusSchema>;
