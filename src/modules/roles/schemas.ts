import { z } from "zod";

export const CreateRoleSchema = z.object({
  name: z.string().min(1).max(100),
  description: z.string().min(1).max(500),
  parentRoleId: z.string().optional(),
  permissions: z.array(z.string()).optional(),
  tenantId: z.string(),
});

export const UpdateRoleSchema = z.object({
  name: z.string().min(1).max(100).optional(),
  description: z.string().min(1).max(500).optional(),
  parentRoleId: z.string().nullable().optional(),
  permissions: z.array(z.string()).optional(),
});

export const AssignPermissionSchema = z.object({
  permissionId: z.string(),
});

export const RemovePermissionSchema = z.object({
  permissionId: z.string(),
});

export const GetRoleHierarchySchema = z.object({
  tenantId: z.string(),
});

export type CreateRoleDto = z.infer<typeof CreateRoleSchema>;
export type UpdateRoleDto = z.infer<typeof UpdateRoleSchema>;
export type AssignPermissionDto = z.infer<typeof AssignPermissionSchema>;
export type RemovePermissionDto = z.infer<typeof RemovePermissionSchema>;
export type GetRoleHierarchyDto = z.infer<typeof GetRoleHierarchySchema>;
