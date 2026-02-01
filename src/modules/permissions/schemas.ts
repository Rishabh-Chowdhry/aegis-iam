import { z } from "zod";

export const CreatePermissionSchema = z.object({
  id: z.string().min(1).max(100),
  resource: z.string().min(1).max(100),
  action: z.string().min(1).max(100),
  description: z.string().min(1).max(500),
  tenantId: z.string(),
});

export const UpdatePermissionSchema = z.object({
  resource: z.string().min(1).max(100).optional(),
  action: z.string().min(1).max(100).optional(),
  description: z.string().min(1).max(500).optional(),
});

export const GetPermissionSchema = z.object({
  tenantId: z.string(),
});

export type CreatePermissionDto = z.infer<typeof CreatePermissionSchema>;
export type UpdatePermissionDto = z.infer<typeof UpdatePermissionSchema>;
export type GetPermissionDto = z.infer<typeof GetPermissionSchema>;
