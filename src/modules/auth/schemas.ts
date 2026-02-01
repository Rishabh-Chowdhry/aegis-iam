import { z } from "zod";

export const loginSchema = z.object({
  body: z.object({
    email: z.string().email(),
    password: z.string().min(8),
    tenantId: z.string(),
  }),
});

export const logoutSchema = z.object({
  body: z.object({
    refreshToken: z.string(),
    tenantId: z.string(),
  }),
});

export const refreshTokenSchema = z.object({
  body: z.object({
    refreshToken: z.string(),
    tenantId: z.string(),
  }),
});

export type LoginInput = z.infer<typeof loginSchema>["body"];
export type LogoutInput = z.infer<typeof logoutSchema>["body"];
export type RefreshTokenInput = z.infer<typeof refreshTokenSchema>["body"];
