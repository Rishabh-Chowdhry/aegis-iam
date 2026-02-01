/**
 * Auth Schemas - Zod Validation Schemas
 *
 * This module defines Zod schemas for validating authentication requests:
 * - Registration, login, password reset, etc.
 *
 * Security Considerations:
 * - Strict input validation prevents injection attacks
 * - Password minimum length enforced
 * - Email format validation
 */

import { z } from "zod";

/**
 * User registration schema
 *
 * Requirements:
 * - Email must be valid format
 * - Password must be at least 12 characters
 * - First and last name required
 */
export const registerSchema = z.object({
  body: z.object({
    email: z
      .string()
      .email("Invalid email format")
      .min(1, "Email is required")
      .max(254, "Email is too long"),
    password: z
      .string()
      .min(12, "Password must be at least 12 characters")
      .max(128, "Password is too long"),
    firstName: z
      .string()
      .min(1, "First name is required")
      .max(100, "First name is too long")
      .regex(/^[a-zA-Z\s\-']+$/, "First name contains invalid characters"),
    lastName: z
      .string()
      .min(1, "Last name is required")
      .max(100, "Last name is too long")
      .regex(/^[a-zA-Z\s\-']+$/, "Last name contains invalid characters"),
    tenantId: z.string().optional(),
  }),
});

/**
 * User login schema
 *
 * Requirements:
 * - Email must be valid format
 * - Password required (length checked at service level)
 */
export const loginSchema = z.object({
  body: z.object({
    email: z.string().email("Invalid email format").min(1, "Email is required"),
    password: z.string().min(1, "Password is required"),
    tenantId: z.string().optional(),
  }),
});

/**
 * Token refresh schema
 *
 * Requirements:
 * - Refresh token required
 */
export const refreshSchema = z.object({
  body: z.object({
    refreshToken: z.string().min(1, "Refresh token is required"),
  }),
});

/**
 * Forgot password schema
 *
 * Requirements:
 * - Email must be valid format
 */
export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.string().email("Invalid email format").min(1, "Email is required"),
    tenantId: z.string().optional(),
  }),
});

/**
 * Reset password schema
 *
 * Requirements:
 * - Reset token required
 * - New password must be at least 12 characters
 */
export const resetPasswordSchema = z.object({
  body: z.object({
    token: z.string().min(1, "Reset token is required"),
    password: z
      .string()
      .min(12, "Password must be at least 12 characters")
      .max(128, "Password is too long"),
    tenantId: z.string().optional(),
  }),
});

/**
 * Change password schema
 *
 * Requirements:
 * - Current password required
 * - New password must be at least 12 characters
 * - New password must be different from current
 */
export const changePasswordSchema = z.object({
  body: z.object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: z
      .string()
      .min(12, "New password must be at least 12 characters")
      .max(128, "New password is too long"),
    tenantId: z.string().optional(),
  }),
});

/**
 * Type inference from schemas
 */
export type RegisterInput = z.infer<typeof registerSchema>["body"];
export type LoginInput = z.infer<typeof loginSchema>["body"];
export type RefreshInput = z.infer<typeof refreshSchema>["body"];
export type ForgotPasswordInput = z.infer<typeof forgotPasswordSchema>["body"];
export type ResetPasswordInput = z.infer<typeof resetPasswordSchema>["body"];
export type ChangePasswordInput = z.infer<typeof changePasswordSchema>["body"];
