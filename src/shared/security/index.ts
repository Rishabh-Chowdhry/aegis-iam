import * as crypto from "crypto";
import * as jwt from "jsonwebtoken";
import createDOMPurify from "dompurify";
import { JSDOM } from "jsdom";
import validator from "validator";
import { config } from "../config";
import { AppError, ErrorCode } from "../errors/AppError";

// Initialize DOMPurify with JSDOM
const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

export class SecurityUtils {
  /**
   * Generate a secure random string
   */
  static generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString("hex");
  }

  /**
   * Hash a password using Argon2id
   */
  static async hashPassword(password: string): Promise<string> {
    const argon2 = require("argon2");
    return await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 2 ** 16, // 64 MB
      timeCost: 3,
      parallelism: 1,
    });
  }

  /**
   * Verify a password against its hash
   */
  static async verifyPassword(
    hash: string,
    password: string,
  ): Promise<boolean> {
    const argon2 = require("argon2");
    try {
      return await argon2.verify(hash, password);
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate JWT access token
   */
  static generateAccessToken(payload: object): string {
    return jwt.sign(payload, config.jwtSecret, {
      expiresIn: config.jwtExpiresIn,
      issuer: "iam-system",
      audience: "iam-clients",
    } as jwt.SignOptions);
  }

  /**
   * Generate JWT refresh token
   */
  static generateRefreshToken(payload: object): string {
    return jwt.sign(payload, config.jwtRefreshSecret, {
      expiresIn: config.jwtRefreshExpiresIn,
      issuer: "iam-system",
      audience: "iam-clients",
    } as jwt.SignOptions);
  }

  /**
   * Verify JWT access token
   */
  static verifyAccessToken(token: string): any {
    try {
      return jwt.verify(token, config.jwtSecret, {
        issuer: "iam-system",
        audience: "iam-clients",
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_EXPIRED);
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_INVALID);
      }
      throw error;
    }
  }

  /**
   * Verify JWT refresh token
   */
  static verifyRefreshToken(token: string): any {
    try {
      return jwt.verify(token, config.jwtRefreshSecret, {
        issuer: "iam-system",
        audience: "iam-clients",
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw AppError.fromErrorCode(ErrorCode.TOKEN_EXPIRED);
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw AppError.fromErrorCode(ErrorCode.REFRESH_TOKEN_INVALID);
      }
      throw error;
    }
  }

  /**
   * Extract token from Authorization header
   */
  static extractTokenFromHeader(authHeader: string | undefined): string | null {
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null;
    }
    return authHeader.substring(7);
  }

  /**
   * Sanitize input to prevent injection attacks
   * Uses DOMPurify for HTML sanitization and removes dangerous characters
   */
  static sanitizeInput(input: string): string {
    if (!input || typeof input !== "string") {
      return "";
    }

    // First, use DOMPurify to sanitize any HTML content
    const sanitized = DOMPurify.sanitize(input, {
      ALLOWED_TAGS: [], // Remove all HTML tags
      ALLOWED_ATTR: [], // Remove all HTML attributes
      KEEP_CONTENT: true, // Keep the text content
    });

    // Remove any remaining dangerous characters
    return sanitized
      .replace(/[<>]/g, "") // Remove angle brackets
      .replace(/javascript:/gi, "") // Remove javascript: protocol
      .replace(/on\w+\s*=/gi, "") // Remove inline event handlers
      .replace(/data:/gi, ""); // Remove data: protocol
  }

  /**
   * Sanitize HTML content while allowing safe tags
   */
  static sanitizeHTML(input: string, allowedTags: string[] = []): string {
    if (!input || typeof input !== "string") {
      return "";
    }

    return DOMPurify.sanitize(input, {
      ALLOWED_TAGS: allowedTags,
      ALLOWED_ATTR: [],
      KEEP_CONTENT: true,
    });
  }

  /**
   * Validate email format using validator.js
   */
  static isValidEmail(email: string): boolean {
    if (!email || typeof email !== "string") {
      return false;
    }
    return validator.isEmail(email) && email.length <= 254;
  }

  /**
   * Validate URL format using validator.js
   */
  static isValidURL(url: string): boolean {
    if (!url || typeof url !== "string") {
      return false;
    }
    return validator.isURL(url, {
      protocols: ["http", "https"],
      require_protocol: true,
      allow_underscores: false,
    });
  }

  /**
   * Validate UUID format using validator.js
   */
  static isValidUUID(uuid: string): boolean {
    if (!uuid || typeof uuid !== "string") {
      return false;
    }
    return validator.isUUID(uuid);
  }

  /**
   * Validate that a string contains only alphanumeric characters
   */
  static isAlphanumeric(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isAlphanumeric(input);
  }

  /**
   * Validate that a string contains only numeric characters
   */
  static isNumeric(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isNumeric(input);
  }

  /**
   * Validate that a string is a valid integer
   */
  static isInt(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isInt(input);
  }

  /**
   * Validate that a string is a valid float
   */
  static isFloat(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isFloat(input);
  }

  /**
   * Validate that a string is a valid date
   */
  static isDate(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isDate(input);
  }

  /**
   * Validate that a string is a valid ISO date
   */
  static isISO8601(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isISO8601(input);
  }

  /**
   * Validate that a string is a valid JSON
   */
  static isJSON(input: string): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    return validator.isJSON(input);
  }

  /**
   * Escape special characters in a string for safe use in regex
   */
  static escapeRegex(input: string): string {
    if (!input || typeof input !== "string") {
      return "";
    }
    return validator.escape(input);
  }

  /**
   * Normalize email address (lowercase and trim)
   */
  static normalizeEmail(email: string): string | null {
    if (!email || typeof email !== "string") {
      return null;
    }
    const normalized = validator.normalizeEmail(email);
    return normalized || null;
  }

  /**
   * Trim and validate string length
   */
  static validateStringLength(
    input: string,
    min: number = 0,
    max: number = 1000,
  ): boolean {
    if (!input || typeof input !== "string") {
      return false;
    }
    const trimmed = input.trim();
    return trimmed.length >= min && trimmed.length <= max;
  }

  /**
   * Sanitize and validate a string
   */
  static sanitizeAndValidate(
    input: string,
    options: {
      minLength?: number;
      maxLength?: number;
      allowEmpty?: boolean;
      trim?: boolean;
    } = {},
  ): { isValid: boolean; sanitized: string; error?: string } {
    const {
      minLength = 0,
      maxLength = 1000,
      allowEmpty = false,
      trim = true,
    } = options;

    if (!input || typeof input !== "string") {
      return {
        isValid: allowEmpty,
        sanitized: "",
        error: allowEmpty ? undefined : "Input is required",
      };
    }

    let sanitized = this.sanitizeInput(input);

    if (trim) {
      sanitized = sanitized.trim();
    }

    if (!allowEmpty && sanitized.length === 0) {
      return {
        isValid: false,
        sanitized,
        error: "Input cannot be empty",
      };
    }

    if (sanitized.length < minLength) {
      return {
        isValid: false,
        sanitized,
        error: `Input must be at least ${minLength} characters`,
      };
    }

    if (sanitized.length > maxLength) {
      return {
        isValid: false,
        sanitized,
        error: `Input must be at most ${maxLength} characters`,
      };
    }

    return {
      isValid: true,
      sanitized,
    };
  }

  /**
   * Validate an object's properties against a schema
   */
  static validateObject(
    obj: Record<string, unknown>,
    schema: Record<string, (value: unknown) => boolean>,
  ): { isValid: boolean; errors: string[] } {
    const errors: string[] = [];

    for (const [key, validatorFn] of Object.entries(schema)) {
      const value = obj[key];
      if (!validatorFn(value)) {
        errors.push(`Invalid value for ${key}`);
      }
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Validate password strength
   */
  static validatePasswordStrength(password: string): {
    isValid: boolean;
    errors: string[];
  } {
    const errors: string[] = [];

    if (password.length < 8) {
      errors.push("Password must be at least 8 characters long");
    }

    if (!/[A-Z]/.test(password)) {
      errors.push("Password must contain at least one uppercase letter");
    }

    if (!/[a-z]/.test(password)) {
      errors.push("Password must contain at least one lowercase letter");
    }

    if (!/\d/.test(password)) {
      errors.push("Password must contain at least one number");
    }

    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      errors.push("Password must contain at least one special character");
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Generate CSRF token
   */
  static generateCSRFToken(): string {
    return crypto.randomBytes(32).toString("base64url");
  }

  /**
   * Hash sensitive data for logging (one-way)
   */
  static hashForLogging(data: string): string {
    return crypto
      .createHash("sha256")
      .update(data)
      .digest("hex")
      .substring(0, 8);
  }
}
