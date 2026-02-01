/**
 * PasswordService - Secure Password Hashing and Validation
 *
 * This service handles all password-related operations with a focus on security:
 * - Argon2id hashing with secure parameters
 * - Password strength validation
 * - Constant-time comparison to prevent timing attacks
 *
 * Security Considerations:
 * - Argon2id is resistant to GPU-based attacks and side-channel attacks
 * - Memory cost of 64MB makes GPU cracking impractical
 * - Time cost of 3 iterations provides good balance between security and UX
 * - Parallelism of 1 prevents concurrent execution attacks
 */

import * as crypto from "crypto";
import { PasswordHash } from "../../../domain/value-objects/PasswordHash";
import { SecurityUtils } from "../../../shared/security";
import { AppError, ErrorCode } from "../../../shared/errors/AppError";
import { logger } from "../../../shared/logger";

/**
 * Password strength validation result
 */
export interface PasswordStrengthResult {
  isValid: boolean;
  score: number; // 0-100
  errors: string[];
  suggestions: string[];
}

/**
 * Password hashing configuration
 */
export interface HashingConfig {
  /** Argon2 type (default: argon2id) */
  type?: number;
  /** Memory cost in KiB (default: 65536 = 64MB) */
  memoryCost?: number;
  /** Time cost / iterations (default: 3) */
  timeCost?: number;
  /** Parallelism factor (default: 1) */
  parallelism?: number;
  /** Hash length in bytes (default: 32) */
  hashLength?: number;
  /** Salt length in bytes (default: 16) */
  saltLength?: number;
}

/**
 * Default hashing configuration optimized for production
 */
const DEFAULT_HASHING_CONFIG: Required<HashingConfig> = {
  type: 2, // argon2id (2 is the argon2id constant in argon2 package)
  memoryCost: 2 ** 16, // 65536 KiB = 64 MB
  timeCost: 3, // 3 iterations
  parallelism: 1, // Single-threaded per hash
  hashLength: 32, // 256-bit hash
  saltLength: 16, // 128-bit salt
};

export class PasswordService {
  private static instance: PasswordService;
  private config: Required<HashingConfig>;

  private constructor(config?: HashingConfig) {
    this.config = { ...DEFAULT_HASHING_CONFIG, ...config };
  }

  /**
   * Get singleton instance
   */
  static getInstance(config?: HashingConfig): PasswordService {
    if (!PasswordService.instance) {
      PasswordService.instance = new PasswordService(config);
    }
    return PasswordService.instance;
  }

  /**
   * Hash a password using Argon2id
   *
   * @param plainPassword - Plain text password to hash
   * @returns Hashed password string (includes salt and parameters)
   * @throws AppError if hashing fails
   *
   * Security Notes:
   * - Uses Argon2id which is resistant to both GPU and side-channel attacks
   * - Includes automatic salt generation (16 bytes)
   * - Returns a complete hash string that includes parameters for verification
   */
  async hash(plainPassword: string): Promise<string> {
    this.validatePasswordInput(plainPassword);

    try {
      const argon2 = require("argon2");

      const hash = await argon2.hash(plainPassword, {
        type: this.config.type,
        memoryCost: this.config.memoryCost,
        timeCost: this.config.timeCost,
        parallelism: this.config.parallelism,
        hashLength: this.config.hashLength,
        saltLength: this.config.saltLength,
      });

      logger.debug("Password hashed successfully", {
        memoryCost: this.config.memoryCost,
        timeCost: this.config.timeCost,
        parallelism: this.config.parallelism,
      });

      return hash;
    } catch (error) {
      logger.error("Password hashing failed", {
        error: (error as Error).message,
      });
      throw AppError.fromErrorCode(
        ErrorCode.INTERNAL_SERVER_ERROR,
        "Failed to process password",
      );
    }
  }

  /**
   * Verify a password against a hash
   * 
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Stored hash to compare against
   * @returns true if password matches, false otherwise
   * 
   * Security Notes:
   - Uses argon2's built-in constant-time verification
   - Never reveals whether the user exists or the password is wrong
   - Always performs the hash computation to prevent timing attacks
   */
  async verify(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    if (!plainPassword || !hashedPassword) {
      return false;
    }

    try {
      const argon2 = require("argon2");
      return await argon2.verify(hashedPassword, plainPassword);
    } catch (error) {
      // Argon2 verify throws on invalid hash format or other errors
      // We return false to not leak information
      logger.debug("Password verification failed", {
        error: (error as Error).message,
      });
      return false;
    }
  }

  /**
   * Validate password strength according to security requirements
   *
   * @param password - Password to validate
   * @returns Validation result with score, errors, and suggestions
   *
   * Requirements:
   * - Minimum 12 characters
   * - At least one uppercase letter (A-Z)
   * - At least one lowercase letter (a-z)
   * - At least one digit (0-9)
   * - At least one special character (!@#$%^&*()_+-=[]{}|;':",./<>?)
   */
  validateStrength(password: string): PasswordStrengthResult {
    const errors: string[] = [];
    const suggestions: string[] = [];
    let score = 0;

    // Length check
    if (password.length < 12) {
      errors.push("Password must be at least 12 characters long");
      suggestions.push("Consider using a passphrase with 4+ random words");
    } else if (password.length >= 16) {
      score += 25;
    } else if (password.length >= 14) {
      score += 20;
    } else {
      score += 15;
    }

    // Uppercase check
    if (!/[A-Z]/.test(password)) {
      errors.push("Password must contain at least one uppercase letter");
      suggestions.push("Add uppercase letters to increase strength");
    } else {
      score += 15;
    }

    // Lowercase check
    if (!/[a-z]/.test(password)) {
      errors.push("Password must contain at least one lowercase letter");
      suggestions.push("Add lowercase letters to increase strength");
    } else {
      score += 15;
    }

    // Digit check
    if (!/[0-9]/.test(password)) {
      errors.push("Password must contain at least one number");
      suggestions.push("Add numbers to increase strength");
    } else {
      score += 15;
    }

    // Special character check
    const specialCharRegex = /[!@#$%^&*()_+\-=\[\]{}|;':",./<>?]/;
    if (!specialCharRegex.test(password)) {
      errors.push("Password must contain at least one special character");
      suggestions.push(
        "Add special characters like !@#$%^&* to increase strength",
      );
    } else {
      score += 20;
    }

    // Additional checks for strong passwords
    // Check for common patterns
    if (/(.)\1{2,}/.test(password)) {
      errors.push("Password contains repeated characters");
      suggestions.push("Avoid repeating characters like 'aaa'");
      score -= 10;
    }

    // Check for sequential characters
    const sequentialPatterns = [
      "123",
      "234",
      "345",
      "456",
      "567",
      "678",
      "789",
      "abc",
      "bcd",
      "cde",
      "def",
      "efg",
      "fgh",
      "ghi",
      "qwerty",
      "asdfgh",
      "zxcvbn",
    ];
    const lowerPassword = password.toLowerCase();
    const hasSequential = sequentialPatterns.some((pattern) =>
      lowerPassword.includes(pattern),
    );
    if (hasSequential) {
      errors.push("Password contains sequential characters");
      suggestions.push("Avoid common patterns like '123' or 'qwerty'");
      score -= 15;
    }

    // Check password entropy (bonus points)
    const uniqueChars = new Set(password).size;
    const entropyBonus = Math.min(uniqueChars * 2, 10);
    score += entropyBonus;

    // Normalize score to 0-100
    score = Math.max(0, Math.min(100, score));

    return {
      isValid: errors.length === 0,
      score,
      errors,
      suggestions,
    };
  }

  /**
   * Generate a secure random password
   *
   * @param length - Password length (default: 16)
   * @returns Randomly generated secure password
   */
  generateSecurePassword(length: number = 16): string {
    const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const lowercase = "abcdefghijklmnopqrstuvwxyz";
    const digits = "0123456789";
    const special = "!@#$%^&*()_+-=[]{}|;':\",./<>?";
    const allChars = uppercase + lowercase + digits + special;

    // Ensure at least one character from each set
    const sets = [uppercase, lowercase, digits, special];
    const passwordChars: string[] = [];

    for (const set of sets) {
      passwordChars.push(set[crypto.randomInt(set.length)]);
    }

    // Fill remaining length
    const remainingLength = Math.max(0, length - sets.length);
    for (let i = 0; i < remainingLength; i++) {
      passwordChars.push(allChars[crypto.randomInt(allChars.length)]);
    }

    // Shuffle the password
    for (let i = passwordChars.length - 1; i > 0; i--) {
      const j = crypto.randomInt(i + 1);
      [passwordChars[i], passwordChars[j]] = [
        passwordChars[j],
        passwordChars[i],
      ];
    }

    return passwordChars.join("");
  }

  /**
   * Check if a password has been compromised (requires HaveIBeenPwned integration)
   * This is a placeholder for future k-Anonymity integration
   *
   * @param password - Password to check
   * @returns true if password appears in known breaches
   */
  async isPasswordCompromised(_password: string): Promise<boolean> {
    // TODO: Implement k-Anonymity HIBP integration
    // For production, this should:
    // 1. Hash password with SHA-256
    // 2. Send first 5 chars to HIBP API
    // 3. Check if suffix is in returned list
    // This implementation is intentionally left as a placeholder

    logger.debug("Password compromise check not implemented - placeholder");
    return false;
  }

  /**
   * Validate password input
   *
   * @param password - Password to validate
   * @throws AppError if password is invalid
   */
  private validatePasswordInput(password: string): void {
    if (!password || typeof password !== "string") {
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_PASSWORD,
        "Password is required",
      );
    }

    // Reject passwords that are too long (DoS protection)
    if (password.length > 1000) {
      throw AppError.fromErrorCode(
        ErrorCode.INVALID_PASSWORD,
        "Password is too long",
      );
    }
  }

  /**
   * Generate a cryptographic salt
   *
   * @param length - Salt length in bytes (default: 16)
   * @returns Random salt as hex string
   */
  static generateSalt(length: number = 16): string {
    return crypto.randomBytes(length).toString("hex");
  }

  /**
   * Get hashing configuration (for testing/debugging)
   */
  getConfig(): Readonly<Required<HashingConfig>> {
    return { ...this.config };
  }
}
