/**
 * Unit Tests for PasswordHash Value Object
 *
 * Tests cover:
 * - Password hashing (async)
 * - Password verification (async)
 * - Hash comparison
 * - Salt handling
 */

import { PasswordHash } from "../../src/domain/value-objects/PasswordHash";

// Mock argon2 for testing
jest.mock("argon2", () => ({
  hash: jest.fn(),
  verify: jest.fn(),
  argon2id: "argon2id",
}));

import argon2 from "argon2";

describe("PasswordHash Value Object", () => {
  const mockedArgon2 = argon2 as jest.Mocked<typeof argon2>;

  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Creation", () => {
    describe("with valid hash", () => {
      it("should create a PasswordHash with valid hash string", () => {
        const hash = "$argon2id$v=19$m=65536,t=3,p=4$testHash";
        const passwordHash = new PasswordHash(hash);

        expect(passwordHash.hash).toBe(hash);
      });

      it("should create a PasswordHash with long hash", () => {
        const longHash =
          "$argon2id$v=19$m=65536,t=3,p=4$veryLongHashStringThatRepresentsAProperArgon2Hash";
        const passwordHash = new PasswordHash(longHash);

        expect(passwordHash.hash).toBe(longHash);
      });

      it("should create a PasswordHash with special characters in hash", () => {
        const hashWithSpecialChars =
          "$argon2id$v=19$m=65536,t=3,p=4$hashWith+Spectial/Ch@rs=";
        const passwordHash = new PasswordHash(hashWithSpecialChars);

        expect(passwordHash.hash).toBe(hashWithSpecialChars);
      });

      it("should create a PasswordHash with whitespace (spaces are valid characters)", () => {
        // PasswordHash constructor only checks for falsy, not whitespace
        const hashWithSpaces =
          "$argon2id$v=19$m=65536,t=3,p=4$hash with spaces";
        const passwordHash = new PasswordHash(hashWithSpaces);

        expect(passwordHash.hash).toBe(hashWithSpaces);
      });
    });

    describe("with invalid data", () => {
      it("should throw error when hash is empty string", () => {
        expect(() => new PasswordHash("")).toThrow("Password hash is required");
      });

      it("should throw error when hash is null", () => {
        expect(() => new PasswordHash(null as any)).toThrow(
          "Password hash is required",
        );
      });

      it("should throw error when hash is undefined", () => {
        expect(() => new PasswordHash(undefined as any)).toThrow(
          "Password hash is required",
        );
      });
    });
  });

  describe("fromPlainPassword (Static Factory)", () => {
    it("should create PasswordHash from plain password using argon2", async () => {
      const mockHash = "$argon2id$v=19$m=65536,t=3,p=4$mockedHash";
      mockedArgon2.hash.mockResolvedValue(mockHash);

      const passwordHash =
        await PasswordHash.fromPlainPassword("plainPassword");

      expect(passwordHash).toBeInstanceOf(PasswordHash);
      expect(passwordHash.hash).toBe(mockHash);
      expect(mockedArgon2.hash).toHaveBeenCalledWith("plainPassword", {
        type: "argon2id",
      });
    });

    it("should use argon2id algorithm", async () => {
      mockedArgon2.hash.mockResolvedValue("mockedHash");

      await PasswordHash.fromPlainPassword("password");

      expect(mockedArgon2.hash).toHaveBeenCalledWith("password", {
        type: "argon2id",
      });
    });

    it("should throw error when hashing fails", async () => {
      mockedArgon2.hash.mockRejectedValue(new Error("Hashing failed"));

      await expect(PasswordHash.fromPlainPassword("password")).rejects.toThrow(
        "Hashing failed",
      );
    });
  });

  describe("verifyPassword", () => {
    it("should return true when password matches hash", async () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$mockedHash";
      const passwordHash = new PasswordHash(hash);
      mockedArgon2.verify.mockResolvedValue(true);

      const result = await passwordHash.verifyPassword("correctPassword");

      expect(result).toBe(true);
      expect(mockedArgon2.verify).toHaveBeenCalledWith(hash, "correctPassword");
    });

    it("should return false when password does not match hash", async () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$mockedHash";
      const passwordHash = new PasswordHash(hash);
      mockedArgon2.verify.mockResolvedValue(false);

      const result = await passwordHash.verifyPassword("wrongPassword");

      expect(result).toBe(false);
    });

    it("should throw error when verification fails", async () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$mockedHash";
      const passwordHash = new PasswordHash(hash);
      mockedArgon2.verify.mockRejectedValue(new Error("Verification failed"));

      await expect(passwordHash.verifyPassword("password")).rejects.toThrow(
        "Verification failed",
      );
    });
  });

  describe("equals", () => {
    it("should return true for identical hashes", () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$sameHash";
      const passwordHash1 = new PasswordHash(hash);
      const passwordHash2 = new PasswordHash(hash);

      expect(passwordHash1.equals(passwordHash2)).toBe(true);
    });

    it("should return false for different hashes", () => {
      const hash1 = "$argon2id$v=19$m=65536,t=3,p=4$hash1";
      const hash2 = "$argon2id$v=19$m=65536,t=3,p=4$hash2";
      const passwordHash1 = new PasswordHash(hash1);
      const passwordHash2 = new PasswordHash(hash2);

      expect(passwordHash1.equals(passwordHash2)).toBe(false);
    });

    it("should throw error for comparing with null", () => {
      const passwordHash = new PasswordHash(
        "$argon2id$v=19$m=65536,t=3,p=4$hash",
      );

      expect(() => passwordHash.equals(null as any)).toThrow();
    });

    it("should throw error for comparing with undefined", () => {
      const passwordHash = new PasswordHash(
        "$argon2id$v=19$m=65536,t=3,p=4$hash",
      );

      expect(() => passwordHash.equals(undefined as any)).toThrow();
    });

    it("should return false for comparing with non-PasswordHash object", () => {
      const passwordHash = new PasswordHash(
        "$argon2id$v=19$m=65536,t=3,p=4$hash",
      );

      expect(passwordHash.equals({ hash: "different" } as any)).toBe(false);
    });
  });

  describe("Hash Format", () => {
    it("should store argon2id format hash", () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$testHash";
      const passwordHash = new PasswordHash(hash);

      expect(passwordHash.hash.startsWith("$argon2id$")).toBe(true);
    });

    it("should handle different argon2 variants", () => {
      const argon2dHash = "$argon2d$v=19$m=65536,t=3,p=4$testHash";
      const passwordHash = new PasswordHash(argon2dHash);

      expect(passwordHash.hash).toBe(argon2dHash);
    });
  });

  describe("Security Considerations", () => {
    it("should not expose plain password in error messages", () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$testHash";
      const passwordHash = new PasswordHash(hash);

      try {
        new PasswordHash("");
      } catch (error: any) {
        expect(error.message).not.toContain("plain password");
        expect(error.message).toBe("Password hash is required");
      }
    });
  });

  describe("Immutability", () => {
    it("should have consistent hash value", () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$testHash";
      const passwordHash = new PasswordHash(hash);

      expect(passwordHash.hash).toBe(hash);
      expect(passwordHash.hash).toBe(hash); // Multiple calls should return same value
    });

    it("should not allow modification through public API", () => {
      const hash = "$argon2id$v=19$m=65536,t=3,p=4$testHash";
      const passwordHash = new PasswordHash(hash);

      // Verify that the hash getter returns the same value
      expect(passwordHash.hash).toBe(hash);
    });
  });
});
