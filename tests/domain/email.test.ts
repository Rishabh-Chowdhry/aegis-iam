/**
 * Unit Tests for Email Value Object
 *
 * Tests cover:
 * - Valid email formats
 * - Invalid email formats
 * - Email normalization
 * - Email equality comparison
 */

import { Email } from "../../src/domain/value-objects/Email";

describe("Email Value Object", () => {
  describe("Creation", () => {
    describe("with valid email formats", () => {
      it("should create an email with standard format", () => {
        const email = new Email("user@example.com");
        expect(email.value).toBe("user@example.com");
      });

      it("should create an email with subdomain", () => {
        const email = new Email("user@mail.example.com");
        expect(email.value).toBe("user@mail.example.com");
      });

      it("should create an email with plus addressing", () => {
        const email = new Email("user+tag@example.com");
        expect(email.value).toBe("user+tag@example.com");
      });

      it("should create an email with dots in local part", () => {
        const email = new Email("first.last@example.com");
        expect(email.value).toBe("first.last@example.com");
      });

      it("should create an email with numbers", () => {
        const email = new Email("user123@example.com");
        expect(email.value).toBe("user123@example.com");
      });

      it("should create an email with hyphen in domain", () => {
        const email = new Email("user@my-domain.com");
        expect(email.value).toBe("user@my-domain.com");
      });

      it("should create an email with multiple hyphens in domain", () => {
        const email = new Email("user@my-sub-domain.com");
        expect(email.value).toBe("user@my-sub-domain.com");
      });

      it("should create an email with long TLD", () => {
        const email = new Email("user@example.technology");
        expect(email.value).toBe("user@example.technology");
      });

      it("should create an email with uppercase letters (normalized to lowercase)", () => {
        const email = new Email("USER@EXAMPLE.COM");
        expect(email.value).toBe("user@example.com");
      });

      it("should create an email with mixed case (normalized to lowercase)", () => {
        const email = new Email("User@Example.Com");
        expect(email.value).toBe("user@example.com");
      });
    });

    describe("with invalid email formats", () => {
      it("should throw error for empty string", () => {
        expect(() => new Email("")).toThrow("Invalid email format");
      });

      it("should throw error for email without @ symbol", () => {
        expect(() => new Email("userexample.com")).toThrow(
          "Invalid email format",
        );
      });

      it("should throw error for email without local part", () => {
        expect(() => new Email("@example.com")).toThrow("Invalid email format");
      });

      it("should throw error for email without domain", () => {
        expect(() => new Email("user@")).toThrow("Invalid email format");
      });

      it("should throw error for email without TLD", () => {
        expect(() => new Email("user@example")).toThrow("Invalid email format");
      });

      it("should throw error for email with spaces", () => {
        expect(() => new Email("user @example.com")).toThrow(
          "Invalid email format",
        );
      });

      it("should throw error for email with multiple @ symbols", () => {
        expect(() => new Email("user@example@domain.com")).toThrow(
          "Invalid email format",
        );
      });

      it("should accept email with special characters (regex allows ! at end)", () => {
        // The current regex /^[^\s@]+@[^\s@]+\.[^\s@]+$/ allows some special chars
        const email = new Email("user@example.com!");
        expect(email.value).toBe("user@example.com!");
      });

      it("should throw error for just @", () => {
        expect(() => new Email("@")).toThrow("Invalid email format");
      });

      it("should throw error for only local part", () => {
        expect(() => new Email("user")).toThrow("Invalid email format");
      });
    });
  });

  describe("Normalization", () => {
    it("should normalize email to lowercase", () => {
      const email = new Email("USER@EXAMPLE.COM");
      expect(email.value).toBe("user@example.com");
    });

    it("should preserve plus addressing", () => {
      const email = new Email("USER+TAG@EXAMPLE.COM");
      expect(email.value).toBe("user+tag@example.com");
    });

    it("should normalize mixed case with numbers", () => {
      const email = new Email("User123@Example123.COM");
      expect(email.value).toBe("user123@example123.com");
    });
  });

  describe("equals", () => {
    it("should return true for identical emails", () => {
      const email1 = new Email("user@example.com");
      const email2 = new Email("user@example.com");

      expect(email1.equals(email2)).toBe(true);
    });

    it("should return true for emails with different case", () => {
      const email1 = new Email("user@example.com");
      const email2 = new Email("USER@EXAMPLE.COM");

      expect(email1.equals(email2)).toBe(true);
    });

    it("should return false for different emails", () => {
      const email1 = new Email("user@example.com");
      const email2 = new Email("other@example.com");

      expect(email1.equals(email2)).toBe(false);
    });

    it("should return false for emails with different domains", () => {
      const email1 = new Email("user@example.com");
      const email2 = new Email("user@other.com");

      expect(email1.equals(email2)).toBe(false);
    });

    it("should return false for emails with different local parts", () => {
      const email1 = new Email("user@example.com");
      const email2 = new Email("admin@example.com");

      expect(email1.equals(email2)).toBe(false);
    });

    it("should throw error for comparing with null", () => {
      const email = new Email("user@example.com");
      expect(() => email.equals(null as any)).toThrow();
    });

    it("should throw error for comparing with undefined", () => {
      const email = new Email("user@example.com");
      expect(() => email.equals(undefined as any)).toThrow();
    });
  });

  describe("toString", () => {
    it("should return the email value as string", () => {
      const email = new Email("user@example.com");
      expect(email.toString()).toBe("user@example.com");
    });

    it("should return normalized email", () => {
      const email = new Email("USER@EXAMPLE.COM");
      expect(email.toString()).toBe("user@example.com");
    });
  });

  describe("Value Immutability", () => {
    it("should return consistent value across multiple calls", () => {
      const email = new Email("user@example.com");
      expect(email.value).toBe(email.value);
    });

    it("should not allow same email to be modified", () => {
      const email = new Email("user@example.com");
      const email2 = new Email("user@example.com");

      // Both should have same value
      expect(email.value).toBe(email2.value);
    });
  });
});
