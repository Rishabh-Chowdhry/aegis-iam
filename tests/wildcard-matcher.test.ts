/**
 * WildcardMatcher Test Suite
 *
 * Comprehensive tests for enterprise-grade ABAC policy engine wildcard matching.
 */

import {
  WildcardMatcher,
  WildcardPattern,
  matchesAction,
  matchesResource,
  matchesHierarchicalAction,
  matchesHierarchicalResource,
  normalizeAction,
  normalizeResource,
  parseActionParts,
  expandPattern,
} from "../src/modules/iam/conditions/WildcardMatcher";

describe("WildcardMatcher", () => {
  let matcher: WildcardMatcher;

  beforeEach(() => {
    matcher = new WildcardMatcher();
    // Clear cache before each test
    WildcardMatcher.clearCache();
  });

  afterAll(() => {
    WildcardMatcher.clearCache();
  });

  describe("matches() - Single Pattern Matching", () => {
    it("should match basic wildcard pattern", () => {
      const result = matcher.matches("INVOICE_READ", "INVOICE_*");
      expect(result.matches).toBe(true);
      expect(result.matchedPattern).toBe("INVOICE_*");
    });

    it("should match pattern with multiple wildcards", () => {
      const result = matcher.matches("INVOICE_DELETE", "INVOICE_*");
      expect(result.matches).toBe(true);
      expect(result.matchedPattern).toBe("INVOICE_*");
    });

    it("should not match non-matching pattern", () => {
      const result = matcher.matches("USER_READ", "INVOICE_*");
      expect(result.matches).toBe(false);
      expect(result.reason).toBe("No wildcard match");
    });

    it("should match single character wildcard", () => {
      const result = matcher.matches("invoice:a", "invoice:?");
      expect(result.matches).toBe(true);
      expect(result.matchedPattern).toBe("invoice:?");
    });

    it("should not match single character wildcard with multiple chars", () => {
      const result = matcher.matches("invoice:123", "invoice:?");
      expect(result.matches).toBe(false);
    });

    it("should match multiple wildcards in pattern", () => {
      const result = matcher.matches("USER_A_READ", "*_?_READ");
      expect(result.matches).toBe(true);
    });

    it("should not match when single char wildcard expects exactly one", () => {
      const result = matcher.matches("USER_READ", "*_?_READ");
      expect(result.matches).toBe(false);
    });

    it("should match asterisk at start", () => {
      const result = matcher.matches("USER_READ", "*_READ");
      expect(result.matches).toBe(true);
    });

    it("should match asterisk at end", () => {
      const result = matcher.matches("INVOICE_READ", "INVOICE_*");
      expect(result.matches).toBe(true);
    });

    it("should handle case-insensitive matching for actions", () => {
      const result = matcher.matches("invoice_read", "INVOICE_*", {
        caseInsensitive: true,
      });
      expect(result.matches).toBe(true);
    });

    it("should handle case-sensitive matching", () => {
      const result = matcher.matches("INVOICE_READ", "invoice_*", {
        caseInsensitive: false,
      });
      expect(result.matches).toBe(false);
    });

    it("should handle null/undefined values", () => {
      const result1 = matcher.matches(null as any, "INVOICE_*");
      expect(result1.matches).toBe(false);
      expect(result1.reason).toBe("Value is null or undefined");

      const result2 = matcher.matches(undefined as any, "INVOICE_*");
      expect(result2.matches).toBe(false);
      expect(result2.reason).toBe("Value is null or undefined");
    });

    it("should handle empty pattern", () => {
      const result1 = matcher.matches("", "");
      expect(result1.matches).toBe(true);

      const result2 = matcher.matches("value", "");
      expect(result2.matches).toBe(false);
    });

    it("should match global wildcard", () => {
      const result = matcher.matches("ANY_ACTION", "*");
      expect(result.matches).toBe(true);
    });
  });

  describe("matchesAny() - Multiple Pattern Matching", () => {
    it("should match first pattern in list", () => {
      const result = matcher.matchesAny("INVOICE_DELETE", [
        "INVOICE_*",
        "USER_*",
      ]);
      expect(result.matched).toBe(true);
      expect(result.matchedPatterns).toEqual(["INVOICE_*"]);
      expect(result.unmatchedPatterns).toEqual(["USER_*"]);
    });

    it("should match second pattern in list", () => {
      const result = matcher.matchesAny("USER_DELETE", ["INVOICE_*", "USER_*"]);
      expect(result.matched).toBe(true);
      expect(result.matchedPatterns).toEqual(["USER_*"]);
      expect(result.unmatchedPatterns).toEqual(["INVOICE_*"]);
    });

    it("should match multiple patterns if they all match", () => {
      const result = matcher.matchesAny("INVOICE_READ", [
        "INVOICE_*",
        "*_READ",
      ]);
      expect(result.matched).toBe(true);
      expect(result.matchedPatterns).toEqual(["INVOICE_*", "*_READ"]);
    });

    it("should return no matches if none match", () => {
      const result = matcher.matchesAny("ORDER_DELETE", [
        "INVOICE_*",
        "USER_*",
      ]);
      expect(result.matched).toBe(false);
      expect(result.matchedPatterns).toEqual([]);
      expect(result.unmatchedPatterns).toEqual(["INVOICE_*", "USER_*"]);
    });

    it("should handle empty patterns array", () => {
      const result = matcher.matchesAny("INVOICE_READ", []);
      expect(result.matched).toBe(false);
      expect(result.matchedPatterns).toEqual([]);
    });
  });

  describe("matchAll() - Multiple Values Against Multiple Patterns", () => {
    it("should return map of values to matched patterns", () => {
      const values = ["INVOICE_READ", "USER_READ"];
      const patterns = ["INVOICE_*", "USER_*"];
      const result = matcher.matchAll(values, patterns);

      expect(result.get("INVOICE_READ")).toEqual(["INVOICE_*"]);
      expect(result.get("USER_READ")).toEqual(["USER_*"]);
    });

    it("should handle multiple matches per value", () => {
      const values = ["INVOICE_READ"];
      const patterns = ["INVOICE_*", "*_READ"];
      const result = matcher.matchAll(values, patterns);

      expect(result.get("INVOICE_READ")).toEqual(["INVOICE_*", "*_READ"]);
    });

    it("should handle no matches", () => {
      const values = ["ORDER_DELETE"];
      const patterns = ["INVOICE_*", "USER_*"];
      const result = matcher.matchAll(values, patterns);

      expect(result.get("ORDER_DELETE")).toEqual([]);
    });

    it("should handle empty arrays", () => {
      const result1 = matcher.matchAll([], ["INVOICE_*"]);
      expect(result1.size).toBe(0);

      const result2 = matcher.matchAll(["INVOICE_READ"], []);
      expect(result2.get("INVOICE_READ")).toEqual([]);
    });
  });

  describe("isValidPattern() - Pattern Validation", () => {
    it("should return true for valid patterns", () => {
      expect(matcher.isValidPattern("INVOICE_*")).toBe(true);
      expect(matcher.isValidPattern("*_READ")).toBe(true);
      expect(matcher.isValidPattern("invoice:?")).toBe(true);
      expect(matcher.isValidPattern("*")).toBe(true);
    });

    it("should return false for empty pattern", () => {
      expect(matcher.isValidPattern("")).toBe(false);
    });

    it("should handle null/undefined", () => {
      expect(matcher.isValidPattern(null as any)).toBe(false);
      expect(matcher.isValidPattern(undefined as any)).toBe(false);
    });
  });

  describe("patternToRegex() - Regex Conversion", () => {
    it("should convert wildcard pattern to regex", () => {
      const regex = matcher.patternToRegex("INVOICE_*");
      expect(regex.test("INVOICE_READ")).toBe(true);
      expect(regex.test("INVOICE_DELETE")).toBe(true);
      expect(regex.test("USER_READ")).toBe(false);
    });

    it("should convert single char wildcard to regex", () => {
      const regex = matcher.patternToRegex("invoice:?");
      expect(regex.test("invoice:a")).toBe(true);
      expect(regex.test("invoice:ab")).toBe(true);
    });

    it("should handle case-insensitive option", () => {
      const regex = matcher.patternToRegex("INVOICE_*", {
        caseInsensitive: true,
      });
      expect(regex.test("invoice_read")).toBe(true);
      expect(regex.test("Invoice_Read")).toBe(true);
    });

    it("should handle start anchoring", () => {
      const regex = matcher.patternToRegex("INVOICE_*", {
        anchorStart: true,
      });
      expect(regex.test("INVOICE_READ")).toBe(true);
      expect(regex.test("PREFIX_INVOICE_READ")).toBe(false);
      expect(regex.test("INVOICE_READ_SUFFIX")).toBe(true);
    });
  });

  describe("matchesAction() - Action Matching", () => {
    it("should match action with case-insensitivity", () => {
      const result = matcher.matchesAction("invoice:read", "INVOICE:READ");
      expect(result.matches).toBe(true);
    });

    it("should match action with wildcard", () => {
      const result = matcher.matchesAction("INVOICE:DELETE", "INVOICE:*");
      expect(result.matches).toBe(true);
    });

    it("should not match different actions", () => {
      const result = matcher.matchesAction("USER:READ", "INVOICE:*");
      expect(result.matches).toBe(false);
    });
  });

  describe("matchesResource() - Resource Matching", () => {
    it("should match resource pattern", () => {
      const result = matcher.matchesResource("invoice:12345", "invoice:*");
      expect(result.matches).toBe(true);
    });

    it("should not match different resources", () => {
      const result = matcher.matchesResource("order:12345", "invoice:*");
      expect(result.matches).toBe(false);
    });

    it("should be case-sensitive by default", () => {
      const result = matcher.matchesResource("INVOICE:12345", "invoice:*");
      expect(result.matches).toBe(false);
    });
  });

  describe("matchesHierarchicalAction() - Hierarchical Action Matching", () => {
    it("should match hierarchical action with wildcard", () => {
      const result = matcher.matchesHierarchicalAction(
        "INVOICE:READ:123",
        "INVOICE:*",
      );
      expect(result.matches).toBe(true);
    });

    it("should match with wildcard at start", () => {
      const result = matcher.matchesHierarchicalAction(
        "INVOICE:READ",
        "*:READ",
      );
      expect(result.matches).toBe(true);
    });

    it("should match exact action", () => {
      const result = matcher.matchesHierarchicalAction(
        "INVOICE:READ",
        "INVOICE:READ",
      );
      expect(result.matches).toBe(true);
    });

    it("should not match when pattern has more segments", () => {
      const result = matcher.matchesHierarchicalAction(
        "INVOICE:READ",
        "INVOICE:READ:EXTRA",
      );
      expect(result.matches).toBe(false);
    });
  });

  describe("matchesHierarchicalResource() - Hierarchical Resource Matching", () => {
    it("should match hierarchical resource with wildcard", () => {
      const result = matcher.matchesHierarchicalResource(
        "invoice:123:items",
        "invoice:*",
      );
      expect(result.matches).toBe(true);
    });

    it("should match exact resource", () => {
      const result = matcher.matchesHierarchicalResource(
        "invoice:123",
        "invoice:123",
      );
      expect(result.matches).toBe(true);
    });

    it("should not match different resources", () => {
      const result = matcher.matchesHierarchicalResource(
        "order:123",
        "invoice:*",
      );
      expect(result.matches).toBe(false);
    });
  });

  describe("Pattern Caching", () => {
    it("should cache compiled patterns", () => {
      matcher.matches("INVOICE_READ", "INVOICE_*");
      matcher.matches("INVOICE_DELETE", "INVOICE_*");
      expect(WildcardMatcher.getCacheSize()).toBeGreaterThan(0);
    });

    it("should clear cache", () => {
      matcher.matches("INVOICE_READ", "INVOICE_*");
      WildcardMatcher.clearCache();
      expect(WildcardMatcher.getCacheSize()).toBe(0);
    });
  });
});

describe("WildcardPattern", () => {
  it("should compile pattern to regex", () => {
    const pattern = new WildcardPattern("INVOICE_*");
    expect(pattern.matches("INVOICE_READ")).toBe(true);
    expect(pattern.matches("USER_READ")).toBe(false);
  });

  it("should report if pattern has wildcards", () => {
    expect(new WildcardPattern("INVOICE_*").hasWildcards()).toBe(true);
    expect(new WildcardPattern("INVOICE_READ").hasWildcards()).toBe(false);
  });

  it("should return original pattern", () => {
    const pattern = new WildcardPattern("INVOICE_*");
    expect(pattern.getPattern()).toBe("INVOICE_*");
  });
});

describe("Helper Functions", () => {
  describe("normalizeAction", () => {
    it("should uppercase and trim action", () => {
      expect(normalizeAction("  invoice:read  ")).toBe("INVOICE:READ");
    });
  });

  describe("normalizeResource", () => {
    it("should lowercase and trim resource", () => {
      expect(normalizeResource("  INVOICE:123  ")).toBe("invoice:123");
    });
  });

  describe("parseActionParts", () => {
    it("should split action into parts", () => {
      expect(parseActionParts("INVOICE:READ:123")).toEqual([
        "INVOICE",
        "READ",
        "123",
      ]);
    });

    it("should handle single segment", () => {
      expect(parseActionParts("INVOICE")).toEqual(["INVOICE"]);
    });

    it("should filter empty segments", () => {
      expect(parseActionParts("INVOICE::READ")).toEqual(["INVOICE", "READ"]);
    });
  });

  describe("matchesAction", () => {
    it("should match action with case-insensitivity", () => {
      expect(matchesAction("invoice:read", "INVOICE:READ")).toBe(true);
    });
  });

  describe("matchesResource", () => {
    it("should match resource with case-sensitivity", () => {
      expect(matchesResource("invoice:123", "invoice:123")).toBe(true);
      expect(matchesResource("INVOICE:123", "invoice:123")).toBe(false);
    });
  });

  describe("matchesHierarchicalAction", () => {
    it("should match hierarchical action", () => {
      expect(matchesHierarchicalAction("INVOICE:READ", "INVOICE:*")).toBe(true);
      expect(matchesHierarchicalAction("INVOICE:READ", "*:READ")).toBe(true);
      expect(matchesHierarchicalAction("INVOICE:READ", "PAYMENT:*")).toBe(
        false,
      );
    });
  });

  describe("matchesHierarchicalResource", () => {
    it("should match hierarchical resource", () => {
      expect(
        matchesHierarchicalResource("invoice:123:items", "invoice:*"),
      ).toBe(true);
      expect(matchesHierarchicalResource("invoice:123", "invoice:123")).toBe(
        true,
      );
    });
  });

  describe("expandPattern", () => {
    it("should expand pattern to possible combinations", () => {
      const expansions = expandPattern("A?B", 100);
      expect(expansions.length).toBeGreaterThan(0);
      expect(expansions).toContain("AaB");
    });

    it("should respect maxExpansions limit", () => {
      const expansions = expandPattern("***", 5);
      expect(expansions.length).toBeLessThanOrEqual(5);
    });
  });
});

describe("Pattern Examples from Requirements", () => {
  const matcher = new WildcardMatcher();

  // Pattern examples table - using AWS IAM-style behavior
  // * matches zero or more characters within a segment
  // ? matches exactly one character within a segment
  // Wildcards do not cross segment boundaries (defined by :)
  const patternTests = [
    // Basic wildcard patterns
    ["INVOICE_*", "INVOICE_READ", true],
    ["INVOICE_*", "INVOICE_APPROVE", true],
    ["INVOICE_*", "INVOICE_", true], // * matches zero characters after underscore
    ["INVOICE_*", "INVOICE", false], // underscore is literal, must be present
    ["*_READ", "USER_READ", true],
    ["*_READ", "INVOICE_READ", true],
    ["*_READ", "READ_USER", false],
    ["*", "AnyAction", true],

    // Hierarchical resource patterns (segment delimiter :)
    ["invoice:*", "invoice:123", true],
    ["invoice:*", "invoice:abc", true],
    ["invoice:*", "invoice", false],
    ["invoice:*", "invoice:123:extra", true], // * matches segment "123", extra is additional segment

    // Single character wildcard
    ["invoice:?", "invoice:a", true],
    ["invoice:?", "invoice:1", true],
    ["invoice:?", "invoice:123", false], // ? matches exactly one character

    // Hierarchical action patterns
    ["*:READ", "user:READ", true],
    ["*:READ", "order:READ", true],
    ["*:READ", "READ", false],

    // Multiple wildcards
    ["*_?_READ", "USER_A_READ", true],
    ["*_?_READ", "USER_READ", false],
    ["*_?_READ", "USER_AB_READ", false],
  ];

  test.each(patternTests)(
    "Pattern %s should %s match %s",
    (pattern, value, expected) => {
      const result = matcher.matches(value as string, pattern as string);
      expect(result.matches).toBe(expected);
    },
  );
});
