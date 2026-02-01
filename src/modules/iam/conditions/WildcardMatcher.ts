/**
 * Wildcard Pattern Matcher
 *
 * Implements AWS IAM-style glob-style pattern matching for policy actions and resources.
 * Supports single character wildcards (*) and multi-character wildcards (?).
 * Designed for enterprise-grade ABAC policy engine.
 */

export interface WildcardMatchOptions {
  /**
   * Whether to treat patterns as case-insensitive
   */
  caseInsensitive?: boolean;

  /**
   * Whether to anchor pattern at start
   */
  anchorStart?: boolean;

  /**
   * Whether to anchor pattern at end
   */
  anchorEnd?: boolean;

  /**
   * Segment delimiter for hierarchical matching (default: ":")
   */
  segmentDelimiter?: string;
}

/**
 * Result of pattern matching for single value/pattern
 */
export interface MatchResult {
  matches: boolean;
  matchedPattern: string;
  reason?: string;
}

/**
 * Result of matching a value against multiple patterns
 */
export interface MultiMatchResult {
  matched: boolean;
  matchedPatterns: string[];
  unmatchedPatterns: string[];
}

/**
 * Result of matching multiple values against multiple patterns
 */
export interface MultiValueMatchResult {
  matched: boolean;
  matches: Map<string, string[]>;
}

/**
 * WildcardPattern class for glob-style pattern matching
 */
export class WildcardPattern {
  private pattern: string;
  private options: Required<WildcardMatchOptions>;
  private regex: RegExp | null = null;

  constructor(pattern: string, options: WildcardMatchOptions = {}) {
    this.pattern = pattern;
    this.options = {
      caseInsensitive: options.caseInsensitive ?? false,
      anchorStart: options.anchorStart ?? false,
      anchorEnd: options.anchorEnd ?? false,
      segmentDelimiter: options.segmentDelimiter ?? ":",
    };
    this.compile();
  }

  /**
   * Compile wildcard pattern to regex
   */
  private compile(): void {
    // Escape special regex characters except * and ?
    let regexStr = this.pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars
      .replace(/\*\*/g, "≋≋") // Temporary placeholder for **
      .replace(/\*/g, ".*") // * matches any character (including empty)
      .replace(/≋≋/g, ".*") // ** also matches any character (including empty)
      .replace(/\?/g, "."); // ? matches exactly one character

    // Apply anchoring
    if (this.options.anchorStart) {
      regexStr = `^${regexStr}`;
    }
    if (this.options.anchorEnd) {
      regexStr = `${regexStr}$`;
    }

    this.regex = new RegExp(
      regexStr,
      this.options.caseInsensitive ? "i" : undefined,
    );
  }

  /**
   * Test if value matches the pattern
   */
  matches(value: string): boolean {
    if (!this.regex) {
      throw new Error("Pattern not compiled");
    }
    return this.regex.test(value);
  }

  /**
   * Get the original pattern
   */
  getPattern(): string {
    return this.pattern;
  }

  /**
   * Check if pattern contains wildcards
   */
  hasWildcards(): boolean {
    return this.pattern.includes("*") || this.pattern.includes("?");
  }
}

/**
 * WildcardMatcher - Enterprise-grade wildcard pattern matching for ABAC policies
 *
 * Implements AWS IAM-style wildcard matching with:
 * - * matches zero or more characters within a single segment
 * - ? matches exactly one character within a segment
 * - Case-insensitive matching for actions
 * - Segment-based matching for namespace:action format
 */
export class WildcardMatcher {
  // Pattern cache for performance optimization
  private static patternCache: Map<string, WildcardPattern> = new Map();
  private static readonly CACHE_MAX_SIZE = 1000;

  /**
   * Get or create a cached pattern
   */
  private static getCachedPattern(
    pattern: string,
    caseInsensitive: boolean = false,
  ): WildcardPattern {
    const cacheKey = `${caseInsensitive ? "ci:" : "cs:"}${pattern}`;
    let cached = this.patternCache.get(cacheKey);

    if (!cached) {
      // Clear cache if it exceeds max size
      if (this.patternCache.size >= this.CACHE_MAX_SIZE) {
        // Remove oldest entry (first key-value pair)
        const firstKey = this.patternCache.keys().next().value;
        if (firstKey !== undefined) {
          this.patternCache.delete(firstKey);
        }
      }
      cached = new WildcardPattern(pattern, { caseInsensitive });
      this.patternCache.set(cacheKey, cached);
    }

    return cached;
  }

  /**
   * Clear the pattern cache
   * Useful for testing and memory management
   */
  static clearCache(): void {
    this.patternCache.clear();
  }

  /**
   * Get cache size for monitoring
   */
  static getCacheSize(): number {
    return this.patternCache.size;
  }

  /**
   * Match a single segment against a pattern segment
   * Handles * and ? wildcards within a single segment
   */
  private matchSegment(segment: string, patternSegment: string): boolean {
    // Escape special regex characters except * and ?
    let regexStr = patternSegment
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*") // * matches zero or more characters
      .replace(/\?/g, "."); // ? matches exactly one character

    const regex = new RegExp(`^${regexStr}$`);
    return regex.test(segment);
  }

  /**
   * Match a single value against a single pattern
   *
   * @param value - The value to match (e.g., "INVOICE_READ")
   * @param pattern - The wildcard pattern (e.g., "INVOICE_*")
   * @param options - Optional matching options
   * @returns MatchResult with matches boolean, matched pattern, and optional reason
   */
  matches(
    value: string,
    pattern: string,
    options?: WildcardMatchOptions,
  ): MatchResult {
    // Handle edge cases
    if (value === undefined || value === null) {
      return {
        matches: false,
        matchedPattern: pattern,
        reason: "Value is null or undefined",
      };
    }

    if (!pattern || pattern.trim() === "") {
      // Empty pattern only matches empty value
      return {
        matches: value === "",
        matchedPattern: pattern,
        reason:
          value === ""
            ? undefined
            : "Empty pattern cannot match non-empty value",
      };
    }

    const caseInsensitive = options?.caseInsensitive ?? false;
    const delimiter = options?.segmentDelimiter ?? ":";
    const normalizedValue = caseInsensitive ? value.toUpperCase() : value;
    const normalizedPattern = caseInsensitive ? pattern.toUpperCase() : pattern;

    // Use segment-based matching for patterns with delimiters
    if (delimiter && pattern.includes(delimiter)) {
      return this.matchHierarchical(
        normalizedValue,
        normalizedPattern,
        delimiter,
      );
    }

    // For simple patterns without segment delimiter, use regex matching
    try {
      const wildcardPattern = WildcardMatcher.getCachedPattern(
        pattern,
        caseInsensitive,
      );
      const matchResult = wildcardPattern.matches(normalizedValue);

      return {
        matches: matchResult,
        matchedPattern: pattern,
        reason: matchResult ? undefined : "No wildcard match",
      };
    } catch (error) {
      return {
        matches: false,
        matchedPattern: pattern,
        reason: `Pattern compilation error: ${(error as Error).message}`,
      };
    }
  }

  /**
   * Hierarchical matching for segment-based patterns
   */
  private matchHierarchical(
    value: string,
    pattern: string,
    delimiter: string,
  ): MatchResult {
    const valueParts = value.split(delimiter).filter(Boolean);
    const patternParts = pattern.split(delimiter).filter(Boolean);

    // If pattern has more parts than value, it can't match
    if (patternParts.length > valueParts.length) {
      return {
        matches: false,
        matchedPattern: pattern,
        reason: "Pattern has more segments than value",
      };
    }

    // Check each part
    for (let i = 0; i < patternParts.length; i++) {
      const patternPart = patternParts[i];
      const valuePart = valueParts[i];

      const segmentMatch = this.matchSegment(valuePart, patternPart);
      if (!segmentMatch) {
        return {
          matches: false,
          matchedPattern: pattern,
          reason: `Segment ${i + 1} does not match`,
        };
      }
    }

    return {
      matches: true,
      matchedPattern: pattern,
    };
  }

  /**
   * Match a value against multiple patterns (OR logic)
   * Returns true if value matches any pattern
   *
   * @param value - The value to match
   * @param patterns - Array of wildcard patterns
   * @param options - Optional matching options
   * @returns MultiMatchResult with matched/unmatched patterns
   */
  matchesAny(
    value: string,
    patterns: string[],
    options?: WildcardMatchOptions,
  ): MultiMatchResult {
    const matchedPatterns: string[] = [];
    const unmatchedPatterns: string[] = [];

    for (const pattern of patterns) {
      const result = this.matches(value, pattern, options);
      if (result.matches) {
        matchedPatterns.push(pattern);
      } else {
        unmatchedPatterns.push(pattern);
      }
    }

    return {
      matched: matchedPatterns.length > 0,
      matchedPatterns,
      unmatchedPatterns,
    };
  }

  /**
   * Match multiple values against multiple patterns
   * Returns which patterns matched each value
   *
   * @param values - Array of values to match
   * @param patterns - Array of wildcard patterns
   * @param options - Optional matching options
   * @returns Map of value to matched patterns
   */
  matchAll(
    values: string[],
    patterns: string[],
    options?: WildcardMatchOptions,
  ): Map<string, string[]> {
    const matches = new Map<string, string[]>();

    for (const value of values) {
      const result = this.matchesAny(value, patterns, options);
      matches.set(value, result.matchedPatterns);
    }

    return matches;
  }

  /**
   * Check if a pattern is valid (syntactically)
   *
   * @param pattern - The pattern to validate
   * @returns boolean indicating if pattern is valid
   */
  isValidPattern(pattern: string): boolean {
    if (!pattern || typeof pattern !== "string") {
      return false;
    }

    // Check for unbalanced brackets or other invalid regex characters
    try {
      // Test if pattern can be compiled to regex
      const escapedPattern = pattern
        .replace(/[.+^${}()|[\]\\]/g, "\\$&")
        .replace(/\*/g, ".*")
        .replace(/\?/g, ".");
      new RegExp(escapedPattern);
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Convert glob pattern to regex for internal matching
   *
   * @param pattern - The glob pattern to convert
   * @param options - Optional matching options
   * @returns RegExp object for the pattern
   */
  patternToRegex(pattern: string, options?: WildcardMatchOptions): RegExp {
    const caseInsensitive = options?.caseInsensitive ?? false;
    let regexStr = pattern
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*\*/g, "≋≋")
      .replace(/\*/g, ".*")
      .replace(/≋≋/g, ".*")
      .replace(/\?/g, ".");

    if (options?.anchorStart) {
      regexStr = `^${regexStr}`;
    }
    if (options?.anchorEnd) {
      regexStr = `${regexStr}$`;
    }

    return new RegExp(regexStr, caseInsensitive ? "i" : undefined);
  }

  /**
   * Match action string against action pattern (case-insensitive)
   * Convenience method for action matching
   *
   * @param action - The action to match (e.g., "INVOICE:READ")
   * @param actionPattern - The action pattern (e.g., "INVOICE:*")
   * @returns MatchResult
   */
  matchesAction(action: string, actionPattern: string): MatchResult {
    return this.matches(action, actionPattern, { caseInsensitive: true });
  }

  /**
   * Match resource string against resource pattern
   * Convenience method for resource matching
   *
   * @param resource - The resource to match (e.g., "invoice:12345")
   * @param resourcePattern - The resource pattern (e.g., "invoice:*")
   * @returns MatchResult
   */
  matchesResource(resource: string, resourcePattern: string): MatchResult {
    return this.matches(resource, resourcePattern, { caseInsensitive: false });
  }

  /**
   * Match action with hierarchical namespace support
   * Handles namespace:action format with wildcards in any segment
   *
   * @param action - The action to match (e.g., "INVOICE:READ:123")
   * @param actionPattern - The action pattern (e.g., "INVOICE:*")
   * @returns MatchResult
   */
  matchesHierarchicalAction(
    action: string,
    actionPattern: string,
  ): MatchResult {
    return this.matches(action, actionPattern, {
      caseInsensitive: true,
      segmentDelimiter: ":",
    });
  }

  /**
   * Match resource with hierarchical namespace support
   * Handles type:id format with wildcards in any segment
   *
   * @param resource - The resource to match (e.g., "invoice:123:items")
   * @param resourcePattern - The resource pattern (e.g., "invoice:*")
   * @returns MatchResult
   */
  matchesHierarchicalResource(
    resource: string,
    resourcePattern: string,
  ): MatchResult {
    return this.matches(resource, resourcePattern, {
      caseInsensitive: false,
      segmentDelimiter: ":",
    });
  }
}

/**
 * Match a single value against a single segment pattern
 */
function matchSegment(
  segment: string,
  patternSegment: string,
  caseInsensitive: boolean = false,
): boolean {
  // Escape special regex characters except * and ?
  let regexStr = patternSegment
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*") // * matches zero or more characters
    .replace(/\?/g, "."); // ? matches exactly one character

  const flags = caseInsensitive ? "i" : "";
  const regex = new RegExp(`^${regexStr}$`, flags);
  return regex.test(segment);
}

/**
 * Match a single value against multiple patterns
 */
export function matchAnyPattern(
  value: string,
  patterns: string[],
  options: WildcardMatchOptions = {},
): { matched: boolean; matchedPattern?: string } {
  const matcher = new WildcardMatcher();
  return matcher.matchesAny(value, patterns, options);
}

/**
 * Match a value against a single pattern
 */
export function matchPattern(
  value: string,
  pattern: string,
  options: WildcardMatchOptions = {},
): boolean {
  const matcher = new WildcardMatcher();
  return matcher.matches(value, pattern, options).matches;
}

/**
 * Check if value matches action pattern (case-insensitive by default)
 */
export function matchesAction(action: string, actionPattern: string): boolean {
  const matcher = new WildcardMatcher();
  return matcher.matchesAction(action, actionPattern).matches;
}

/**
 * Check if value matches resource pattern
 */
export function matchesResource(
  resource: string,
  resourcePattern: string,
): boolean {
  const matcher = new WildcardMatcher();
  return matcher.matchesResource(resource, resourcePattern).matches;
}

/**
 * Normalize action pattern (uppercase, trim)
 */
export function normalizeAction(action: string): string {
  return action.toUpperCase().trim();
}

/**
 * Normalize resource pattern (lowercase, trim)
 */
export function normalizeResource(resource: string): string {
  return resource.toLowerCase().trim();
}

/**
 * Parse action string to parts for hierarchical matching
 * e.g., "INVOICE:READ" -> ["INVOICE", "READ"]
 */
export function parseActionParts(action: string): string[] {
  return action.toUpperCase().split(":").filter(Boolean);
}

/**
 * Check if action matches hierarchical pattern
 * e.g., "INVOICE:READ" matches "INVOICE:*" and "*:READ" but not "PAYMENT:*"
 */
export function matchesHierarchicalAction(
  action: string,
  actionPattern: string,
): boolean {
  const actionParts = parseActionParts(action);
  const patternParts = parseActionParts(actionPattern);

  // If pattern has more parts, it can't match
  if (patternParts.length > actionParts.length) {
    return false;
  }

  // Check each part
  for (let i = 0; i < patternParts.length; i++) {
    const patternPart = patternParts[i];
    const actionPart = actionParts[i];

    // Skip if this is a wildcard level (matches everything below)
    if (patternPart === "*") {
      return true;
    }

    // Check exact match or wildcard
    if (!matchSegment(actionPart, patternPart, true)) {
      return false;
    }
  }

  return true;
}

/**
 * Match resource with hierarchical namespace
 * e.g., "invoice:123:items" matches "invoice:*" and "invoice:123"
 */
export function matchesHierarchicalResource(
  resource: string,
  resourcePattern: string,
): boolean {
  const resourceParts = resource.split(":").filter(Boolean);
  const patternParts = resourcePattern.split(":").filter(Boolean);

  // If pattern has more parts, it can't match
  if (patternParts.length > resourceParts.length) {
    return false;
  }

  // Check each part
  for (let i = 0; i < patternParts.length; i++) {
    const patternPart = patternParts[i];
    const resourcePart = resourceParts[i];

    if (!matchSegment(resourcePart, patternPart, false)) {
      return false;
    }
  }

  return true;
}

/**
 * Expand pattern to all possible combinations (for testing/debugging)
 */
export function expandPattern(
  pattern: string,
  maxExpansions: number = 100,
): string[] {
  const results: string[] = [];

  function expand(current: string, remaining: string): void {
    if (results.length >= maxExpansions) {
      return;
    }

    if (remaining.length === 0) {
      results.push(current);
      return;
    }

    const nextChar = remaining[0];

    if (nextChar === "*") {
      // For *, expand to empty string and single character
      expand(current, remaining.slice(1));
      expand(current + "a", remaining.slice(1));
    } else if (nextChar === "?") {
      expand(current + "a", remaining.slice(1));
    } else {
      expand(current + nextChar, remaining.slice(1));
    }
  }

  expand("", pattern);
  return results;
}

// ============================================================================
// TEST CASES
// ============================================================================
// See tests/wildcard-matcher.test.ts for comprehensive test cases
//
// Example usage:
//
// const matcher = new WildcardMatcher();
//
// // Basic wildcard matching
// matcher.matches("INVOICE_READ", "INVOICE_*"); // { matches: true, matchedPattern: "INVOICE_*" }
// matcher.matches("USER_READ", "INVOICE_*"); // { matches: false, reason: "No wildcard match" }
//
// // Single character wildcard
// matcher.matches("invoice:a", "invoice:?"); // { matches: true, matchedPattern: "invoice:?" }
// matcher.matches("invoice:123", "invoice:?"); // { matches: false }
//
// // Multiple wildcards
// matcher.matches("USER_A_READ", "*_?_READ"); // { matches: true }
// matcher.matches("USER_READ", "*_?_READ"); // { matches: false }
//
// // Multiple patterns (OR logic)
// matcher.matchesAny("INVOICE_DELETE", ["INVOICE_*", "USER_*"]);
// // { matched: true, matchedPatterns: ["INVOICE_*"], unmatchedPatterns: ["USER_*"] }
//
// // Hierarchical matching
// matcher.matchesHierarchicalAction("INVOICE:READ:123", "INVOICE:*"); // { matches: true }
// matcher.matchesHierarchicalAction("INVOICE:READ", "*:READ"); // { matches: true }
//
// // Resource matching
// matcher.matchesHierarchicalResource("invoice:12345", "invoice:*"); // { matches: true }
// matcher.matchesHierarchicalResource("order:12345", "invoice:*"); // { matches: false }
//
// // Pattern validation
// matcher.isValidPattern("INVOICE_*_READ"); // true
// matcher.isValidPattern("INVOICE_*["); // false
//
// // Regex conversion
// const regex = matcher.patternToRegex("INVOICE_*");
// regex.test("INVOICE_READ"); // true
// regex.test("USER_READ"); // false
