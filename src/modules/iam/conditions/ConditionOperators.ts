/**
 * Condition Operators for ABAC Policy Evaluation
 *
 * Implements all standard IAM condition operators including:
 * - String operators (equals, not equals, like, not like)
 * - Numeric operators (equals, greater than, less than, etc.)
 * - Boolean operators
 * - Date/Time operators (ISO 8601)
 * - IP address operators (CIDR)
 * - Null check operators
 */

import ipaddr from "ipaddr.js";

// ============================================================================
// Condition Registry Class
// ============================================================================

/**
 * ConditionRegistry
 * Centralized registry for managing condition operators
 * Provides dynamic lookup, validation, and registration of operators
 */
export class ConditionRegistry {
  private static instance: ConditionRegistry;
  private operators: Map<string, ConditionOperator>;

  private constructor() {
    this.operators = new Map();
    this.registerDefaultOperators();
  }

  /**
   * Get singleton instance
   */
  static getInstance(): ConditionRegistry {
    if (!ConditionRegistry.instance) {
      ConditionRegistry.instance = new ConditionRegistry();
    }
    return ConditionRegistry.instance;
  }

  /**
   * Register default operators
   */
  private registerDefaultOperators(): void {
    Object.entries(CONDITION_OPERATORS).forEach(([name, operator]) => {
      this.operators.set(name, operator);
    });
  }

  /**
   * Register a custom operator
   */
  register(name: string, operator: ConditionOperator): void {
    if (this.operators.has(name)) {
      throw new Error(`Operator '${name}' is already registered`);
    }
    this.operators.set(name, operator);
  }

  /**
   * Unregister an operator
   */
  unregister(name: string): boolean {
    return this.operators.delete(name);
  }

  /**
   * Get operator by name
   */
  getOperator(name: string): ConditionOperator | undefined {
    return this.operators.get(name);
  }

  /**
   * Check if operator exists
   */
  hasOperator(name: string): boolean {
    return this.operators.has(name);
  }

  /**
   * Get all operator names
   */
  getAllOperatorNames(): string[] {
    return Array.from(this.operators.keys());
  }

  /**
   * Get all operators
   */
  getAllOperators(): ConditionOperator[] {
    return Array.from(this.operators.values());
  }

  /**
   * Validate operator value type
   */
  validateOperatorValue(operatorName: string, value: unknown): boolean {
    const operator = this.getOperator(operatorName);
    if (!operator) {
      return false;
    }

    // Basic type validation based on operator category
    switch (operatorName) {
      case "StringEquals":
      case "StringEqualsIgnoreCase":
      case "StringNotEquals":
      case "StringLike":
      case "StringNotLike":
      case "ArnEquals":
      case "ArnLike":
      case "DateGreaterThan":
      case "DateLessThan":
      case "DateGreaterThanEquals":
      case "DateLessThanEquals":
      case "DateEquals":
      case "IpAddress":
      case "NotIpAddress":
      case "StringEqualsIgnoreCaseIfExists":
        return typeof value === "string";

      case "NumericEquals":
      case "NumericNotEquals":
      case "NumericGreaterThan":
      case "NumericGreaterThanEquals":
      case "NumericLessThan":
      case "NumericLessThanEquals":
        return typeof value === "number";

      case "Bool":
      case "Null":
        return typeof value === "boolean";

      case "BinaryEquals":
        return value instanceof Buffer;

      default:
        return false;
    }
  }

  /**
   * Evaluate condition using registered operator
   */
  evaluate(
    operatorName: string,
    key: string,
    value: any,
    context: Record<string, unknown>,
  ): boolean {
    const operator = this.getOperator(operatorName);
    if (!operator) {
      throw new Error(`Operator '${operatorName}' not found`);
    }

    return operator.evaluate(key, value, context);
  }

  /**
   * Get operators by category
   */
  getOperatorsByCategory(category: string): ConditionOperator[] {
    const categoryMap: Record<string, string[]> = {
      string: [
        "StringEquals",
        "StringEqualsIgnoreCase",
        "StringNotEquals",
        "StringLike",
        "StringNotLike",
        "StringEqualsIgnoreCaseIfExists",
      ],
      numeric: [
        "NumericEquals",
        "NumericNotEquals",
        "NumericGreaterThan",
        "NumericGreaterThanEquals",
        "NumericLessThan",
        "NumericLessThanEquals",
      ],
      boolean: ["Bool", "Null"],
      date: [
        "DateEquals",
        "DateGreaterThan",
        "DateLessThan",
        "DateGreaterThanEquals",
        "DateLessThanEquals",
      ],
      ip: ["IpAddress", "NotIpAddress"],
      arn: ["ArnEquals", "ArnLike"],
      binary: ["BinaryEquals"],
    };

    const operatorNames = categoryMap[category] || [];
    return operatorNames
      .map((name) => this.getOperator(name))
      .filter((op): op is ConditionOperator => op !== undefined);
  }

  /**
   * Clear all operators (useful for testing)
   */
  clear(): void {
    this.operators.clear();
  }

  /**
   * Reset to default operators
   */
  reset(): void {
    this.clear();
    this.registerDefaultOperators();
  }
}

// Export singleton instance getter
export const getConditionRegistry = (): ConditionRegistry => {
  return ConditionRegistry.getInstance();
};

// ============================================================================
// Type Aliases
// ============================================================================

type StringConditionValue = string;
type NumericConditionValue = number;
type BooleanConditionValue = boolean;
type DateConditionValue = string; // ISO 8601
type IPAddressConditionValue = string; // CIDR notation
type NullConditionValue = boolean;

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get value from context using dot notation path
 */
function getContextValue(
  key: string,
  context: Record<string, unknown>,
): unknown {
  const keys = key.split(".");
  let value: unknown = context;

  for (const k of keys) {
    if (value === null || value === undefined) {
      return undefined;
    }
    if (typeof value === "object" && value !== null) {
      value = (value as Record<string, unknown>)[k];
    } else {
      return undefined;
    }
  }

  return value;
}

/**
 * Parse IP address or CIDR range
 */
function parseIPCondition(
  value: string,
): { type: "ip" | "cidr"; ip?: string; mask?: number } | null {
  try {
    if (value.includes("/")) {
      const [ip, mask] = value.split("/");
      ipaddr.parse(ip);
      return {
        type: "cidr",
        ip: ip,
        mask: parseInt(mask, 10),
      };
    } else {
      ipaddr.parse(value);
      return {
        type: "ip",
        ip: value,
      };
    }
  } catch {
    return null;
  }
}

/**
 * Check if IP is in CIDR range
 */
function isIPInCIDR(ip: string, cidr: string): boolean {
  try {
    const range = ipaddr.parseCIDR(cidr);
    const ipAddr = ipaddr.parse(ip);
    // Check if IP version matches (IPv4 vs IPv6)
    const ipKind = ipAddr.kind();
    const rangeKind = range[0].kind();
    if (ipKind !== rangeKind) return false;

    // Use type assertion to handle the union type
    if (ipKind === "ipv4") {
      return (ipAddr as ipaddr.IPv4).match(range as [ipaddr.IPv4, number]);
    } else {
      return (ipAddr as ipaddr.IPv6).match(range as [ipaddr.IPv6, number]);
    }
  } catch {
    return false;
  }
}

/**
 * Parse ISO 8601 date string
 */
function parseDate(dateString: string): Date | null {
  const timestamp = Date.parse(dateString);
  if (isNaN(timestamp)) {
    return null;
  }
  return new Date(timestamp);
}

// ============================================================================
// String Operators
// ============================================================================

/**
 * StringEquals: Exact case-sensitive string match
 */
export function StringEquals(
  key: string,
  value: StringConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  return typeof actual === "string" && actual === value;
}

/**
 * StringEqualsIgnoreCase: Case-insensitive string match
 */
export function StringEqualsIgnoreCase(
  key: string,
  value: StringConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  return (
    typeof actual === "string" && actual.toLowerCase() === value.toLowerCase()
  );
}

/**
 * StringNotEquals: Negation of StringEquals
 */
export function StringNotEquals(
  key: string,
  value: StringConditionValue,
  context: Record<string, unknown>,
): boolean {
  return !StringEquals(key, value, context);
}

/**
 * StringLike: Case-sensitive glob pattern matching
 */
export function StringLike(
  key: string,
  value: StringConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual !== "string") {
    return false;
  }

  // Convert glob pattern to regex
  const regexPattern = value
    .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars
    .replace(/\*/g, ".*") // * matches any characters
    .replace(/\?/g, "."); // ? matches single character

  const regex = new RegExp(`^${regexPattern}$`);
  return regex.test(actual);
}

/**
 * StringNotLike: Negation of StringLike
 */
export function StringNotLike(
  key: string,
  value: StringConditionValue,
  context: Record<string, unknown>,
): boolean {
  return !StringLike(key, value, context);
}

// ============================================================================
// Numeric Operators
// ============================================================================

/**
 * NumericEquals: Exact numeric match
 */
export function NumericEquals(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual === "number") {
    return actual === value;
  }
  if (typeof actual === "string") {
    return parseFloat(actual) === value;
  }
  return false;
}

/**
 * NumericNotEquals: Negation of NumericEquals
 */
export function NumericNotEquals(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  return !NumericEquals(key, value, context);
}

/**
 * NumericGreaterThan: Strict greater than comparison
 */
export function NumericGreaterThan(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual === "number") {
    return actual > value;
  }
  if (typeof actual === "string") {
    const parsed = parseFloat(actual);
    return !isNaN(parsed) && parsed > value;
  }
  return false;
}

/**
 * NumericGreaterThanEquals: Greater than or equal comparison
 */
export function NumericGreaterThanEquals(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual === "number") {
    return actual >= value;
  }
  if (typeof actual === "string") {
    const parsed = parseFloat(actual);
    return !isNaN(parsed) && parsed >= value;
  }
  return false;
}

/**
 * NumericLessThan: Strict less than comparison
 */
export function NumericLessThan(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual === "number") {
    return actual < value;
  }
  if (typeof actual === "string") {
    const parsed = parseFloat(actual);
    return !isNaN(parsed) && parsed < value;
  }
  return false;
}

/**
 * NumericLessThanEquals: Less than or equal comparison
 */
export function NumericLessThanEquals(
  key: string,
  value: NumericConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual === "number") {
    return actual <= value;
  }
  if (typeof actual === "string") {
    const parsed = parseFloat(actual);
    return !isNaN(parsed) && parsed <= value;
  }
  return false;
}

// ============================================================================
// Boolean Operators
// ============================================================================

/**
 * Bool: Boolean match
 */
export function Bool(
  key: string,
  value: BooleanConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  return typeof actual === "boolean" && actual === value;
}

// ============================================================================
// Date/Time Operators
// ============================================================================

/**
 * DateGreaterThan: Check if context date is after specified date
 */
export function DateGreaterThan(
  key: string,
  value: DateConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualStr = getContextValue(key, context);
  if (typeof actualStr !== "string") {
    return false;
  }

  const actualDate = parseDate(actualStr);
  const compareDate = parseDate(value);

  if (!actualDate || !compareDate) {
    return false;
  }

  return actualDate.getTime() > compareDate.getTime();
}

/**
 * DateLessThan: Check if context date is before specified date
 */
export function DateLessThan(
  key: string,
  value: DateConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualStr = getContextValue(key, context);
  if (typeof actualStr !== "string") {
    return false;
  }

  const actualDate = parseDate(actualStr);
  const compareDate = parseDate(value);

  if (!actualDate || !compareDate) {
    return false;
  }

  return actualDate.getTime() < compareDate.getTime();
}

/**
 * DateGreaterThanEquals: Check if context date is after or equal to specified date
 */
export function DateGreaterThanEquals(
  key: string,
  value: DateConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualStr = getContextValue(key, context);
  if (typeof actualStr !== "string") {
    return false;
  }

  const actualDate = parseDate(actualStr);
  const compareDate = parseDate(value);

  if (!actualDate || !compareDate) {
    return false;
  }

  return actualDate.getTime() >= compareDate.getTime();
}

/**
 * DateLessThanEquals: Check if context date is before or equal to specified date
 */
export function DateLessThanEquals(
  key: string,
  value: DateConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualStr = getContextValue(key, context);
  if (typeof actualStr !== "string") {
    return false;
  }

  const actualDate = parseDate(actualStr);
  const compareDate = parseDate(value);

  if (!actualDate || !compareDate) {
    return false;
  }

  return actualDate.getTime() <= compareDate.getTime();
}

/**
 * DateEquals: Check if context date equals specified date
 */
export function DateEquals(
  key: string,
  value: DateConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualStr = getContextValue(key, context);
  if (typeof actualStr !== "string") {
    return false;
  }

  const actualDate = parseDate(actualStr);
  const compareDate = parseDate(value);

  if (!actualDate || !compareDate) {
    return false;
  }

  return actualDate.getTime() === compareDate.getTime();
}

// ============================================================================
// IP Address Operators
// ============================================================================

/**
 * IpAddress: Check if IP is in allowed range(s)
 */
export function IpAddress(
  key: string,
  value: IPAddressConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actualIP = getContextValue(key, context);
  if (typeof actualIP !== "string") {
    return false;
  }

  // Handle multiple IPs/ranges separated by comma
  const ranges = value.split(",").map((r) => r.trim());

  for (const range of ranges) {
    const parsed = parseIPCondition(range);
    if (!parsed) continue;

    if (parsed.type === "ip") {
      if (actualIP === parsed.ip) return true;
    } else if (parsed.type === "cidr") {
      if (isIPInCIDR(actualIP, range)) return true;
    }
  }

  return false;
}

/**
 * NotIpAddress: Check if IP is NOT in specified range(s)
 */
export function NotIpAddress(
  key: string,
  value: IPAddressConditionValue,
  context: Record<string, unknown>,
): boolean {
  return !IpAddress(key, value, context);
}

// ============================================================================
// Null Check Operators
// ============================================================================

/**
 * Null: Check if attribute is null or absent
 * If value is true: checks if attribute is null/undefined (attribute must not exist)
 * If value is false: checks if attribute exists and is not null
 */
export function Null(
  key: string,
  value: NullConditionValue,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);

  if (value === true) {
    // Check that attribute is null/undefined (doesn't exist)
    return actual === null || actual === undefined;
  } else {
    // Check that attribute exists and is not null
    return actual !== null && actual !== undefined;
  }
}

// ============================================================================
// ARN Operators (for AWS-style resource matching)
// ============================================================================

/**
 * ArnEquals: Exact ARN match
 */
export function ArnEquals(
  key: string,
  value: string,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  return typeof actual === "string" && actual === value;
}

/**
 * ArnLike: ARN pattern matching with wildcards
 */
export function ArnLike(
  key: string,
  value: string,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);
  if (typeof actual !== "string") {
    return false;
  }

  // ARN format: arn:partition:service:region:account-id:resource-type:resource-id
  // Support wildcards in any segment
  const actualParts = actual.split(":");
  const valueParts = value.split(":");

  if (actualParts.length !== 7 || valueParts.length !== 7) {
    return false;
  }

  for (let i = 0; i < 7; i++) {
    const actualPart = actualParts[i];
    const valuePart = valueParts[i];

    // Convert glob pattern to regex for this segment
    const regexPattern = valuePart
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, ".*")
      .replace(/\?/g, ".");

    const regex = new RegExp(`^${regexPattern}$`);
    if (!regex.test(actualPart)) {
      return false;
    }
  }

  return true;
}

// ============================================================================
// Binary Operators (for content comparison)
// ============================================================================

/**
 * BinaryEquals: Compare binary data
 */
export function BinaryEquals(
  key: string,
  value: Buffer,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);

  if (actual instanceof Buffer) {
    return actual.equals(value);
  }

  if (actual instanceof Uint8Array) {
    const actualBuffer = Buffer.from(actual);
    return actualBuffer.equals(value);
  }

  return false;
}

// ============================================================================
// Conditional Exists Operators (if attribute exists, check condition)
// ============================================================================

/**
 * StringEqualsIgnoreCaseIfExists: Case-insensitive match only if attribute exists
 */
export function StringEqualsIgnoreCaseIfExists(
  key: string,
  value: string,
  context: Record<string, unknown>,
): boolean {
  const actual = getContextValue(key, context);

  // If attribute doesn't exist, condition is vacuously true
  if (actual === null || actual === undefined) {
    return true;
  }

  return StringEqualsIgnoreCase(key, value, context);
}

// ============================================================================
// Operator Registry (for dynamic lookup)
// ============================================================================

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type EvaluateFunction = (
  key: string,
  value: any,
  context: Record<string, unknown>,
) => boolean;

export interface ConditionOperator {
  name: string;
  evaluate: EvaluateFunction;
}

export const CONDITION_OPERATORS: Record<string, ConditionOperator> = {
  StringEquals: {
    name: "StringEquals",
    evaluate: StringEquals,
  },
  StringEqualsIgnoreCase: {
    name: "StringEqualsIgnoreCase",
    evaluate: StringEqualsIgnoreCase,
  },
  StringNotEquals: {
    name: "StringNotEquals",
    evaluate: StringNotEquals,
  },
  StringLike: {
    name: "StringLike",
    evaluate: StringLike,
  },
  StringNotLike: {
    name: "StringNotLike",
    evaluate: StringNotLike,
  },
  NumericEquals: {
    name: "NumericEquals",
    evaluate: NumericEquals,
  },
  NumericNotEquals: {
    name: "NumericNotEquals",
    evaluate: NumericNotEquals,
  },
  NumericGreaterThan: {
    name: "NumericGreaterThan",
    evaluate: NumericGreaterThan,
  },
  NumericGreaterThanEquals: {
    name: "NumericGreaterThanEquals",
    evaluate: NumericGreaterThanEquals,
  },
  NumericLessThan: {
    name: "NumericLessThan",
    evaluate: NumericLessThan,
  },
  NumericLessThanEquals: {
    name: "NumericLessThanEquals",
    evaluate: NumericLessThanEquals,
  },
  Bool: {
    name: "Bool",
    evaluate: Bool,
  },
  DateGreaterThan: {
    name: "DateGreaterThan",
    evaluate: DateGreaterThan,
  },
  DateLessThan: {
    name: "DateLessThan",
    evaluate: DateLessThan,
  },
  DateGreaterThanEquals: {
    name: "DateGreaterThanEquals",
    evaluate: DateGreaterThanEquals,
  },
  DateLessThanEquals: {
    name: "DateLessThanEquals",
    evaluate: DateLessThanEquals,
  },
  DateEquals: {
    name: "DateEquals",
    evaluate: DateEquals,
  },
  IpAddress: {
    name: "IpAddress",
    evaluate: IpAddress,
  },
  NotIpAddress: {
    name: "NotIpAddress",
    evaluate: NotIpAddress,
  },
  Null: {
    name: "Null",
    evaluate: Null,
  },
  ArnEquals: {
    name: "ArnEquals",
    evaluate: ArnEquals,
  },
  ArnLike: {
    name: "ArnLike",
    evaluate: ArnLike,
  },
  BinaryEquals: {
    name: "BinaryEquals",
    evaluate: BinaryEquals,
  },
  StringEqualsIgnoreCaseIfExists: {
    name: "StringEqualsIgnoreCaseIfExists",
    evaluate: StringEqualsIgnoreCaseIfExists,
  },
};

/**
 * Get operator by name
 */
export function getOperator(name: string): ConditionOperator | undefined {
  return CONDITION_OPERATORS[name];
}

/**
 * Check if operator exists
 */
export function hasOperator(name: string): boolean {
  return name in CONDITION_OPERATORS;
}

/**
 * Get all operator names
 */
export function getAllOperatorNames(): string[] {
  return Object.keys(CONDITION_OPERATORS);
}

/**
 * Validate operator value type
 */
export function validateOperatorValue(
  operatorName: string,
  value: unknown,
): boolean {
  const operator = getOperator(operatorName);
  if (!operator) {
    return false;
  }

  // Basic type validation based on operator category
  switch (operatorName) {
    case "StringEquals":
    case "StringEqualsIgnoreCase":
    case "StringNotEquals":
    case "StringLike":
    case "StringNotLike":
    case "ArnEquals":
    case "ArnLike":
    case "DateGreaterThan":
    case "DateLessThan":
    case "DateGreaterThanEquals":
    case "DateLessThanEquals":
    case "DateEquals":
    case "IpAddress":
    case "NotIpAddress":
      return typeof value === "string";

    case "NumericEquals":
    case "NumericNotEquals":
    case "NumericGreaterThan":
    case "NumericGreaterThanEquals":
    case "NumericLessThan":
    case "NumericLessThanEquals":
      return typeof value === "number";

    case "Bool":
      return typeof value === "boolean";

    case "Null":
      return typeof value === "boolean";

    case "BinaryEquals":
      return value instanceof Buffer;

    case "StringEqualsIgnoreCaseIfExists":
      return typeof value === "string";

    default:
      return false;
  }
}
