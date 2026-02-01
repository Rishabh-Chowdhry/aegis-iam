/**
 * Condition Evaluator for ABAC Policy Engine
 *
 * Evaluates policy conditions against authorization request context.
 * Supports AWS IAM-style condition operators with enterprise-grade reliability.
 */

import {
  PolicyCondition,
  Subject,
  Resource,
  AuthorizationContext,
  RequestContext,
} from "../policy/models/types";

// ============================================================================
// Interfaces
// ============================================================================

/**
 * Result of evaluating conditions
 */
export interface ConditionEvaluationResult {
  /** Whether all conditions are satisfied */
  isMet: boolean;
  /** List of conditions that failed evaluation */
  failedConditions: FailedCondition[];
  /** Timestamp of evaluation */
  evaluatedAt: Date;
}

/**
 * Details of a failed condition
 */
export interface FailedCondition {
  /** Condition operator that was evaluated */
  operator: string;
  /** Condition key that was evaluated */
  key: string;
  /** Expected value from the policy */
  expected: unknown;
  /** Actual value from the context */
  actual: unknown;
}

/**
 * Result of resolving a path to its value
 */
export interface PathValue {
  /** The path that was resolved */
  path: string;
  /** The resolved value */
  value: unknown;
  /** Whether the path exists in the context */
  exists: boolean;
}

// ============================================================================
// Condition Evaluator Class
// ============================================================================

/**
 * ConditionEvaluator
 *
 * Evaluates ABAC policy conditions against authorization requests.
 * Implements fail-closed behavior: if any condition cannot be evaluated,
 * the overall result is false.
 */
export class ConditionEvaluator {
  /**
   * Evaluate policy conditions against an authorization request.
   *
   * @param conditions - Policy conditions to evaluate
   * @param subject - Subject (who is making the request)
   * @param resource - Resource being accessed
   * @param context - Authorization context including request context
   * @returns ConditionEvaluationResult with evaluation outcome
   */
  evaluate(
    conditions: PolicyCondition | undefined,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): ConditionEvaluationResult {
    const startTime = Date.now();
    const failedConditions: FailedCondition[] = [];

    // If no conditions, consider them satisfied
    if (!conditions || Object.keys(conditions).length === 0) {
      return {
        isMet: true,
        failedConditions: [],
        evaluatedAt: new Date(),
      };
    }

    // Build the combined context for evaluation
    const evalContext = this.buildEvaluationContext(subject, resource, context);

    // Evaluate all condition groups (AND logic between groups)
    const conditionGroups = this.getConditionGroups(conditions);

    for (const conditionGroup of conditionGroups) {
      const groupResult = this.evaluateConditionGroup(
        conditionGroup,
        subject,
        resource,
        context,
      );

      if (!groupResult) {
        // Collect failed conditions from this group
        for (const [operator, conditionsByKey] of Object.entries(
          conditionGroup,
        )) {
          for (const [key, expectedValue] of Object.entries(
            conditionsByKey as Record<string, unknown>,
          )) {
            const actualValue = this.resolvePath(
              key,
              subject,
              resource,
              context,
            ).value;
            failedConditions.push({
              operator,
              key,
              expected: expectedValue,
              actual: actualValue,
            });
          }
        }
      }
    }

    return {
      isMet: failedConditions.length === 0,
      failedConditions,
      evaluatedAt: new Date(),
    };
  }

  /**
   * Evaluate a single condition group.
   * All conditions within a group must be satisfied (AND logic).
   *
   * @param conditionGroup - Object mapping keys to expected values
   * @param subject - Subject (who is making the request)
   * @param resource - Resource being accessed
   * @param context - Authorization context
   * @returns true if all conditions in the group are satisfied
   */
  evaluateConditionGroup(
    conditionGroup: Record<string, Record<string, unknown>>,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): boolean {
    if (!conditionGroup || Object.keys(conditionGroup).length === 0) {
      return true;
    }

    for (const [operator, conditionsByKey] of Object.entries(conditionGroup)) {
      for (const [key, expectedValue] of Object.entries(
        conditionsByKey as Record<string, unknown>,
      )) {
        const result = this.evaluateSingleCondition(
          operator,
          key,
          expectedValue,
          subject,
          resource,
          context,
        );

        if (!result) {
          return false;
        }
      }
    }

    return true;
  }

  /**
   * Evaluate a single condition.
   *
   * @param operator - Condition operator (e.g., "StringEquals")
   * @param key - Condition key (e.g., "subject.tenantId")
   * @param expectedValue - Expected value from the policy
   * @param subject - Subject (who is making the request)
   * @param resource - Resource being accessed
   * @param context - Authorization context
   * @returns true if the condition is satisfied
   */
  evaluateSingleCondition(
    operator: string,
    key: string,
    expectedValue: unknown,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): boolean {
    try {
      // Resolve the actual value from the context
      const pathValue = this.resolvePath(key, subject, resource, context);
      const actualValue = pathValue.value;

      // Handle variable substitution (e.g., "resource.tenantId" -> subject.tenantId)
      let resolvedExpected = expectedValue;
      if (typeof expectedValue === "string") {
        resolvedExpected = this.resolveVariableValue(
          expectedValue,
          subject,
          resource,
          context,
        );
      }

      // Evaluate based on operator type
      return this.applyOperator(
        operator,
        key,
        actualValue,
        resolvedExpected,
        subject,
        resource,
        context,
      );
    } catch (error) {
      // Fail-closed: any evaluation error results in false
      return false;
    }
  }

  /**
   * Resolve a dotted path to its value in the authorization context.
   *
   * @param path - Dotted path (e.g., "subject.tenantId")
   * @param subject - Subject object
   * @param resource - Resource object
   * @param context - Authorization context
   * @returns PathValue with resolved value and existence flag
   */
  resolvePath(
    path: string,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): PathValue {
    if (!path || typeof path !== "string") {
      return { path: "", value: undefined, exists: false };
    }

    const parts = path.split(".");
    const root = parts[0] as "subject" | "resource" | "context";

    switch (root) {
      case "subject":
        return this.resolveSubjectPath(parts.slice(1), subject);
      case "resource":
        return this.resolveResourcePath(parts.slice(1), resource);
      case "context":
        return this.resolveContextPath(parts.slice(1), context.context);
      default:
        return { path, value: undefined, exists: false };
    }
  }

  // ============================================================================
  // Private Methods
  // ============================================================================

  /**
   * Build a flat evaluation context from the authorization context.
   */
  private buildEvaluationContext(
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): Record<string, unknown> {
    return {
      // Subject paths
      "subject.id": subject.id,
      "subject.tenantId": subject.tenantId,
      "subject.type": subject.type,
      "subject.roles": subject.roles,
      "subject.groups": subject.groups,
      // Subject attributes
      ...this.flattenAttributes("subject.attributes", subject.attributes),
      // Resource paths
      "resource.type": resource.type,
      "resource.id": resource.id,
      "resource.ownerId": resource.ownerId,
      "resource.tenantId": resource.tenantId,
      // Resource attributes
      ...this.flattenAttributes("resource.attributes", resource.attributes),
      // Context paths
      "context.time": context.context.timestamp,
      "context.ip": context.context.ipAddress,
      "context.mfa": context.context.mfaAuthenticated,
      "context.riskScore": context.context.riskScore,
      "context.environment": context.context.environment,
      "context.requestId": context.action?.id,
      "context.sessionId": context.context.sessionId,
      "context.hour": context.context.hour,
      "context.dayOfWeek": context.context.dayOfWeek,
      // Additional context attributes
      ...this.flattenAttributes("context", context.context),
    };
  }

  /**
   * Flatten nested attributes into dotted paths.
   */
  private flattenAttributes(
    prefix: string,
    attributes?: Record<string, unknown>,
  ): Record<string, unknown> {
    if (!attributes) {
      return {};
    }

    const result: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(attributes)) {
      const path = `${prefix}.${key}`;
      if (
        typeof value === "object" &&
        value !== null &&
        !Array.isArray(value)
      ) {
        // Recursively flatten nested objects
        Object.assign(
          result,
          this.flattenAttributes(path, value as Record<string, unknown>),
        );
      } else {
        result[path] = value;
      }
    }

    return result;
  }

  /**
   * Get condition groups from policy conditions.
   */
  private getConditionGroups(
    conditions: PolicyCondition,
  ): Record<string, Record<string, unknown>>[] {
    const groups: Record<string, Record<string, unknown>>[] = [];

    // String conditions
    if (conditions.StringEquals) {
      groups.push({ StringEquals: conditions.StringEquals });
    }
    if (conditions.StringNotEquals) {
      groups.push({ StringNotEquals: conditions.StringNotEquals });
    }
    if (conditions.StringLike) {
      groups.push({ StringLike: conditions.StringLike });
    }
    if (conditions.StringNotLike) {
      groups.push({ StringNotLike: conditions.StringNotLike });
    }
    if (conditions.StringEqualsIgnoreCase) {
      groups.push({
        StringEqualsIgnoreCase: conditions.StringEqualsIgnoreCase,
      });
    }

    // Numeric conditions
    if (conditions.NumericEquals) {
      groups.push({ NumericEquals: conditions.NumericEquals });
    }
    if (conditions.NumericNotEquals) {
      groups.push({ NumericNotEquals: conditions.NumericNotEquals });
    }
    if (conditions.NumericGreaterThan) {
      groups.push({ NumericGreaterThan: conditions.NumericGreaterThan });
    }
    if (conditions.NumericGreaterThanEquals) {
      groups.push({
        NumericGreaterThanEquals: conditions.NumericGreaterThanEquals,
      });
    }
    if (conditions.NumericLessThan) {
      groups.push({ NumericLessThan: conditions.NumericLessThan });
    }
    if (conditions.NumericLessThanEquals) {
      groups.push({ NumericLessThanEquals: conditions.NumericLessThanEquals });
    }

    // Boolean conditions
    if (conditions.Bool) {
      groups.push({ Bool: conditions.Bool });
    }

    // Date conditions
    if (conditions.DateGreaterThan) {
      groups.push({ DateGreaterThan: conditions.DateGreaterThan });
    }
    if (conditions.DateLessThan) {
      groups.push({ DateLessThan: conditions.DateLessThan });
    }
    if (conditions.DateGreaterThanEquals) {
      groups.push({ DateGreaterThanEquals: conditions.DateGreaterThanEquals });
    }
    if (conditions.DateLessThanEquals) {
      groups.push({ DateLessThanEquals: conditions.DateLessThanEquals });
    }
    if (conditions.DateEquals) {
      groups.push({ DateEquals: conditions.DateEquals });
    }
    if (conditions.DateNotEquals) {
      groups.push({ DateNotEquals: conditions.DateNotEquals });
    }

    // IP address conditions
    if (conditions.IpAddress) {
      groups.push({ IpAddress: conditions.IpAddress });
    }
    if (conditions.NotIpAddress) {
      groups.push({ NotIpAddress: conditions.NotIpAddress });
    }

    // List conditions
    if (conditions.InList) {
      groups.push({ InList: conditions.InList });
    }
    if (conditions.NotInList) {
      groups.push({ NotInList: conditions.NotInList });
    }

    // Null check
    if (conditions.Null) {
      groups.push({ Null: conditions.Null });
    }

    return groups;
  }

  /**
   * Resolve a variable value that might reference another path.
   */
  private resolveVariableValue(
    value: unknown,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): unknown {
    if (typeof value !== "string") {
      return value;
    }

    // Check if value is a variable reference (starts with resource., subject., or context.)
    if (
      value.startsWith("resource.") ||
      value.startsWith("subject.") ||
      value.startsWith("context.")
    ) {
      const pathValue = this.resolvePath(value, subject, resource, context);
      if (pathValue.exists) {
        return pathValue.value;
      }
    }

    return value;
  }

  /**
   * Apply the appropriate operator to evaluate a condition.
   */
  private applyOperator(
    operator: string,
    key: string,
    actualValue: unknown,
    expectedValue: unknown,
    subject: Subject,
    resource: Resource,
    context: AuthorizationContext,
  ): boolean {
    switch (operator) {
      // String operators
      case "StringEquals":
        return this.stringEquals(actualValue, expectedValue);
      case "StringNotEquals":
        return !this.stringEquals(actualValue, expectedValue);
      case "StringEqualsIgnoreCase":
        return this.stringEqualsIgnoreCase(actualValue, expectedValue);
      case "StringLike":
        return this.stringLike(actualValue, expectedValue);
      case "StringNotLike":
        return !this.stringLike(actualValue, expectedValue);

      // Numeric operators
      case "NumericEquals":
        return this.numericEquals(actualValue, expectedValue);
      case "NumericNotEquals":
        return !this.numericEquals(actualValue, expectedValue);
      case "NumericGreaterThan":
        return this.numericGreaterThan(actualValue, expectedValue);
      case "NumericGreaterThanEquals":
        return this.numericGreaterThanOrEquals(actualValue, expectedValue);
      case "NumericLessThan":
        return this.numericLessThan(actualValue, expectedValue);
      case "NumericLessThanEquals":
        return this.numericLessThanOrEquals(actualValue, expectedValue);

      // Boolean operator
      case "Bool":
        return this.boolEquals(actualValue, expectedValue);

      // Date operators
      case "DateGreaterThan":
        return this.dateGreaterThan(actualValue, expectedValue);
      case "DateLessThan":
        return this.dateLessThan(actualValue, expectedValue);
      case "DateGreaterThanEquals":
        return this.dateGreaterThanOrEquals(actualValue, expectedValue);
      case "DateLessThanEquals":
        return this.dateLessThanOrEquals(actualValue, expectedValue);
      case "DateEquals":
        return this.dateEquals(actualValue, expectedValue);
      case "DateNotEquals":
        return !this.dateEquals(actualValue, expectedValue);

      // IP address operators
      case "IpAddress":
        return this.ipAddress(actualValue, expectedValue);
      case "NotIpAddress":
        return !this.ipAddress(actualValue, expectedValue);

      // List operators
      case "InList":
        return this.inList(actualValue, expectedValue);
      case "NotInList":
        return !this.inList(actualValue, expectedValue);

      // Null check
      case "Null":
        return this.nullCheck(actualValue, expectedValue);

      default:
        return false;
    }
  }

  // ============================================================================
  // Path Resolution Methods
  // ============================================================================

  /**
   * Resolve a path within the subject object.
   */
  private resolveSubjectPath(parts: string[], subject: Subject): PathValue {
    const path = parts.join(".");

    if (parts.length === 0) {
      return { path: "subject", value: subject, exists: true };
    }

    const root = parts[0];

    switch (root) {
      case "id":
        return { path, value: subject.id, exists: true };
      case "tenantId":
        return { path, value: subject.tenantId, exists: true };
      case "type":
        return { path, value: subject.type, exists: true };
      case "roles":
        return {
          path,
          value: subject.roles,
          exists: Array.isArray(subject.roles),
        };
      case "groups":
        return {
          path,
          value: subject.groups,
          exists: Array.isArray(subject.groups),
        };
      case "attributes":
        if (parts.length === 1) {
          return {
            path,
            value: subject.attributes,
            exists: !!subject.attributes,
          };
        }
        return this.resolveNestedValue(parts.slice(1), subject.attributes);
      default:
        // Check if it's a custom attribute
        if (subject.attributes && parts.length === 1) {
          const value = (subject.attributes as Record<string, unknown>)[root];
          return { path, value, exists: value !== undefined };
        }
        return { path, value: undefined, exists: false };
    }
  }

  /**
   * Resolve a path within the resource object.
   */
  private resolveResourcePath(parts: string[], resource: Resource): PathValue {
    const path = parts.join(".");

    if (parts.length === 0) {
      return { path: "resource", value: resource, exists: true };
    }

    const root = parts[0];

    switch (root) {
      case "type":
        return { path, value: resource.type, exists: true };
      case "id":
        return { path, value: resource.id, exists: resource.id !== undefined };
      case "ownerId":
        return {
          path,
          value: resource.ownerId,
          exists: resource.ownerId !== undefined,
        };
      case "tenantId":
        return { path, value: resource.tenantId, exists: true };
      case "parentId":
        return {
          path,
          value: resource.parentId,
          exists: resource.parentId !== undefined,
        };
      case "attributes":
        if (parts.length === 1) {
          return {
            path,
            value: resource.attributes,
            exists: !!resource.attributes,
          };
        }
        return this.resolveNestedValue(parts.slice(1), resource.attributes);
      case "labels":
        if (parts.length === 1) {
          return { path, value: resource.labels, exists: !!resource.labels };
        }
        return this.resolveNestedValue(parts.slice(1), resource.labels);
      default:
        // Check if it's a custom attribute
        if (resource.attributes && parts.length === 1) {
          const value = (resource.attributes as Record<string, unknown>)[root];
          return { path, value, exists: value !== undefined };
        }
        return { path, value: undefined, exists: false };
    }
  }

  /**
   * Resolve a path within the request context.
   */
  private resolveContextPath(
    parts: string[],
    context: RequestContext,
  ): PathValue {
    const path = parts.join(".");

    if (parts.length === 0) {
      return { path: "context", value: context, exists: true };
    }

    const root = parts[0];

    switch (root) {
      case "time":
      case "timestamp":
        return { path, value: context.timestamp, exists: !!context.timestamp };
      case "ip":
      case "ipAddress":
        return { path, value: context.ipAddress, exists: !!context.ipAddress };
      case "mfa":
      case "mfaAuthenticated":
        return {
          path,
          value: context.mfaAuthenticated,
          exists: context.mfaAuthenticated !== undefined,
        };
      case "riskScore":
        return {
          path,
          value: context.riskScore,
          exists: context.riskScore !== undefined,
        };
      case "environment":
        return {
          path,
          value: context.environment,
          exists: !!context.environment,
        };
      case "requestId":
        return { path, value: context.sessionId, exists: !!context.sessionId };
      case "sessionId":
        return { path, value: context.sessionId, exists: !!context.sessionId };
      case "hour":
        return {
          path,
          value: context.hour,
          exists: context.hour !== undefined,
        };
      case "dayOfWeek":
        return {
          path,
          value: context.dayOfWeek,
          exists: context.dayOfWeek !== undefined,
        };
      case "userAgent":
        return { path, value: context.userAgent, exists: !!context.userAgent };
      case "referer":
        return { path, value: context.referer, exists: !!context.referer };
      case "source":
        return { path, value: context.source, exists: !!context.source };
      case "location":
        if (parts.length === 1) {
          return { path, value: context.location, exists: !!context.location };
        }
        return this.resolveNestedValue(parts.slice(1), context.location);
      default:
        // Check if it's a custom context attribute
        const value = (context as Record<string, unknown>)[root];
        return { path, value, exists: value !== undefined };
    }
  }

  /**
   * Resolve a nested value from an object using path parts.
   */
  private resolveNestedValue(
    parts: string[],
    obj?: Record<string, unknown>,
  ): PathValue {
    const path = parts.join(".");

    if (!obj) {
      return { path, value: undefined, exists: false };
    }

    if (parts.length === 0) {
      return { path, value: obj, exists: true };
    }

    let current: unknown = obj;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return { path, value: undefined, exists: false };
      }

      if (typeof current === "object" && current !== null) {
        current = (current as Record<string, unknown>)[part];
      } else {
        return { path, value: undefined, exists: false };
      }
    }

    return { path, value: current, exists: current !== undefined };
  }

  // ============================================================================
  // Operator Implementation Methods
  // ============================================================================

  /**
   * StringEquals: Exact case-sensitive string match.
   */
  private stringEquals(actual: unknown, expected: unknown): boolean {
    if (typeof actual !== "string" || typeof expected !== "string") {
      return false;
    }
    return actual === expected;
  }

  /**
   * StringEqualsIgnoreCase: Case-insensitive string match.
   */
  private stringEqualsIgnoreCase(actual: unknown, expected: unknown): boolean {
    if (typeof actual !== "string" || typeof expected !== "string") {
      return false;
    }
    return actual.toLowerCase() === expected.toLowerCase();
  }

  /**
   * StringLike: Wildcard pattern matching (case-sensitive).
   * Supports * (matches any characters) and ? (matches single character).
   */
  private stringLike(actual: unknown, expected: unknown): boolean {
    if (typeof actual !== "string" || typeof expected !== "string") {
      return false;
    }

    // Convert glob pattern to regex
    const regexPattern = expected
      .replace(/[.+^${}()|[\]\\]/g, "\\$&") // Escape regex special chars
      .replace(/\*/g, ".*") // * matches any characters (including empty)
      .replace(/\?/g, "."); // ? matches exactly one character

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(actual);
  }

  /**
   * NumericEquals: Exact numeric match with type coercion.
   */
  private numericEquals(actual: unknown, expected: unknown): boolean {
    const actualNum = this.toNumber(actual);
    const expectedNum = this.toNumber(expected);

    if (actualNum === null || expectedNum === null) {
      return false;
    }

    return actualNum === expectedNum;
  }

  /**
   * NumericGreaterThan: Strict greater than comparison.
   */
  private numericGreaterThan(actual: unknown, expected: unknown): boolean {
    const actualNum = this.toNumber(actual);
    const expectedNum = this.toNumber(expected);

    if (actualNum === null || expectedNum === null) {
      return false;
    }

    return actualNum > expectedNum;
  }

  /**
   * NumericGreaterThanOrEquals: Greater than or equal comparison.
   */
  private numericGreaterThanOrEquals(
    actual: unknown,
    expected: unknown,
  ): boolean {
    const actualNum = this.toNumber(actual);
    const expectedNum = this.toNumber(expected);

    if (actualNum === null || expectedNum === null) {
      return false;
    }

    return actualNum >= expectedNum;
  }

  /**
   * NumericLessThan: Strict less than comparison.
   */
  private numericLessThan(actual: unknown, expected: unknown): boolean {
    const actualNum = this.toNumber(actual);
    const expectedNum = this.toNumber(expected);

    if (actualNum === null || expectedNum === null) {
      return false;
    }

    return actualNum < expectedNum;
  }

  /**
   * NumericLessThanOrEquals: Less than or equal comparison.
   */
  private numericLessThanOrEquals(actual: unknown, expected: unknown): boolean {
    const actualNum = this.toNumber(actual);
    const expectedNum = this.toNumber(expected);

    if (actualNum === null || expectedNum === null) {
      return false;
    }

    return actualNum <= expectedNum;
  }

  /**
   * Bool: Boolean match.
   */
  private boolEquals(actual: unknown, expected: unknown): boolean {
    if (typeof actual !== "boolean" || typeof expected !== "boolean") {
      return false;
    }
    return actual === expected;
  }

  /**
   * DateGreaterThan: Check if actual date is after expected date.
   */
  private dateGreaterThan(actual: unknown, expected: unknown): boolean {
    return this.compareDates(actual, expected) > 0;
  }

  /**
   * DateLessThan: Check if actual date is before expected date.
   */
  private dateLessThan(actual: unknown, expected: unknown): boolean {
    return this.compareDates(actual, expected) < 0;
  }

  /**
   * DateGreaterThanOrEquals: Check if actual date is after or equal to expected date.
   */
  private dateGreaterThanOrEquals(actual: unknown, expected: unknown): boolean {
    return this.compareDates(actual, expected) >= 0;
  }

  /**
   * DateLessThanOrEquals: Check if actual date is before or equal to expected date.
   */
  private dateLessThanOrEquals(actual: unknown, expected: unknown): boolean {
    return this.compareDates(actual, expected) <= 0;
  }

  /**
   * DateEquals: Check if actual date equals expected date.
   */
  private dateEquals(actual: unknown, expected: unknown): boolean {
    return this.compareDates(actual, expected) === 0;
  }

  /**
   * Compare two date values.
   * Returns negative if actual < expected, positive if actual > expected, 0 if equal.
   */
  private compareDates(actual: unknown, expected: unknown): number {
    const actualDate = this.parseDate(actual);
    const expectedDate = this.parseDate(expected);

    if (!actualDate || !expectedDate) {
      return NaN;
    }

    return actualDate.getTime() - expectedDate.getTime();
  }

  /**
   * Parse a value into a Date object.
   */
  private parseDate(value: unknown): Date | null {
    if (value instanceof Date) {
      return isNaN(value.getTime()) ? null : value;
    }

    if (typeof value !== "string") {
      return null;
    }

    const timestamp = Date.parse(value);
    if (isNaN(timestamp)) {
      return null;
    }

    return new Date(timestamp);
  }

  /**
   * IpAddress: Check if IP is in the specified range(s).
   * Supports CIDR notation and comma-separated ranges.
   */
  private ipAddress(actual: unknown, expected: unknown): boolean {
    if (typeof actual !== "string" || typeof expected !== "string") {
      return false;
    }

    // Handle comma-separated ranges
    const ranges = expected.split(",").map((r) => r.trim());

    for (const range of ranges) {
      if (this.isIPInRange(actual, range)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if an IP address is within a CIDR range or matches an IP.
   */
  private isIPInRange(ip: string, range: string): boolean {
    try {
      // Handle single IP
      if (!range.includes("/")) {
        return ip === range;
      }

      // Handle CIDR range
      return this.matchCIDR(ip, range);
    } catch {
      return false;
    }
  }

  /**
   * Match an IP address against a CIDR range.
   */
  private matchCIDR(ip: string, cidr: string): boolean {
    try {
      const [rangeIP, maskStr] = cidr.split("/");
      const mask = parseInt(maskStr, 10);

      if (isNaN(mask) || mask < 0 || mask > 32) {
        return false;
      }

      // Parse IP addresses
      const ipParts = ip.split(".").map(Number);
      const rangeParts = rangeIP.split(".").map(Number);

      if (ipParts.length !== 4 || rangeParts.length !== 4) {
        return false;
      }

      // Convert to 32-bit integers
      const ipNum =
        (ipParts[0] << 24) |
        (ipParts[1] << 16) |
        (ipParts[2] << 8) |
        ipParts[3];
      const rangeNum =
        (rangeParts[0] << 24) |
        (rangeParts[1] << 16) |
        (rangeParts[2] << 8) |
        rangeParts[3];

      // Create mask
      const maskNum = ~((1 << (32 - mask)) - 1) >>> 0;

      // Check if IPs match within the mask
      return (ipNum & maskNum) === (rangeNum & maskNum);
    } catch {
      return false;
    }
  }

  /**
   * InList: Check if actual value is in the list of expected values.
   */
  private inList(actual: unknown, expected: unknown): boolean {
    if (!Array.isArray(expected)) {
      return false;
    }

    for (const item of expected) {
      if (this.valuesEqual(actual, item)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Null: Check if value is null/undefined or exists.
   */
  private nullCheck(actual: unknown, expected: unknown): boolean {
    if (typeof expected !== "boolean") {
      return false;
    }

    const isNull = actual === null || actual === undefined;

    if (expected) {
      // Value must be null/undefined
      return isNull;
    } else {
      // Value must exist and not be null
      return !isNull;
    }
  }

  /**
   * Compare two values for equality with type coercion.
   */
  private valuesEqual(a: unknown, b: unknown): boolean {
    // Handle numeric comparison with string coercion
    const aNum = this.toNumber(a);
    const bNum = this.toNumber(b);

    if (aNum !== null && bNum !== null) {
      return aNum === bNum;
    }

    // Direct equality for other types
    return a === b;
  }

  /**
   * Convert a value to a number.
   */
  private toNumber(value: unknown): number | null {
    if (typeof value === "number") {
      return isNaN(value) ? null : value;
    }

    if (typeof value === "string") {
      const parsed = parseFloat(value);
      return isNaN(parsed) ? null : parsed;
    }

    if (value instanceof Date) {
      const parsed = value.getTime();
      return isNaN(parsed) ? null : parsed;
    }

    return null;
  }
}

// ============================================================================
// Export
// ============================================================================

export { ConditionEvaluator as default };
