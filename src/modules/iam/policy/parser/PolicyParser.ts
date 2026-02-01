/**
 * Policy Parser
 *
 * Parses and validates ABAC policy documents from JSON format.
 * Enterprise-grade parser with comprehensive validation for multi-tenant isolation.
 */

import {
  ABACPolicy,
  PolicyStatement,
  PolicyCondition,
  ActionSpec,
  ResourceSpec,
  PrincipalSpec,
  PolicyEffect,
  PrincipalType,
  PolicyVersion,
  PolicyMetadata,
} from "../models/types";

// ==================== IAM POLICY TYPE (AWS-IAM-STYLE) ====================

/**
 * AWS-IAM-style Policy interface for compatibility
 */
export interface IAMPolicy {
  version: string;
  tenantId: string;
  statements: IAMPolicyStatement[];
  metadata?: {
    description?: string;
    tags?: Record<string, string>;
    createdBy?: string;
    createdAt?: string;
    updatedBy?: string;
    updatedAt?: string;
  };
  status?: "ACTIVE" | "DEPRECATED" | "DISABLED" | "DRAFT";
}

/**
 * AWS-IAM-style Policy Statement
 */
export interface IAMPolicyStatement {
  sid: string;
  effect: "ALLOW" | "DENY";
  principal?: {
    type: PrincipalType;
    ids?: string[];
  };
  actions: string[];
  resources: string[];
  conditions?: PolicyCondition;
  description?: string;
}

// ==================== PARSE RESULT ====================

/**
 * Result of parsing an IAM policy
 */
export interface ParseResult<T> {
  success: boolean;
  data?: T;
  errors: ValidationError[];
}

/**
 * Validation error structure for policy parsing
 */
export interface ValidationError {
  field: string;
  message: string;
  path: string;
  code?: string;
}

// ==================== CUSTOM ERROR CLASSES ====================

/**
 * Base class for policy validation errors
 */
export class PolicyValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public path: string,
  ) {
    super(message);
    this.name = "PolicyValidationError";
  }
}

/**
 * Error thrown when policy version is invalid
 */
export class PolicyVersionError extends PolicyValidationError {
  constructor(version: string, message?: string) {
    super(
      message || `Invalid policy version: ${version}`,
      "version",
      "version",
    );
    this.name = "PolicyVersionError";
  }
}

/**
 * Error thrown when tenantId is missing
 */
export class MissingTenantIdError extends PolicyValidationError {
  constructor(message?: string) {
    super(
      message || "Tenant ID is required for multi-tenant isolation",
      "tenantId",
      "tenantId",
    );
    this.name = "MissingTenantIdError";
  }
}

/**
 * Error thrown when statements array is empty
 */
export class EmptyStatementsError extends PolicyValidationError {
  constructor(message?: string) {
    super(
      message || "Policy must have at least one statement",
      "statements",
      "statements",
    );
    this.name = "EmptyStatementsError";
  }
}

/**
 * Error thrown when statement SID is duplicate
 */
export class DuplicateStatementSidError extends PolicyValidationError {
  constructor(sid: string, message?: string) {
    super(
      message || `Duplicate statement ID: ${sid}`,
      "sid",
      `statements[?].sid`,
    );
    this.name = "DuplicateStatementSidError";
  }
}

/**
 * Error thrown when statement effect is invalid
 */
export class InvalidEffectError extends PolicyValidationError {
  constructor(effect: string, message?: string) {
    super(
      message || `Invalid effect: ${effect}. Must be "ALLOW" or "DENY"`,
      "effect",
      "effect",
    );
    this.name = "InvalidEffectError";
  }
}

/**
 * Error thrown when actions array is empty
 */
export class EmptyActionsError extends PolicyValidationError {
  constructor(message?: string) {
    super(message || "At least one action is required", "actions", "actions");
    this.name = "EmptyActionsError";
  }
}

/**
 * Error thrown when resources array is empty
 */
export class EmptyResourcesError extends PolicyValidationError {
  constructor(message?: string) {
    super(
      message || "At least one resource is required",
      "resources",
      "resources",
    );
    this.name = "EmptyResourcesError";
  }
}

// ==================== ERROR CODES (for backward compatibility) ====================

export const ERROR_CODES = {
  MISSING_FIELD: "MISSING_FIELD",
  INVALID_EFFECT: "INVALID_EFFECT",
  EMPTY_ACTIONS: "EMPTY_ACTIONS",
  EMPTY_RESOURCES: "EMPTY_RESOURCES",
  INVALID_VERSION: "INVALID_VERSION",
  INVALID_CONDITION_KEY: "INVALID_CONDITION_KEY",
  INVALID_CONDITION_VALUE: "INVALID_CONDITION_VALUE",
  INVALID_WILDCARD: "INVALID_WILDCARD",
  DUPLICATE_SID: "DUPLICATE_SID",
  TENANT_MISMATCH: "TENANT_MISMATCH",
  UNSUPPORTED_OPERATOR: "UNSUPPORTED_OPERATOR",
} as const;

// ==================== VALIDATION RESULT TYPES ====================

export interface ValidationWarning {
  code: string;
  field: string;
  message: string;
  path: string;
}

export interface ValidationResult {
  isValid: boolean;
  errors: ValidationError[];
  warnings: ValidationWarning[];
}

// ==================== PARSE ERROR CLASS ====================

class ParseError extends Error {
  constructor(
    message: string,
    public errors: ValidationError[] = [],
  ) {
    super(message);
    this.name = "ParseError";
  }
}

// ==================== POLICY PARSER CLASS ====================

export class PolicyParser {
  // Supported policy version
  private readonly SUPPORTED_VERSION = "2026-01-01" as PolicyVersion;

  // Valid effect values
  private readonly VALID_EFFECTS = ["ALLOW", "DENY"] as const;

  // Valid principal types
  private readonly VALID_PRINCIPAL_TYPES = [
    "User",
    "Role",
    "Group",
    "Service",
    "Anonymous",
  ] as const;

  // Valid condition operators
  private readonly VALID_CONDITION_OPERATORS = [
    // String operators
    "StringEquals",
    "StringNotEquals",
    "StringEqualsIgnoreCase",
    "StringLike",
    "StringNotLike",
    "StringStartsWith",
    "StringEndsWith",
    // Numeric operators
    "NumericEquals",
    "NumericNotEquals",
    "NumericGreaterThan",
    "NumericGreaterThanOrEquals",
    "NumericLessThan",
    "NumericLessThanOrEquals",
    // Boolean operators
    "Bool",
    // Date operators
    "DateEquals",
    "DateNotEquals",
    "DateGreaterThan",
    "DateGreaterThanOrEquals",
    "DateLessThan",
    "DateLessThanOrEquals",
    // IP operators
    "IpAddress",
    "NotIpAddress",
    // List operators
    "ListContains",
    "ListNotContains",
    "InList",
    "NotInList",
    // Null check
    "Null",
  ];

  // Valid condition key prefixes
  private readonly VALID_CONDITION_KEY_PREFIXES = [
    "subject.",
    "resource.",
    "context.",
  ];

  // ==================== PUBLIC METHODS ====================

  /**
   * Parse and validate an IAM policy JSON
   * @param policyJson - Raw JSON string or object
   * @returns ParseResult<IAMPolicy>
   */
  parse(policyJson: string | object): ParseResult<IAMPolicy> {
    let rawPolicy: Record<string, unknown>;

    // Handle both string and object input
    if (typeof policyJson === "string") {
      try {
        rawPolicy = JSON.parse(policyJson);
      } catch (error) {
        return {
          success: false,
          errors: [
            {
              field: "json",
              message: `Failed to parse JSON: ${error instanceof Error ? error.message : "Unknown error"}`,
              path: "json",
            },
          ],
        };
      }
    } else {
      rawPolicy = policyJson as Record<string, unknown>;
    }

    const errors: ValidationError[] = [];

    // Validate required fields
    if (!rawPolicy.version) {
      errors.push({
        field: "version",
        message: "Policy version is required",
        path: "version",
      });
    }

    if (!rawPolicy.tenantId) {
      errors.push({
        field: "tenantId",
        message: "Tenant ID is required for multi-tenant isolation",
        path: "tenantId",
      });
    } else if (typeof rawPolicy.tenantId !== "string") {
      errors.push({
        field: "tenantId",
        message: "Tenant ID must be a string",
        path: "tenantId",
      });
    }

    if (!rawPolicy.statements) {
      errors.push({
        field: "statements",
        message: "Policy statements are required",
        path: "statements",
      });
    } else if (!Array.isArray(rawPolicy.statements)) {
      errors.push({
        field: "statements",
        message: "Statements must be an array",
        path: "statements",
      });
    } else if (rawPolicy.statements.length === 0) {
      errors.push({
        field: "statements",
        message: "Policy must have at least one statement",
        path: "statements",
      });
    }

    if (errors.length > 0) {
      return {
        success: false,
        errors,
      };
    }

    // Validate version format
    const version = rawPolicy.version as string;
    const versionValidation = this.validateVersionRaw(version);
    if (!versionValidation.isValid) {
      return {
        success: false,
        errors: versionValidation.errors,
      };
    }

    // Parse statements
    const statementsResult = this.parseStatementsRaw(rawPolicy.statements);
    if (!statementsResult.success) {
      return {
        success: false,
        errors: statementsResult.errors,
      };
    }

    // Build IAMPolicy
    const iamPolicy: IAMPolicy = {
      version,
      tenantId: rawPolicy.tenantId as string,
      statements: statementsResult.data!,
    };

    // Parse metadata if present
    if (rawPolicy.metadata && typeof rawPolicy.metadata === "object") {
      const metadata = rawPolicy.metadata as Record<string, unknown>;
      iamPolicy.metadata = {
        description: metadata.description as string | undefined,
        tags: metadata.tags as Record<string, string> | undefined,
        createdBy: metadata.createdBy as string | undefined,
        createdAt: metadata.createdAt as string | undefined,
        updatedBy: metadata.updatedBy as string | undefined,
        updatedAt: metadata.updatedAt as string | undefined,
      };
    }

    // Set status if present
    if (rawPolicy.status) {
      iamPolicy.status = rawPolicy.status as
        | "ACTIVE"
        | "DEPRECATED"
        | "DISABLED"
        | "DRAFT";
    }

    return {
      success: true,
      data: iamPolicy,
      errors: [],
    };
  }

  /**
   * Validate a parsed policy
   * @param policy - Parsed IAMPolicy
   * @returns ValidationError[]
   */
  validate(policy: IAMPolicy): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate version
    const versionResult = this.validateVersionRaw(policy.version);
    errors.push(...versionResult.errors);

    // Validate tenantId
    if (!policy.tenantId) {
      errors.push({
        field: "tenantId",
        message: "Tenant ID is required",
        path: "tenantId",
      });
    }

    // Validate statements
    const seenSids = new Set<string>();
    for (let i = 0; i < policy.statements.length; i++) {
      const statementErrors = this.validateStatement(policy.statements[i]);
      errors.push(...statementErrors);

      // Check for duplicate SIDs
      const sid = policy.statements[i].sid;
      if (seenSids.has(sid)) {
        errors.push({
          field: "sid",
          message: `Duplicate statement ID: ${sid}`,
          path: `statements[${i}].sid`,
        });
      }
      seenSids.add(sid);
    }

    // Check for empty statements
    if (policy.statements.length === 0) {
      errors.push({
        field: "statements",
        message: "Policy must have at least one statement",
        path: "statements",
      });
    }

    return errors;
  }

  /**
   * Validate a single statement
   * @param statement - Policy statement
   * @returns ValidationError[]
   */
  validateStatement(statement: IAMPolicyStatement): ValidationError[] {
    const errors: ValidationError[] = [];

    // Validate SID
    if (!statement.sid) {
      errors.push({
        field: "sid",
        message: "Statement ID is required",
        path: "sid",
      });
    }

    // Validate effect
    if (!statement.effect) {
      errors.push({
        field: "effect",
        message: "Statement effect is required (ALLOW or DENY)",
        path: "effect",
      });
    } else if (!this.VALID_EFFECTS.includes(statement.effect)) {
      errors.push({
        field: "effect",
        message: `Invalid effect: ${statement.effect}. Must be "ALLOW" or "DENY"`,
        path: "effect",
      });
    }

    // Validate actions
    if (
      !statement.actions ||
      !Array.isArray(statement.actions) ||
      statement.actions.length === 0
    ) {
      errors.push({
        field: "actions",
        message: "At least one action is required",
        path: "actions",
      });
    } else {
      // Validate action patterns
      for (const action of statement.actions) {
        if (typeof action !== "string") {
          errors.push({
            field: "actions",
            message: "Action must be a string",
            path: "actions",
          });
        } else {
          const patternResult = this.validateWildcardPatternRaw(
            action,
            "action",
          );
          errors.push(...patternResult.errors);
        }
      }
    }

    // Validate resources
    if (
      !statement.resources ||
      !Array.isArray(statement.resources) ||
      statement.resources.length === 0
    ) {
      errors.push({
        field: "resources",
        message: "At least one resource is required",
        path: "resources",
      });
    } else {
      // Validate resource patterns
      for (const resource of statement.resources) {
        if (typeof resource !== "string") {
          errors.push({
            field: "resources",
            message: "Resource must be a string",
            path: "resources",
          });
        } else {
          const patternResult = this.validateWildcardPatternRaw(
            resource,
            "resource",
          );
          errors.push(...patternResult.errors);
        }
      }
    }

    return errors;
  }

  /**
   * Check policy version compatibility (raw string version)
   */
  private validateVersionRaw(version: string): {
    isValid: boolean;
    errors: ValidationError[];
  } {
    const errors: ValidationError[] = [];

    // Validate version format (YYYY-MM-DD)
    const versionRegex = /^\d{4}-\d{2}-\d{2}$/;
    if (!versionRegex.test(version)) {
      errors.push({
        field: "version",
        message: `Invalid version format: ${version}. Expected format: YYYY-MM-DD`,
        path: "version",
      });
      return { isValid: false, errors };
    }

    // Check if version is supported (must be 2026-01-01 or later)
    const minVersion = "2026-01-01";
    if (version < minVersion) {
      errors.push({
        field: "version",
        message: `Unsupported version: ${version}. Minimum supported version is ${minVersion}`,
        path: "version",
      });
    }

    return {
      isValid: errors.length === 0,
      errors,
    };
  }

  /**
   * Parse statements array (returns ParseResult for error handling)
   */
  private parseStatementsRaw(
    statements: unknown,
  ): ParseResult<IAMPolicyStatement[]> {
    if (!Array.isArray(statements)) {
      return {
        success: false,
        errors: [
          {
            field: "statements",
            message: "Statements must be an array",
            path: "statements",
          },
        ],
      };
    }

    if (statements.length === 0) {
      return {
        success: false,
        errors: [
          {
            field: "statements",
            message: "Policy must have at least one statement",
            path: "statements",
          },
        ],
      };
    }

    const parsedStatements: IAMPolicyStatement[] = [];
    const errors: ValidationError[] = [];

    for (let i = 0; i < statements.length; i++) {
      const stmt = statements[i];
      if (!stmt || typeof stmt !== "object") {
        errors.push({
          field: "statements",
          message: `Statement ${i} must be an object`,
          path: `statements[${i}]`,
        });
        continue;
      }

      const statement = stmt as Record<string, unknown>;

      // Validate SID
      const sid = statement.sid as string;
      if (!sid || typeof sid !== "string") {
        errors.push({
          field: "sid",
          message: `Statement ${i} must have a valid SID`,
          path: `statements[${i}].sid`,
        });
      }

      // Validate effect
      const effect = statement.effect as string;
      if (!this.VALID_EFFECTS.includes(effect as PolicyEffect)) {
        errors.push({
          field: "effect",
          message: `Statement ${sid || i} has invalid effect: ${effect}`,
          path: `statements[${i}].effect`,
        });
      }

      // Validate actions
      const actions = statement.actions;
      if (!actions || !Array.isArray(actions) || actions.length === 0) {
        errors.push({
          field: "actions",
          message: `Statement ${sid || i} must have at least one action`,
          path: `statements[${i}].actions`,
        });
      }

      // Validate resources
      const resources = statement.resources;
      if (!resources || !Array.isArray(resources) || resources.length === 0) {
        errors.push({
          field: "resources",
          message: `Statement ${sid || i} must have at least one resource`,
          path: `statements[${i}].resources`,
        });
      }

      // Parse principal (optional)
      let principal: { type: PrincipalType; ids?: string[] } | undefined;
      if (statement.principal) {
        const principalSpec = statement.principal as Record<string, unknown>;
        const type = principalSpec.type as string;
        if (
          type &&
          this.VALID_PRINCIPAL_TYPES.includes(type as PrincipalType)
        ) {
          principal = {
            type: type as PrincipalType,
            ids: Array.isArray(principalSpec.ids)
              ? (principalSpec.ids as string[])
              : undefined,
          };
        }
      }

      // Parse conditions (optional)
      let conditions: PolicyCondition | undefined;
      if (statement.conditions) {
        conditions = statement.conditions as PolicyCondition;
      }

      parsedStatements.push({
        sid: sid || `Statement${i}`,
        effect: (effect as PolicyEffect) || "ALLOW",
        principal,
        actions: (actions as string[]) || [],
        resources: (resources as string[]) || [],
        conditions,
        description: statement.description as string | undefined,
      });
    }

    if (errors.length > 0) {
      return { success: false, errors };
    }

    return { success: true, data: parsedStatements, errors: [] };
  }

  /**
   * Validate wildcard pattern (raw)
   */
  private validateWildcardPatternRaw(
    pattern: string,
    type: "action" | "resource",
  ): { isValid: boolean; errors: ValidationError[] } {
    const errors: ValidationError[] = [];

    if (!pattern || typeof pattern !== "string") {
      errors.push({
        field: type + "s",
        message: `${type} pattern must be a non-empty string`,
        path: type + "s",
      });
      return { isValid: false, errors };
    }

    // Check for invalid wildcard patterns
    if (pattern.includes("*")) {
      // Check for consecutive wildcards (invalid)
      if (pattern.includes("**")) {
        errors.push({
          field: type + "s",
          message: `Invalid wildcard pattern: ${pattern}. Consecutive wildcards are not allowed`,
          path: type + "s",
        });
      }
    }

    // Check for empty segments
    const segments = pattern.split(":");
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === "" && i > 0) {
        errors.push({
          field: type + "s",
          message: `Invalid pattern: ${pattern}. Empty segment at position ${i}`,
          path: type + "s",
        });
      }
    }

    return { isValid: errors.length === 0, errors };
  }

  /**
   * Extract tenantId from raw policy object
   */
  extractTenantId(policy: Record<string, unknown>): string {
    if (!policy.tenantId) {
      throw new MissingTenantIdError();
    }
    if (typeof policy.tenantId !== "string") {
      throw new MissingTenantIdError("tenantId must be a string");
    }
    return policy.tenantId;
  }

  // ==================== PRIVATE PARSING METHODS ====================

  /**
   * Parse policy statements
   */
  private parseStatements(statements: unknown): PolicyStatement[] {
    if (!Array.isArray(statements)) {
      throw new ParseError("Statements must be an array", [
        {
          code: ERROR_CODES.MISSING_FIELD,
          field: "statements",
          message: "Statements must be an array",
          path: "statements",
        },
      ]);
    }

    if (statements.length === 0) {
      throw new ParseError("Policy must have at least one statement", [
        {
          code: ERROR_CODES.MISSING_FIELD,
          field: "statements",
          message: "Policy must have at least one statement",
          path: "statements",
        },
      ]);
    }

    return statements.map((stmt, index) => this.parseStatement(stmt, index));
  }

  /**
   * Parse a single policy statement
   */
  private parseStatement(stmt: unknown, index: number): PolicyStatement {
    if (!stmt || typeof stmt !== "object") {
      throw new ParseError(`Statement ${index} must be an object`, [
        {
          code: ERROR_CODES.MISSING_FIELD,
          field: "statements",
          message: `Statement ${index} must be an object`,
          path: `statements[${index}]`,
        },
      ]);
    }

    const statement = stmt as Record<string, unknown>;

    // Validate SID
    const sid = statement.sid as string;
    if (!sid || typeof sid !== "string") {
      throw new ParseError(`Statement ${index} must have a valid SID`, [
        {
          code: ERROR_CODES.MISSING_FIELD,
          field: "sid",
          message: `Statement ${index} must have a valid SID`,
          path: `statements[${index}].sid`,
        },
      ]);
    }

    // Validate effect
    const effect = statement.effect as string;
    if (!this.VALID_EFFECTS.includes(effect as PolicyEffect)) {
      throw new ParseError(`Statement ${sid} has invalid effect: ${effect}`, [
        {
          code: ERROR_CODES.INVALID_EFFECT,
          field: "effect",
          message: `Statement ${sid} has invalid effect: ${effect}`,
          path: `statements[${index}].effect`,
        },
      ]);
    }

    // Parse actions
    const actions = this.parseActions(statement.actions, sid);

    // Parse resources
    const resources = this.parseResources(statement.resources, sid);

    // Parse principal (optional)
    let principal: PrincipalSpec | undefined;
    if (statement.principal) {
      principal = this.parsePrincipal(statement.principal, sid);
    }

    // Parse conditions (optional)
    let conditions: PolicyCondition | undefined;
    if (statement.conditions) {
      conditions = this.parseConditions(statement.conditions, sid);
    }

    return {
      sid,
      effect: effect as PolicyEffect,
      principal,
      actions,
      resources,
      conditions,
      description: statement.description as string | undefined,
    };
  }

  /**
   * Parse action specification
   */
  private parseActions(actions: unknown, sid: string): ActionSpec {
    // Handle array format for backward compatibility
    if (Array.isArray(actions)) {
      if (actions.length === 0) {
        throw new ParseError(`Statement ${sid} must have at least one action`, [
          {
            code: ERROR_CODES.EMPTY_ACTIONS,
            field: "actions",
            message: `Statement ${sid} must have at least one action`,
            path: `statements[?].actions`,
          },
        ]);
      }

      return {
        includes: actions.map((a) => {
          if (typeof a !== "string") {
            throw new ParseError(`Statement ${sid} has invalid action: ${a}`, [
              {
                code: ERROR_CODES.INVALID_CONDITION_VALUE,
                field: "actions",
                message: `Statement ${sid} has invalid action: ${a}`,
                path: `statements[?].actions`,
              },
            ]);
          }
          return a;
        }),
        excludes: [],
      };
    }

    // Handle object format
    if (typeof actions === "object" && actions !== null) {
      const actionSpec = actions as Record<string, unknown>;
      const includes = Array.isArray(actionSpec.includes)
        ? actionSpec.includes.map((a) => {
            if (typeof a !== "string") {
              throw new ParseError(
                `Statement ${sid} has invalid action in includes: ${a}`,
                [
                  {
                    code: ERROR_CODES.INVALID_CONDITION_VALUE,
                    field: "actions.includes",
                    message: `Statement ${sid} has invalid action in includes: ${a}`,
                    path: `statements[?].actions.includes`,
                  },
                ],
              );
            }
            return a;
          })
        : [];

      if (includes.length === 0) {
        throw new ParseError(
          `Statement ${sid} must have at least one action in includes`,
          [
            {
              code: ERROR_CODES.EMPTY_ACTIONS,
              field: "actions.includes",
              message: `Statement ${sid} must have at least one action in includes`,
              path: `statements[?].actions.includes`,
            },
          ],
        );
      }

      return {
        includes,
        excludes: Array.isArray(actionSpec.excludes)
          ? actionSpec.excludes.map((e) => {
              if (typeof e !== "string") {
                throw new ParseError(
                  `Statement ${sid} has invalid action in excludes: ${e}`,
                  [
                    {
                      code: ERROR_CODES.INVALID_CONDITION_VALUE,
                      field: "actions.excludes",
                      message: `Statement ${sid} has invalid action in excludes: ${e}`,
                      path: `statements[?].actions.excludes`,
                    },
                  ],
                );
              }
              return e;
            })
          : undefined,
        groups: Array.isArray(actionSpec.groups)
          ? actionSpec.groups.map((g) => {
              if (typeof g !== "string") {
                throw new ParseError(
                  `Statement ${sid} has invalid action group: ${g}`,
                  [
                    {
                      code: ERROR_CODES.INVALID_CONDITION_VALUE,
                      field: "actions.groups",
                      message: `Statement ${sid} has invalid action group: ${g}`,
                      path: `statements[?].actions.groups`,
                    },
                  ],
                );
              }
              return g;
            })
          : undefined,
      };
    }

    throw new ParseError(`Statement ${sid} has invalid actions format`, [
      {
        code: ERROR_CODES.MISSING_FIELD,
        field: "actions",
        message: `Statement ${sid} has invalid actions format`,
        path: `statements[?].actions`,
      },
    ]);
  }

  /**
   * Parse resource specification
   */
  private parseResources(resources: unknown, sid: string): ResourceSpec {
    // Handle string format (backward compatibility)
    if (typeof resources === "string") {
      if (!resources) {
        throw new ParseError(
          `Statement ${sid} must have at least one resource`,
          [
            {
              code: ERROR_CODES.EMPTY_RESOURCES,
              field: "resources",
              message: `Statement ${sid} must have at least one resource`,
              path: `statements[?].resources`,
            },
          ],
        );
      }

      return {
        types: [resources.split(":")[0] || resources],
        ids: resources.includes(":")
          ? [resources.split(":").slice(1).join(":")]
          : undefined,
      };
    }

    // Handle array format
    if (Array.isArray(resources)) {
      if (resources.length === 0) {
        throw new ParseError(
          `Statement ${sid} must have at least one resource`,
          [
            {
              code: ERROR_CODES.EMPTY_RESOURCES,
              field: "resources",
              message: `Statement ${sid} must have at least one resource`,
              path: `statements[?].resources`,
            },
          ],
        );
      }

      const types = new Set<string>();
      const ids: string[] = [];

      for (const r of resources) {
        if (typeof r === "string") {
          const parts = r.split(":");
          types.add(parts[0]);
          if (parts.length > 1) {
            ids.push(parts.slice(1).join(":"));
          }
        }
      }

      return {
        types: Array.from(types),
        ids: ids.length > 0 ? ids : undefined,
      };
    }

    // Handle object format
    if (typeof resources === "object" && resources !== null) {
      const resourceSpec = resources as Record<string, unknown>;

      if (
        !Array.isArray(resourceSpec.types) ||
        resourceSpec.types.length === 0
      ) {
        throw new ParseError(`Statement ${sid} must specify resource types`, [
          {
            code: ERROR_CODES.EMPTY_RESOURCES,
            field: "resources.types",
            message: `Statement ${sid} must specify resource types`,
            path: `statements[?].resources.types`,
          },
        ]);
      }

      return {
        types: resourceSpec.types.map((t) => {
          if (typeof t !== "string") {
            throw new ParseError(
              `Statement ${sid} has invalid resource type: ${t}`,
              [
                {
                  code: ERROR_CODES.INVALID_CONDITION_VALUE,
                  field: "resources.types",
                  message: `Statement ${sid} has invalid resource type: ${t}`,
                  path: `statements[?].resources.types`,
                },
              ],
            );
          }
          return t;
        }),
        ids: Array.isArray(resourceSpec.ids)
          ? resourceSpec.ids.map((i) => {
              if (typeof i !== "string") {
                throw new ParseError(
                  `Statement ${sid} has invalid resource ID: ${i}`,
                  [
                    {
                      code: ERROR_CODES.INVALID_CONDITION_VALUE,
                      field: "resources.ids",
                      message: `Statement ${sid} has invalid resource ID: ${i}`,
                      path: `statements[?].resources.ids`,
                    },
                  ],
                );
              }
              return i;
            })
          : undefined,
        paths: Array.isArray(resourceSpec.paths)
          ? resourceSpec.paths.map((p) => {
              if (typeof p !== "string") {
                throw new ParseError(
                  `Statement ${sid} has invalid resource path: ${p}`,
                  [
                    {
                      code: ERROR_CODES.INVALID_CONDITION_VALUE,
                      field: "resources.paths",
                      message: `Statement ${sid} has invalid resource path: ${p}`,
                      path: `statements[?].resources.paths`,
                    },
                  ],
                );
              }
              return p;
            })
          : undefined,
        attributes:
          (resourceSpec.attributes as Record<string, unknown>) || undefined,
      };
    }

    throw new ParseError(`Statement ${sid} has invalid resources format`, [
      {
        code: ERROR_CODES.MISSING_FIELD,
        field: "resources",
        message: `Statement ${sid} has invalid resources format`,
        path: `statements[?].resources`,
      },
    ]);
  }

  /**
   * Parse principal specification
   */
  private parsePrincipal(principal: unknown, sid: string): PrincipalSpec {
    if (!principal || typeof principal !== "object") {
      throw new ParseError(`Statement ${sid} has invalid principal`, [
        {
          code: ERROR_CODES.MISSING_FIELD,
          field: "principal",
          message: `Statement ${sid} has invalid principal`,
          path: `statements[?].principal`,
        },
      ]);
    }

    const principalSpec = principal as Record<string, unknown>;

    const type = principalSpec.type as string;
    if (!type || !this.VALID_PRINCIPAL_TYPES.includes(type as PrincipalType)) {
      throw new ParseError(
        `Statement ${sid} has invalid principal type: ${type}`,
        [
          {
            code: ERROR_CODES.MISSING_FIELD,
            field: "principal.type",
            message: `Statement ${sid} has invalid principal type: ${type}`,
            path: `statements[?].principal.type`,
          },
        ],
      );
    }

    return {
      type: type as PrincipalType,
      ids: Array.isArray(principalSpec.ids)
        ? principalSpec.ids.map((id) => {
            if (typeof id !== "string") {
              throw new ParseError(
                `Statement ${sid} has invalid principal ID: ${id}`,
                [
                  {
                    code: ERROR_CODES.INVALID_CONDITION_VALUE,
                    field: "principal.ids",
                    message: `Statement ${sid} has invalid principal ID: ${id}`,
                    path: `statements[?].principal.ids`,
                  },
                ],
              );
            }
            return id;
          })
        : undefined,
      attributes:
        (principalSpec.attributes as Record<string, unknown>) || undefined,
    };
  }

  /**
   * Parse policy conditions
   */
  private parseConditions(conditions: unknown, sid: string): PolicyCondition {
    if (!conditions || typeof conditions !== "object") {
      throw new ParseError(`Statement ${sid} has invalid conditions`, [
        {
          code: ERROR_CODES.INVALID_CONDITION_KEY,
          field: "conditions",
          message: `Statement ${sid} has invalid conditions`,
          path: `statements[?].conditions`,
        },
      ]);
    }

    const conditionBlock = conditions as Record<string, unknown>;
    const result: PolicyCondition = {};

    // Validate each condition operator
    for (const [operator, values] of Object.entries(conditionBlock)) {
      if (!this.VALID_CONDITION_OPERATORS.includes(operator)) {
        throw new ParseError(
          `Statement ${sid} has invalid condition operator: ${operator}`,
          [
            {
              code: ERROR_CODES.UNSUPPORTED_OPERATOR,
              field: "conditions",
              message: `Statement ${sid} has invalid condition operator: ${operator}`,
              path: `statements[?].conditions.${operator}`,
            },
          ],
        );
      }

      if (!values || typeof values !== "object") {
        throw new ParseError(
          `Statement ${sid} condition ${operator} must be an object`,
          [
            {
              code: ERROR_CODES.INVALID_CONDITION_VALUE,
              field: "conditions",
              message: `Statement ${sid} condition ${operator} must be an object`,
              path: `statements[?].conditions.${operator}`,
            },
          ],
        );
      }

      // Validate condition keys and values
      const conditionValues = values as Record<string, unknown>;
      for (const [key, value] of Object.entries(conditionValues)) {
        if (!this.isValidConditionKey(key)) {
          throw new ParseError(
            `Statement ${sid} has invalid condition key: ${key}`,
            [
              {
                code: ERROR_CODES.INVALID_CONDITION_KEY,
                field: "conditions",
                message: `Statement ${sid} has invalid condition key: ${key}`,
                path: `statements[?].conditions.${operator}.${key}`,
              },
            ],
          );
        }

        // Validate value type based on operator
        if (!this.isValidConditionValue(operator, value)) {
          throw new ParseError(
            `Statement ${sid} has invalid condition value for ${operator}: ${String(value)}`,
            [
              {
                code: ERROR_CODES.INVALID_CONDITION_VALUE,
                field: "conditions",
                message: `Statement ${sid} has invalid condition value for ${operator}: ${String(value)}`,
                path: `statements[?].conditions.${operator}.${key}`,
              },
            ],
          );
        }
      }

      (result as Record<string, unknown>)[operator] = values;
    }

    return result;
  }

  /**
   * Parse policy metadata
   */
  private parseMetadata(metadata: Record<string, unknown>): PolicyMetadata {
    const result: PolicyMetadata = {};

    if (metadata.description) {
      result.description = metadata.description as string;
    }

    if (metadata.tags && typeof metadata.tags === "object") {
      result.tags = metadata.tags as Record<string, string>;
    }

    if (metadata.createdBy) {
      result.createdBy = metadata.createdBy as string;
    }

    if (metadata.createdAt) {
      result.createdAt = metadata.createdAt as string;
    }

    if (metadata.updatedBy) {
      result.updatedBy = metadata.updatedBy as string;
    }

    if (metadata.updatedAt) {
      result.updatedAt = metadata.updatedAt as string;
    }

    return result;
  }

  // ==================== PRIVATE VALIDATION METHODS ====================

  /**
   * Validate condition operators
   */
  private validateConditions(
    conditions: PolicyCondition,
    path: string,
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    for (const [operator, values] of Object.entries(conditions)) {
      if (!this.VALID_CONDITION_OPERATORS.includes(operator)) {
        errors.push({
          code: ERROR_CODES.UNSUPPORTED_OPERATOR,
          field: "conditions",
          message: `Unsupported condition operator: ${operator}`,
          path: `${path}.${operator}`,
        });
        continue;
      }

      const conditionValues = values as Record<string, unknown>;
      if (!conditionValues || Object.keys(conditionValues).length === 0) {
        errors.push({
          code: ERROR_CODES.INVALID_CONDITION_VALUE,
          field: "conditions",
          message: `Condition ${operator} must have at least one key-value pair`,
          path: `${path}.${operator}`,
        });
        continue;
      }

      // Validate each condition key-value pair
      for (const [key, value] of Object.entries(conditionValues)) {
        // Validate condition key format
        if (!this.isValidConditionKey(key)) {
          errors.push({
            code: ERROR_CODES.INVALID_CONDITION_KEY,
            field: "conditions",
            message: `Invalid condition key: ${key}. Must start with subject., resource., or context.`,
            path: `${path}.${operator}.${key}`,
          });
        }

        // Validate condition value type
        if (!this.isValidConditionValue(operator, value)) {
          errors.push({
            code: ERROR_CODES.INVALID_CONDITION_VALUE,
            field: "conditions",
            message: `Invalid value type for ${operator}: expected appropriate type`,
            path: `${path}.${operator}.${key}`,
          });
        }
      }
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate condition key format
   */
  private isValidConditionKey(key: string): boolean {
    if (!key || typeof key !== "string") {
      return false;
    }

    // Check if key starts with a valid prefix
    const hasValidPrefix = this.VALID_CONDITION_KEY_PREFIXES.some((prefix) =>
      key.startsWith(prefix),
    );

    if (!hasValidPrefix) {
      return false;
    }

    // Check for empty segments (e.g., "subject..id")
    const parts = key.split(".");
    for (const part of parts) {
      if (part === "") {
        return false;
      }
    }

    return true;
  }

  /**
   * Validate condition value type based on operator
   */
  private isValidConditionValue(operator: string, value: unknown): boolean {
    // String operators expect string values
    if (operator.startsWith("String")) {
      return typeof value === "string";
    }

    // Numeric operators expect number values
    if (operator.startsWith("Numeric")) {
      return typeof value === "number";
    }

    // Boolean operators expect boolean values
    if (operator === "Bool") {
      return typeof value === "boolean";
    }

    // Date operators expect string values (ISO 8601)
    if (operator.startsWith("Date")) {
      return typeof value === "string";
    }

    // IP operators expect string values (CIDR)
    if (operator === "IpAddress" || operator === "NotIpAddress") {
      return typeof value === "string";
    }

    // List operators expect array values or single values
    if (
      operator === "ListContains" ||
      operator === "ListNotContains" ||
      operator === "InList" ||
      operator === "NotInList"
    ) {
      return (
        Array.isArray(value) ||
        typeof value === "string" ||
        typeof value === "number" ||
        typeof value === "boolean"
      );
    }

    // Null check expects boolean value
    if (operator === "Null") {
      return typeof value === "boolean";
    }

    return false;
  }

  /**
   * Validate wildcard patterns
   */
  private validateWildcardPattern(
    pattern: string,
    type: "action" | "resource",
  ): ValidationResult {
    const errors: ValidationError[] = [];
    const warnings: ValidationWarning[] = [];

    if (!pattern || typeof pattern !== "string") {
      errors.push({
        code: ERROR_CODES.INVALID_WILDCARD,
        field: type + "s",
        message: `${type} pattern must be a non-empty string`,
        path: type + "s",
      });
      return { isValid: false, errors, warnings };
    }

    // Check for invalid wildcard patterns
    if (pattern.includes("*")) {
      // Check for consecutive wildcards (invalid)
      if (pattern.includes("**")) {
        errors.push({
          code: ERROR_CODES.INVALID_WILDCARD,
          field: type + "s",
          message: `Invalid wildcard pattern: ${pattern}. Consecutive wildcards are not allowed`,
          path: type + "s",
        });
      }

      // Check for wildcards at the end without proper format
      if (pattern.endsWith("*") && pattern.length > 1) {
        const prefix = pattern.slice(0, -1);
        if (prefix.endsWith(":")) {
          warnings.push({
            code: ERROR_CODES.INVALID_WILDCARD,
            field: type + "s",
            message: `Consider using "${prefix}*" pattern for better matching`,
            path: type + "s",
          });
        }
      }
    }

    // Check for empty segments
    const segments = pattern.split(":");
    for (let i = 0; i < segments.length; i++) {
      if (segments[i] === "" && i > 0) {
        errors.push({
          code: ERROR_CODES.INVALID_WILDCARD,
          field: type + "s",
          message: `Invalid pattern: ${pattern}. Empty segment at position ${i}`,
          path: type + "s",
        });
      }
    }

    // Check for only wildcards
    if (/^\*+$/.test(pattern)) {
      warnings.push({
        code: ERROR_CODES.INVALID_WILDCARD,
        field: type + "s",
        message: `Pattern "${pattern}" matches all ${type}s. Consider using specific patterns for better security`,
        path: type + "s",
      });
    }

    return { isValid: errors.length === 0, errors, warnings };
  }

  /**
   * Validate tenantId consistency across policy conditions
   */
  private validateTenantIdConsistency(
    statements: PolicyStatement[],
    _tenantId: string,
  ): void {
    // Tenant ID consistency validation logic can be extended here
    // For now, we store the tenantId for reference in the policy object
  }

  /**
   * Add policy-level warnings
   */
  private addPolicyWarnings(
    policy: ABACPolicy,
    warnings: ValidationWarning[],
  ): void {
    // Warn if policy has no name
    if (!policy.name || policy.name === "Untitled Policy") {
      warnings.push({
        code: ERROR_CODES.MISSING_FIELD,
        field: "name",
        message: "Policy has no descriptive name",
        path: "name",
      });
    }

    // Warn if policy has DENY statements (potential security risk)
    const hasDeny = policy.statements.some((s) => s.effect === "DENY");
    if (hasDeny) {
      warnings.push({
        code: ERROR_CODES.INVALID_EFFECT,
        field: "statements",
        message:
          "Policy contains DENY statements. Ensure deny rules are properly scoped",
        path: "statements",
      });
    }

    // Warn if policy has very broad permissions
    const hasWildcardAll = policy.statements.some((s) =>
      s.actions.includes.includes("*"),
    );
    if (hasWildcardAll) {
      warnings.push({
        code: ERROR_CODES.INVALID_WILDCARD,
        field: "actions",
        message:
          "Policy grants wildcard action permissions (*). Review for security compliance",
        path: "statements",
      });
    }
  }

  /**
   * Generate a unique policy ID
   */
  private generatePolicyId(): string {
    return `policy_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
  }
}

// ==================== LEGACY FUNCTIONS (for backward compatibility) ====================

/**
 * Parse a policy document from JSON string (legacy function)
 */
export function parsePolicyDocument(json: string): ABACPolicy {
  const parser = new PolicyParser();
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch (error) {
    throw new ParseError("Failed to parse policy JSON", [
      {
        code: ERROR_CODES.INVALID_VERSION,
        field: "json",
        message: `JSON parse error: ${error instanceof Error ? error.message : "Unknown error"}`,
        path: "json",
      },
    ]);
  }

  if (!parsed || typeof parsed !== "object") {
    throw new ParseError("Policy must be an object", [
      {
        code: ERROR_CODES.MISSING_FIELD,
        field: "policy",
        message: "Parsed policy is not an object",
        path: "policy",
      },
    ]);
  }

  const result = parser.parse(parsed as Record<string, unknown>);
  if (!result.success || !result.data) {
    throw new ParseError(
      `Policy parsing failed: ${result.errors.length} error(s) found`,
      result.errors.map((e) => ({
        code: "PARSE_ERROR",
        ...e,
      })),
    );
  }

  // Convert IAMPolicy to ABACPolicy
  return convertIAMPolicyToABAC(result.data);
}

/**
 * Parse a policy from a plain object (legacy function)
 */
export function parsePolicy(obj: unknown): ABACPolicy {
  const parser = new PolicyParser();

  if (!obj || typeof obj !== "object") {
    throw new ParseError("Policy must be an object", [
      {
        code: ERROR_CODES.MISSING_FIELD,
        field: "policy",
        message: "Policy must be an object",
        path: "policy",
      },
    ]);
  }

  const result = parser.parse(obj as Record<string, unknown>);
  if (!result.success || !result.data) {
    throw new ParseError(
      `Policy parsing failed: ${result.errors.length} error(s) found`,
      result.errors.map((e) => ({
        code: "PARSE_ERROR",
        ...e,
      })),
    );
  }

  // Convert IAMPolicy to ABACPolicy
  return convertIAMPolicyToABAC(result.data);
}

/**
 * Convert IAMPolicy to ABACPolicy for backward compatibility
 */
function convertIAMPolicyToABAC(iamPolicy: IAMPolicy): ABACPolicy {
  return {
    version: iamPolicy.version as PolicyVersion,
    tenantId: iamPolicy.tenantId,
    id: `policy_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
    name: iamPolicy.metadata?.description || "Imported Policy",
    statements: iamPolicy.statements.map((stmt) => ({
      sid: stmt.sid,
      effect: stmt.effect,
      principal: stmt.principal
        ? {
            type: stmt.principal.type,
            ids: stmt.principal.ids,
          }
        : undefined,
      actions: {
        includes: stmt.actions,
      },
      resources: {
        types: stmt.resources.map((r) => r.split(":")[0] || r),
        ids: stmt.resources.some((r) => r.includes(":"))
          ? stmt.resources.map((r) =>
              r.includes(":") ? r.split(":").slice(1).join(":") : r,
            )
          : undefined,
      },
      conditions: stmt.conditions,
      description: stmt.description,
    })),
    metadata: iamPolicy.metadata
      ? {
          description: iamPolicy.metadata.description,
          tags: iamPolicy.metadata.tags,
          createdBy: iamPolicy.metadata.createdBy,
          createdAt: iamPolicy.metadata.createdAt,
          updatedBy: iamPolicy.metadata.updatedBy,
          updatedAt: iamPolicy.metadata.updatedAt,
        }
      : undefined,
    status: iamPolicy.status || "ACTIVE",
  };
}
