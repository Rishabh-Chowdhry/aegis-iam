/**
 * Path Resolver
 *
 * Resolves variable paths in authorization context to actual values.
 * Supports dot notation for nested properties.
 */

import { AuthorizationContext } from "../policy/models/types";

/**
 * Path Resolver
 */
export class PathResolver {
  /**
   * Resolve a variable path to its value in the context
   *
   * @param path - Variable path (e.g., "subject.department")
   * @param context - Authorization context
   * @returns Resolved value or undefined if not found
   */
  resolve(path: string, context: AuthorizationContext): unknown {
    if (!path || !context) {
      return undefined;
    }

    // Handle variable substitution syntax ${...}
    if (path.startsWith("${") && path.endsWith("}")) {
      const innerPath = path.slice(2, -1);
      return this.resolveVariable(innerPath, context);
    }

    return this.resolveVariable(path, context);
  }

  /**
   * Resolve a variable path without substitution syntax
   */
  private resolveVariable(
    path: string,
    context: AuthorizationContext,
  ): unknown {
    const parts = path.split(".");
    let current: unknown = context;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }

      if (typeof current === "object" && current !== null) {
        // Handle special cases
        if (part === "subject") {
          current = context.subject;
        } else if (part === "action") {
          current = context.action;
        } else if (part === "resource") {
          current = context.resource;
        } else if (part === "context") {
          current = context.context;
        } else if (part === "attributes") {
          // Skip attributes in path - will be handled in next iteration
          current = (current as Record<string, unknown>)[part];
        } else {
          current = (current as Record<string, unknown>)[part];
        }
      } else {
        return undefined;
      }
    }

    return current;
  }

  /**
   * Get all variables that would be resolved from a path
   */
  getResolvedVariables(path: string): string[] {
    if (path.startsWith("${") && path.endsWith("}")) {
      return [path.slice(2, -1)];
    }
    return [path];
  }
}
