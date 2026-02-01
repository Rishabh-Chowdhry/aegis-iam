import { ResponseStatus } from "./ResponseStatus";

/**
 * StatusMessage interface for defining status-to-message mappings
 * Follows Single Responsibility Principle - only defines mapping structure
 */
export interface StatusMessage {
  readonly code: ResponseStatus;
  readonly message: string;
  readonly isError: boolean;
}

/**
 * IStatusMappingProvider interface
 * Follows Open/Closed and Dependency Inversion principles
 * Allows new status mappings to be added without modifying existing code
 */
export interface IStatusMappingProvider {
  /**
   * Get the message for a given status code
   * @param statusCode - The HTTP status code
   * @returns The message associated with the status code, or default if not found
   */
  getMessage(statusCode: ResponseStatus): string;

  /**
   * Get the full status message object for a given status code
   * @param statusCode - The HTTP status code
   * @returns The StatusMessage object, or default if not found
   */
  getStatusMessage(statusCode: ResponseStatus): StatusMessage;

  /**
   * Check if a status code represents an error
   * @param statusCode - The HTTP status code
   * @returns True if the status code represents an error
   */
  isError(statusCode: ResponseStatus): boolean;

  /**
   * Get all registered status messages
   * @returns Array of all registered StatusMessage objects
   */
  getAllMessages(): StatusMessage[];
}

/**
 * DefaultStatusMappingProvider
 * Concrete implementation providing default HTTP status messages
 * Follows Open/Closed - new providers can extend this behavior
 */
export class DefaultStatusMappingProvider implements IStatusMappingProvider {
  private statusMessages: Map<number, StatusMessage>;

  constructor() {
    this.statusMessages = new Map<number, StatusMessage>([
      // Success messages
      [
        ResponseStatus.OK,
        {
          code: ResponseStatus.OK,
          message: "Request successful",
          isError: false,
        },
      ],
      [
        ResponseStatus.CREATED,
        {
          code: ResponseStatus.CREATED,
          message: "Resource created successfully",
          isError: false,
        },
      ],
      [
        ResponseStatus.NO_CONTENT,
        {
          code: ResponseStatus.NO_CONTENT,
          message: "Request successful, no content to return",
          isError: false,
        },
      ],
      // Client error messages
      [
        ResponseStatus.BAD_REQUEST,
        {
          code: ResponseStatus.BAD_REQUEST,
          message: "Bad request - invalid input provided",
          isError: true,
        },
      ],
      [
        ResponseStatus.UNAUTHORIZED,
        {
          code: ResponseStatus.UNAUTHORIZED,
          message: "Unauthorized - authentication required",
          isError: true,
        },
      ],
      [
        ResponseStatus.FORBIDDEN,
        {
          code: ResponseStatus.FORBIDDEN,
          message: "Forbidden - insufficient permissions",
          isError: true,
        },
      ],
      [
        ResponseStatus.NOT_FOUND,
        {
          code: ResponseStatus.NOT_FOUND,
          message: "Resource not found",
          isError: true,
        },
      ],
      [
        ResponseStatus.CONFLICT,
        {
          code: ResponseStatus.CONFLICT,
          message: "Conflict - resource already exists",
          isError: true,
        },
      ],
      [
        ResponseStatus.UNPROCESSABLE_ENTITY,
        {
          code: ResponseStatus.UNPROCESSABLE_ENTITY,
          message: "Unprocessable entity - validation failed",
          isError: true,
        },
      ],
      // Server error messages
      [
        ResponseStatus.INTERNAL_SERVER_ERROR,
        {
          code: ResponseStatus.INTERNAL_SERVER_ERROR,
          message: "Internal server error",
          isError: true,
        },
      ],
      [
        ResponseStatus.SERVICE_UNAVAILABLE,
        {
          code: ResponseStatus.SERVICE_UNAVAILABLE,
          message: "Service temporarily unavailable",
          isError: true,
        },
      ],
    ]);
  }

  /**
   * Get the message for a given status code
   * @param statusCode - The HTTP status code
   * @returns The message associated with the status code
   */
  getMessage(statusCode: ResponseStatus): string {
    const statusMessage = this.statusMessages.get(statusCode);
    return statusMessage?.message ?? this.getDefaultMessage(statusCode);
  }

  /**
   * Get the full status message object for a given status code
   * @param statusCode - The HTTP status code
   * @returns The StatusMessage object
   */
  getStatusMessage(statusCode: ResponseStatus): StatusMessage {
    const statusMessage = this.statusMessages.get(statusCode);
    if (statusMessage) {
      return statusMessage;
    }
    return {
      code: statusCode,
      message: this.getDefaultMessage(statusCode),
      isError: this.isError(statusCode),
    };
  }

  /**
   * Check if a status code represents an error (4xx or 5xx)
   * @param statusCode - The HTTP status code
   * @returns True if the status code represents an error
   */
  isError(statusCode: ResponseStatus): boolean {
    const statusMessage = this.statusMessages.get(statusCode);
    if (statusMessage) {
      return statusMessage.isError;
    }
    // Default: 4xx and 5xx are errors
    return statusCode >= 400;
  }

  /**
   * Get all registered status messages
   * @returns Array of all registered StatusMessage objects
   */
  getAllMessages(): StatusMessage[] {
    return Array.from(this.statusMessages.values());
  }

  /**
   * Get default message for unknown status codes
   * @param statusCode - The HTTP status code
   * @returns Default message based on status code range
   */
  private getDefaultMessage(statusCode: ResponseStatus): string {
    if (statusCode >= 100 && statusCode < 200) {
      return "Informational response";
    }
    if (statusCode >= 200 && statusCode < 300) {
      return "Request successful";
    }
    if (statusCode >= 300 && statusCode < 400) {
      return "Redirection";
    }
    if (statusCode >= 400 && statusCode < 500) {
      return "Client error";
    }
    if (statusCode >= 500) {
      return "Server error";
    }
    return "Unknown status";
  }
}

/**
 * StatusMapping class - Main facade for status message operations
 * Follows Single Responsibility Principle - provides unified interface for status mapping
 * Follows Dependency Inversion - depends on IStatusMappingProvider abstraction
 */
export class StatusMapping {
  private static instance: StatusMapping | null = null;
  private provider: IStatusMappingProvider;

  /**
   * Private constructor for singleton pattern
   * @param provider - The status mapping provider (defaults to DefaultStatusMappingProvider)
   */
  private constructor(provider?: IStatusMappingProvider) {
    this.provider = provider ?? new DefaultStatusMappingProvider();
  }

  /**
   * Get the singleton instance of StatusMapping
   * @param provider - Optional provider for dependency injection
   * @returns The singleton StatusMapping instance
   */
  static getInstance(provider?: IStatusMappingProvider): StatusMapping {
    if (!StatusMapping.instance) {
      StatusMapping.instance = new StatusMapping(provider);
    }
    return StatusMapping.instance;
  }

  /**
   * Reset the singleton instance (useful for testing)
   */
  static resetInstance(): void {
    StatusMapping.instance = null;
  }

  /**
   * Get the message for a given status code
   * @param statusCode - The HTTP status code
   * @returns The message associated with the status code
   */
  static getMessage(statusCode: ResponseStatus): string {
    return StatusMapping.getInstance().provider.getMessage(statusCode);
  }

  /**
   * Get the full status message object for a given status code
   * @param statusCode - The HTTP status code
   * @returns The StatusMessage object
   */
  static getStatusMessage(statusCode: ResponseStatus): StatusMessage {
    return StatusMapping.getInstance().provider.getStatusMessage(statusCode);
  }

  /**
   * Check if a status code represents an error
   * @param statusCode - The HTTP status code
   * @returns True if the status code represents an error
   */
  static isError(statusCode: ResponseStatus): boolean {
    return StatusMapping.getInstance().provider.isError(statusCode);
  }

  /**
   * Get all registered status messages
   * @returns Array of all registered StatusMessage objects
   */
  static getAllMessages(): StatusMessage[] {
    return StatusMapping.getInstance().provider.getAllMessages();
  }

  /**
   * Create a standardized response object
   * @param statusCode - The HTTP status code
   * @param data - Optional data to include in the response
   * @returns Standardized response object
   */
  static createResponse<T>(
    statusCode: ResponseStatus,
    data?: T,
  ): { success: boolean; message: string; statusCode: number; data?: T } {
    const message = StatusMapping.getMessage(statusCode);
    const isError = StatusMapping.isError(statusCode);

    return {
      success: !isError,
      message,
      statusCode,
      ...(data && { data }),
    };
  }

  /**
   * Create an error response object
   * @param statusCode - The HTTP status code
   * @param error - Optional error details
   * @returns Standardized error response object
   */
  static createErrorResponse(
    statusCode: ResponseStatus,
    error?: string,
  ): { success: boolean; message: string; statusCode: number; error?: string } {
    const message = error || StatusMapping.getMessage(statusCode);

    return {
      success: false,
      message,
      statusCode,
      error: message,
    };
  }
}

/**
 * Convenience function for getting status message
 * @param statusCode - The HTTP status code
 * @returns The message associated with the status code
 */
export function getStatusMessage(statusCode: ResponseStatus): string {
  return StatusMapping.getMessage(statusCode);
}

/**
 * Convenience function for creating a response
 * @param statusCode - The HTTP status code
 * @param data - Optional data to include in the response
 * @returns Standardized response object
 */
export function createStatusResponse<T>(statusCode: ResponseStatus, data?: T) {
  return StatusMapping.createResponse(statusCode, data);
}
