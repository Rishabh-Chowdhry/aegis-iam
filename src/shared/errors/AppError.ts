export enum ErrorCode {
  // Authentication errors
  INVALID_CREDENTIALS = "INVALID_CREDENTIALS",
  TOKEN_EXPIRED = "TOKEN_EXPIRED",
  TOKEN_INVALID = "TOKEN_INVALID",
  TOKEN_MISSING = "TOKEN_MISSING",
  REFRESH_TOKEN_INVALID = "REFRESH_TOKEN_INVALID",
  USER_NOT_FOUND = "USER_NOT_FOUND",
  USER_INACTIVE = "USER_INACTIVE",
  USER_SUSPENDED = "USER_SUSPENDED",

  // Authorization errors
  INSUFFICIENT_PERMISSIONS = "INSUFFICIENT_PERMISSIONS",
  ROLE_NOT_FOUND = "ROLE_NOT_FOUND",
  PERMISSION_NOT_FOUND = "PERMISSION_NOT_FOUND",
  POLICY_DENIED = "POLICY_DENIED",

  // Validation errors
  VALIDATION_ERROR = "VALIDATION_ERROR",
  INVALID_EMAIL = "INVALID_EMAIL",
  INVALID_PASSWORD = "INVALID_PASSWORD",
  REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING",

  // Resource errors
  RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND",
  RESOURCE_ALREADY_EXISTS = "RESOURCE_ALREADY_EXISTS",
  RESOURCE_CONFLICT = "RESOURCE_CONFLICT",

  // System errors
  INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR",
  DATABASE_ERROR = "DATABASE_ERROR",
  REDIS_ERROR = "REDIS_ERROR",
  EXTERNAL_SERVICE_ERROR = "EXTERNAL_SERVICE_ERROR",

  // Rate limiting
  RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED",

  // Tenant errors
  TENANT_NOT_FOUND = "TENANT_NOT_FOUND",
  TENANT_INVALID = "TENANT_INVALID",
}

export class AppError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly isOperational: boolean;
  public readonly details?: any;

  constructor(
    code: ErrorCode,
    message: string,
    statusCode: number = 500,
    isOperational: boolean = true,
    details?: any,
  ) {
    super(message);
    this.code = code;
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.details = details;

    // Maintains proper stack trace for where our error was thrown
    Error.captureStackTrace(this, this.constructor);
  }

  static fromErrorCode(
    code: ErrorCode,
    message?: string,
    details?: any,
  ): AppError {
    const errorConfig = ERROR_STATUS_MAP[code];
    return new AppError(
      code,
      message || errorConfig.defaultMessage,
      errorConfig.statusCode,
      true,
      details,
    );
  }
}

// Status code mapping for error codes
const ERROR_STATUS_MAP: Record<
  ErrorCode,
  { statusCode: number; defaultMessage: string }
> = {
  // Authentication errors (400-401)
  [ErrorCode.INVALID_CREDENTIALS]: {
    statusCode: 401,
    defaultMessage: "Invalid credentials provided",
  },
  [ErrorCode.TOKEN_EXPIRED]: {
    statusCode: 401,
    defaultMessage: "Token has expired",
  },
  [ErrorCode.TOKEN_INVALID]: {
    statusCode: 401,
    defaultMessage: "Invalid token provided",
  },
  [ErrorCode.TOKEN_MISSING]: {
    statusCode: 401,
    defaultMessage: "Authentication token is required",
  },
  [ErrorCode.REFRESH_TOKEN_INVALID]: {
    statusCode: 401,
    defaultMessage: "Invalid refresh token",
  },
  [ErrorCode.USER_NOT_FOUND]: {
    statusCode: 401,
    defaultMessage: "User not found",
  },
  [ErrorCode.USER_INACTIVE]: {
    statusCode: 401,
    defaultMessage: "User account is inactive",
  },
  [ErrorCode.USER_SUSPENDED]: {
    statusCode: 401,
    defaultMessage: "User account is suspended",
  },

  // Authorization errors (403)
  [ErrorCode.INSUFFICIENT_PERMISSIONS]: {
    statusCode: 403,
    defaultMessage: "Insufficient permissions",
  },
  [ErrorCode.ROLE_NOT_FOUND]: {
    statusCode: 404,
    defaultMessage: "Role not found",
  },
  [ErrorCode.PERMISSION_NOT_FOUND]: {
    statusCode: 404,
    defaultMessage: "Permission not found",
  },
  [ErrorCode.POLICY_DENIED]: {
    statusCode: 403,
    defaultMessage: "Policy denied access",
  },

  // Validation errors (400)
  [ErrorCode.VALIDATION_ERROR]: {
    statusCode: 400,
    defaultMessage: "Validation failed",
  },
  [ErrorCode.INVALID_EMAIL]: {
    statusCode: 400,
    defaultMessage: "Invalid email format",
  },
  [ErrorCode.INVALID_PASSWORD]: {
    statusCode: 400,
    defaultMessage: "Invalid password",
  },
  [ErrorCode.REQUIRED_FIELD_MISSING]: {
    statusCode: 400,
    defaultMessage: "Required field is missing",
  },

  // Resource errors (404, 409)
  [ErrorCode.RESOURCE_NOT_FOUND]: {
    statusCode: 404,
    defaultMessage: "Resource not found",
  },
  [ErrorCode.RESOURCE_ALREADY_EXISTS]: {
    statusCode: 409,
    defaultMessage: "Resource already exists",
  },
  [ErrorCode.RESOURCE_CONFLICT]: {
    statusCode: 409,
    defaultMessage: "Resource conflict",
  },

  // System errors (500)
  [ErrorCode.INTERNAL_SERVER_ERROR]: {
    statusCode: 500,
    defaultMessage: "Internal server error",
  },
  [ErrorCode.DATABASE_ERROR]: {
    statusCode: 500,
    defaultMessage: "Database error occurred",
  },
  [ErrorCode.REDIS_ERROR]: {
    statusCode: 500,
    defaultMessage: "Redis error occurred",
  },
  [ErrorCode.EXTERNAL_SERVICE_ERROR]: {
    statusCode: 500,
    defaultMessage: "External service error",
  },

  // Rate limiting (429)
  [ErrorCode.RATE_LIMIT_EXCEEDED]: {
    statusCode: 429,
    defaultMessage: "Rate limit exceeded",
  },

  // Tenant errors (400)
  [ErrorCode.TENANT_NOT_FOUND]: {
    statusCode: 400,
    defaultMessage: "Tenant not found",
  },
  [ErrorCode.TENANT_INVALID]: {
    statusCode: 400,
    defaultMessage: "Invalid tenant",
  },
};

export { ERROR_STATUS_MAP };
