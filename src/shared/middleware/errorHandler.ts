import { Request, Response, NextFunction } from "express";
import { AppError } from "../errors/AppError";
import { logger } from "../logger";

export const errorHandler = (
  error: Error,
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  // Log the error
  logger.logError(error, req);

  // Handle AppError instances
  if (error instanceof AppError) {
    return res.status(error.statusCode).json({
      error: error.message,
      code: error.code,
      ...(error.details && { details: error.details }),
    });
  }

  // Handle validation errors
  if (error.name === "ValidationError") {
    return res.status(400).json({
      error: "Validation failed",
      code: "VALIDATION_ERROR",
      details: error.message,
    });
  }

  // Handle Prisma errors
  if (error.name === "PrismaClientKnownRequestError") {
    const prismaError = error as any;
    switch (prismaError.code) {
      case "P2002":
        return res.status(409).json({
          error: "Resource already exists",
          code: "RESOURCE_CONFLICT",
          details: "A unique constraint was violated",
        });
      case "P2025":
        return res.status(404).json({
          error: "Resource not found",
          code: "RESOURCE_NOT_FOUND",
          details: "The requested resource does not exist",
        });
      default:
        return res.status(500).json({
          error: "Database error",
          code: "DATABASE_ERROR",
        });
    }
  }

  // Handle JWT errors
  if (error.name === "JsonWebTokenError") {
    return res.status(401).json({
      error: "Invalid token",
      code: "TOKEN_INVALID",
    });
  }

  if (error.name === "TokenExpiredError") {
    return res.status(401).json({
      error: "Token expired",
      code: "TOKEN_EXPIRED",
    });
  }

  // Default error response
  res.status(500).json({
    error: "Internal server error",
    code: "INTERNAL_SERVER_ERROR",
  });
};

export const notFoundHandler = (req: Request, res: Response) => {
  res.status(404).json({
    error: "Route not found",
    code: "RESOURCE_NOT_FOUND",
    path: req.path,
    method: req.method,
  });
};
