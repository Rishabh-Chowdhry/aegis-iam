import express from "express";
import cors from "cors";
import { createAuthRouter as authRoutes } from "./modules/auth";
import { permissionRoutes } from "./modules/permissions";
// import { rolesRoutes } from "./modules/roles";
// import { usersRoutes } from "./modules/users";
import { policiesRoutes } from "./modules/policies";
import { RedisService } from "./infrastructure/services/RedisService";
import prisma from "./infrastructure/database/prisma";
import { authenticateToken } from "./shared/middleware/auth";
import { config } from "./shared/config";
import { StructuredLogger } from "./core/logger/structuredLogger";
import { AuditLoggerService } from "./infrastructure/services/AuditLoggerService";
import { PrismaUserRepository } from "./infrastructure/repositories/PrismaUserRepository";
import { PrismaAuditLogRepository } from "./infrastructure/repositories/PrismaAuditLogRepository";

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize structured logger
const logger = StructuredLogger.getInstance({
  level: config.logLevel as "INFO" | "WARN" | "ERROR" | "DEBUG",
  jsonFormat: config.jsonLogFormat,
});

// Initialize audit logger
const auditLogger = AuditLoggerService.getInstance({
  enabled: config.auditLogEnabled,
  retentionDays: config.auditLogRetentionDays,
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS middleware
const corsOptions: cors.CorsOptions = {
  origin: (
    origin: string | undefined,
    callback: (error: Error | null, allow?: boolean) => void,
  ) => {
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      callback(null, true);
      return;
    }

    if (config.corsEnabled) {
      // In production, only allow specific origins
      if (config.nodeEnv === "production") {
        if (config.corsAllowedOrigins.includes(origin)) {
          callback(null, true);
        } else {
          logger.warn("CORS origin rejected", {
            module: "cors",
            action: "origin_rejected",
            metadata: { origin },
          });
          callback(new Error("Not allowed by CORS"));
        }
      } else {
        // In development, allow localhost origins
        if (
          origin.includes("localhost") ||
          config.corsAllowedOrigins.includes(origin)
        ) {
          callback(null, true);
        } else {
          callback(new Error("Not allowed by CORS"));
        }
      }
    } else {
      callback(new Error("CORS is disabled"));
    }
  },
  credentials: config.corsCredentials,
  methods: config.corsMethods,
  allowedHeaders: config.corsAllowedHeaders,
  exposedHeaders: config.corsExposedHeaders,
  maxAge: config.corsMaxAge,
};

app.use(cors(corsOptions));

// Correlation ID middleware
app.use((req, res, next) => {
  const correlationId =
    (req.headers["x-correlation-id"] as string) ||
    (req.headers["x-request-id"] as string) ||
    logger.generateCorrelationId();

  logger.setCorrelationId(correlationId);
  res.setHeader("x-correlation-id", correlationId);
  (req as any).correlationId = correlationId;
  next();
});

// Request logging middleware
app.use((req, res, next) => {
  const startTime = Date.now();

  res.on("finish", () => {
    const responseTime = Date.now() - startTime;
    const userId = (req as any).user?.id;
    const tenantId = (req as any).tenantId;

    logger.logRequest(
      {
        method: req.method,
        url: req.url,
        ip: req.ip || req.connection.remoteAddress,
        userAgent: req.get("User-Agent"),
        correlationId: (req as any).correlationId,
      },
      { statusCode: res.statusCode },
      responseTime,
      userId,
      tenantId,
    );
  });

  next();
});

// Rate limiting middleware
const redisService = new RedisService();
redisService.connect().catch((error) => {
  logger.error("Failed to connect to Redis", error, { module: "redis" });
});

const rateLimitMiddleware = async (
  req: express.Request,
  res: express.Response,
  next: express.NextFunction,
) => {
  const key = req.ip || req.connection.remoteAddress || "unknown";
  const allowed = await redisService.checkRateLimit(key, 100, 60000); // 100 requests per minute

  if (!allowed) {
    logger.warn("Rate limit exceeded", {
      module: "rate-limit",
      action: "rate_limit_exceeded",
      metadata: { ip: key, path: req.path },
    });
    return res.status(429).json({ error: "Too many requests" });
  }

  next();
};

app.use(rateLimitMiddleware);

// Initialize repositories for auth routes
const userRepository = new PrismaUserRepository(prisma);
const auditLogRepository = new PrismaAuditLogRepository(prisma);

// Routes
app.use("/api/auth", authRoutes(userRepository, auditLogRepository));
app.use("/api/permissions", authenticateToken, permissionRoutes);
// app.use("/api/roles", authenticateToken, rolesRoutes);
// app.use("/api/users", authenticateToken, usersRoutes);
app.use("/api/policies", authenticateToken, policiesRoutes);

// Connect to database
async function connectDatabase() {
  try {
    await prisma.$connect();
    logger.info("Database connected successfully", {
      module: "database",
      action: "connect",
    });
  } catch (error) {
    logger.error("Database connection failed", error as Error, {
      module: "database",
      action: "connect",
    });
    process.exit(1);
  }
}

// Graceful shutdown
async function shutdown(signal: string) {
  logger.info(`${signal} received, shutting down gracefully`, {
    module: "shutdown",
  });
  try {
    await redisService.disconnect();
    await prisma.$disconnect();
    logger.info("All connections closed", { module: "shutdown" });
    process.exit(0);
  } catch (error) {
    logger.error("Error during shutdown", error as Error, {
      module: "shutdown",
    });
    process.exit(1);
  }
}

// Health check
app.get("/health", async (req, res) => {
  try {
    // Check database connection by running a simple query
    await prisma.user.findFirst({ take: 1 });
    res.json({
      status: "OK",
      timestamp: new Date().toISOString(),
      database: "connected",
    });
  } catch (error) {
    logger.error("Health check failed", error as Error, { module: "health" });
    res.status(503).json({
      status: "ERROR",
      timestamp: new Date().toISOString(),
      database: "disconnected",
    });
  }
});

// Readiness probe
app.get("/ready", async (req, res) => {
  try {
    // Check database connection
    await prisma.user.findFirst({ take: 1 });

    res.json({
      status: "READY",
      timestamp: new Date().toISOString(),
      checks: {
        database: "ok",
      },
    });
  } catch (error) {
    logger.error("Readiness check failed", error as Error, {
      module: "readiness",
    });
    res.status(503).json({
      status: "NOT_READY",
      timestamp: new Date().toISOString(),
      error: "Service not ready",
    });
  }
});

// Error handling
app.use(
  (
    err: Error,
    req: express.Request,
    res: express.Response,
    next: express.NextFunction,
  ) => {
    logger.error("Unhandled error", err, {
      module: "error-handler",
      action: "unhandled_error",
      metadata: {
        method: req.method,
        url: req.url,
        ip: req.ip,
        correlationId: (req as any).correlationId,
      },
    });
    res.status(500).json({ error: "Something went wrong!" });
  },
);

// Graceful shutdown handlers
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

// Start server
async function start() {
  await connectDatabase();
  logger.info(`Server starting on port ${PORT}`, {
    module: "server",
    action: "start",
    metadata: { port: PORT },
  });

  app.listen(PORT, () => {
    logger.info(`Server is running on port ${PORT}`, {
      module: "server",
      action: "running",
    });
  });
}

start();

export { app, logger, auditLogger };
