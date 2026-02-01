import * as dotenv from "dotenv";

// Load environment variables
dotenv.config();

interface Config {
  // Server
  port: number;
  nodeEnv: string;
  appHost: string;

  // Database
  databaseUrl: string;

  // JWT
  jwtSecret: string;
  jwtRefreshSecret: string;
  jwtExpiresIn: string;
  jwtRefreshExpiresIn: string;
  jwtIssuer: string;
  jwtAudience: string;

  // Redis
  redisUrl: string;
  redisPassword?: string;

  // Rate Limiting
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;

  // Password Hashing (Argon2)
  argon2MemoryCost: number;
  argon2TimeCost: number;
  argon2Parallelism: number;

  // Account Lockout
  maxLoginAttempts: number;
  lockoutDurationMinutes: number;

  // Password Policy
  passwordMinLength: number;
  passwordRequireUppercase: boolean;
  passwordRequireLowercase: boolean;
  passwordRequireNumber: boolean;
  passwordRequireSpecial: boolean;
  passwordHistoryCount: number;

  // Session
  sessionRefreshTokenEnabled: boolean;
  sessionMaxConcurrentSessions: number;

  // Logging
  logLevel: string;
  jsonLogFormat: boolean;
  auditLogEnabled: boolean;
  auditLogRetentionDays: number;

  // SIEM Integration
  siemEnabled: boolean;
  siemEndpoint: string;
  siemApiKey?: string;
  siemFormat: string;
  siemBatchSize: number;
  siemFlushIntervalMs: number;
  siemTimeoutMs: number;
  siemRetryAttempts: number;
  siemSslEnabled: boolean;

  // Encryption
  encryptionKey: string;

  // CORS
  corsEnabled: boolean;
  corsAllowedOrigins: string[];
  corsCredentials: boolean;
  corsMethods: string[];
  corsAllowedHeaders: string[];
  corsExposedHeaders: string[];
  corsMaxAge: number;

  // Tenant
  tenantHeader: string;

  // Redis Circuit Breaker
  redisCircuitBreakerFailureThreshold: number;
  redisCircuitBreakerRecoveryTimeoutMs: number;
  redisCircuitBreakerSuccessThreshold: number;
  redisCircuitBreakerMonitoringWindowMs: number;
  redisFallbackEnabled: boolean;
  redisFallbackMaxEntries: number;
  redisFallbackTtlSeconds: number;

  // Debug
  debug: boolean;
  debugSql: boolean;
}

const config: Config = {
  // Server
  port: parseInt(process.env.PORT || "3000", 10),
  nodeEnv: process.env.NODE_ENV || "development",
  appHost: process.env.APP_HOST || "0.0.0.0",

  // Database
  databaseUrl: process.env.DATABASE_URL || "",

  // JWT
  jwtSecret: process.env.JWT_SECRET || "default-secret-change-in-production",
  jwtRefreshSecret:
    process.env.JWT_REFRESH_SECRET ||
    "default-refresh-secret-change-in-production",
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || "15m",
  jwtRefreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  jwtIssuer: process.env.JWT_ISSUER || "iam-system",
  jwtAudience: process.env.JWT_AUDIENCE || "iam-clients",

  // Redis
  redisUrl: process.env.REDIS_URL || "redis://localhost:6379",
  redisPassword: process.env.REDIS_PASSWORD,

  // Rate Limiting
  rateLimitWindowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || "900000", 10), // 15 minutes
  rateLimitMaxRequests: parseInt(
    process.env.RATE_LIMIT_MAX_REQUESTS || "100",
    10,
  ),

  // Password Hashing (Argon2)
  argon2MemoryCost: parseInt(process.env.ARGON2_MEMORY_COST || "65536", 10),
  argon2TimeCost: parseInt(process.env.ARGON2_TIME_COST || "3", 10),
  argon2Parallelism: parseInt(process.env.ARGON2_PARALLELISM || "1", 10),

  // Account Lockout
  maxLoginAttempts: parseInt(process.env.MAX_LOGIN_ATTEMPTS || "5", 10),
  lockoutDurationMinutes: parseInt(
    process.env.LOCKOUT_DURATION_MINUTES || "30",
    10,
  ),

  // Password Policy
  passwordMinLength: parseInt(process.env.PASSWORD_MIN_LENGTH || "12", 10),
  passwordRequireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE === "true",
  passwordRequireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE === "true",
  passwordRequireNumber: process.env.PASSWORD_REQUIRE_NUMBER === "true",
  passwordRequireSpecial: process.env.PASSWORD_REQUIRE_SPECIAL === "true",
  passwordHistoryCount: parseInt(process.env.PASSWORD_HISTORY_COUNT || "5", 10),

  // Session
  sessionRefreshTokenEnabled:
    process.env.SESSION_REFRESH_TOKEN_ENABLED === "true",
  sessionMaxConcurrentSessions: parseInt(
    process.env.SESSION_MAX_CONCURRENT_SESSIONS || "5",
    10,
  ),

  // Logging
  logLevel: process.env.LOG_LEVEL || "info",
  jsonLogFormat: process.env.JSON_LOG_FORMAT === "true",
  auditLogEnabled: process.env.AUDIT_LOG_ENABLED === "true",
  auditLogRetentionDays: parseInt(
    process.env.AUDIT_LOG_RETENTION_DAYS || "90",
    10,
  ),

  // SIEM Integration
  siemEnabled: process.env.SIEM_ENABLED === "true",
  siemEndpoint: process.env.SIEM_ENDPOINT || "",
  siemApiKey: process.env.SIEM_API_KEY,
  siemFormat: process.env.SIEM_FORMAT || "json",
  siemBatchSize: parseInt(process.env.SIEM_BATCH_SIZE || "100", 10),
  siemFlushIntervalMs: parseInt(
    process.env.SIEM_FLUSH_INTERVAL_MS || "30000",
    10,
  ),
  siemTimeoutMs: parseInt(process.env.SIEM_TIMEOUT_MS || "30000", 10),
  siemRetryAttempts: parseInt(process.env.SIEM_RETRY_ATTEMPTS || "3", 10),
  siemSslEnabled: process.env.SIEM_SSL_ENABLED === "true",

  // Encryption
  encryptionKey: process.env.ENCRYPTION_KEY || "",

  // CORS
  corsEnabled: process.env.CORS_ENABLED === "true",
  corsAllowedOrigins: process.env.CORS_ALLOWED_ORIGINS
    ? process.env.CORS_ALLOWED_ORIGINS.split(",").map((o) => o.trim())
    : [],
  corsCredentials: process.env.CORS_CREDENTIALS === "true",
  corsMethods: (process.env.CORS_METHODS || "GET,POST,PUT,DELETE,PATCH")
    .split(",")
    .map((m) => m.trim()),
  corsAllowedHeaders: (
    process.env.CORS_ALLOWED_HEADERS ||
    "Content-Type,Authorization,X-Correlation-ID,X-Tenant-ID"
  )
    .split(",")
    .map((h) => h.trim()),
  corsExposedHeaders: (
    process.env.CORS_EXPOSED_HEADERS || "X-Correlation-ID,X-Tenant-ID"
  )
    .split(",")
    .map((h) => h.trim()),
  corsMaxAge: parseInt(process.env.CORS_MAX_AGE || "86400", 10),

  // Tenant
  tenantHeader: process.env.TENANT_HEADER || "x-tenant-id",

  // Redis Circuit Breaker
  redisCircuitBreakerFailureThreshold: parseInt(
    process.env.REDIS_CIRCUIT_BREAKER_FAILURE_THRESHOLD || "5",
    10,
  ),
  redisCircuitBreakerRecoveryTimeoutMs: parseInt(
    process.env.REDIS_CIRCUIT_BREAKER_RECOVERY_TIMEOUT_MS || "30000",
    10,
  ),
  redisCircuitBreakerSuccessThreshold: parseInt(
    process.env.REDIS_CIRCUIT_BREAKER_SUCCESS_THRESHOLD || "2",
    10,
  ),
  redisCircuitBreakerMonitoringWindowMs: parseInt(
    process.env.REDIS_CIRCUIT_BREAKER_MONITORING_WINDOW_MS || "60000",
    10,
  ),
  redisFallbackEnabled: process.env.REDIS_FALLBACK_ENABLED === "true",
  redisFallbackMaxEntries: parseInt(
    process.env.REDIS_FALLBACK_MAX_ENTRIES || "1000",
    10,
  ),
  redisFallbackTtlSeconds: parseInt(
    process.env.REDIS_FALLBACK_TTL_SECONDS || "3600",
    10,
  ),

  // Debug
  debug: process.env.DEBUG === "true",
  debugSql: process.env.DEBUG_SQL === "true",
};

// Validate required environment variables
const requiredEnvVars = ["DATABASE_URL", "JWT_SECRET", "JWT_REFRESH_SECRET"];
const missingEnvVars = requiredEnvVars.filter((envVar) => !process.env[envVar]);

// Validate JWT secrets in production
if (process.env.NODE_ENV === "production") {
  const jwtSecret = process.env.JWT_SECRET;
  const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;

  // Check for default/placeholder values
  const defaultSecretPatterns = [
    "default-secret",
    "change-in-production",
    "your-jwt-secret-key-here",
    "your-jwt-refresh-secret-key-here",
    "secret",
    "password",
    "123456",
  ];

  const isDefaultSecret = (secret: string | undefined) => {
    if (!secret) return true;
    return defaultSecretPatterns.some((pattern) =>
      secret.toLowerCase().includes(pattern.toLowerCase()),
    );
  };

  if (isDefaultSecret(jwtSecret)) {
    throw new Error(
      "JWT_SECRET must be set to a secure value in production. " +
        "Default placeholder values are not allowed. " +
        "Generate a secure random secret using: openssl rand -base64 32",
    );
  }

  if (isDefaultSecret(jwtRefreshSecret)) {
    throw new Error(
      "JWT_REFRESH_SECRET must be set to a secure value in production. " +
        "Default placeholder values are not allowed. " +
        "Generate a secure random secret using: openssl rand -base64 32",
    );
  }

  // Validate encryption key in production
  const encryptionKey = process.env.ENCRYPTION_KEY;
  if (!encryptionKey || isDefaultSecret(encryptionKey)) {
    throw new Error(
      "ENCRYPTION_KEY must be set to a secure value in production. " +
        "Generate a secure key using: openssl rand -base64 32",
    );
  }
}

if (missingEnvVars.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missingEnvVars.join(", ")}`,
  );
}

export { config };
