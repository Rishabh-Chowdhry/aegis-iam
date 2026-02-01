/**
 * Audit Module Index
 *
 * Enterprise-grade audit logging and SIEM integration for the IAM platform.
 * Provides immutable audit records suitable for SOC2, ISO 27001, and enterprise audits.
 */

// Decision Logger exports
export {
  DecisionLogger,
  // Types
  AuditEvent,
  AuditEventType,
  AuditSeverity,
  SecurityEventType,
  AuditMetadata,
  LogOptions,
  AuditQuery,
  AuditLoggerConfig,
  AuditBoundaryViolation,
  ComplianceReport,
  ReportSummary,
  IAuditLogRepository,
  CryptoService,
  // Old exports for backward compatibility
  DecisionLogger as IDecisionLogger,
} from "./DecisionLogger";

// SIEM Integration exports
export {
  SIEMIntegration,
  // Configuration
  SIEMConfig,
  defaultSIEMConfig,
  // Event types
  SIEMEvent,
  SIEMResult,
  SIEMBatchResult,
  SIEMHealthResult,
  // Alert types
  AlertConfig,
  AlertCondition,
  AlertAction,
  AlertConditionOperator,
  AlertActionType,
  // HTTP types
  HttpClient,
  HttpRequestOptions,
  HttpResponse,
  // Logger types
  Logger,
} from "./SIEMIntegration";
