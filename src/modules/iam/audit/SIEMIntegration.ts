/**
 * SIEM Integration Service
 *
 * Enterprise-grade integration with Security Information and Event Management (SIEM) systems
 * for forwarding audit logs and security events in real-time.
 * Supports multiple formats: JSON, CEF (Common Event Format), LEEF (Log Event Extended Format).
 */

import * as crypto from "crypto";
import { AuditEvent, AuditSeverity } from "./DecisionLogger";

// ==================== UTILITY FUNCTIONS ====================

/**
 * Generate a UUID v4
 */
function generateUUID(): string {
  return crypto.randomUUID();
}

// ==================== SIEM CONFIGURATION ====================

/**
 * SIEM configuration interface
 */
export interface SIEMConfig {
  /** SIEM endpoint URL */
  endpoint: string;

  /** Output format (json, cef, leef, syslog) */
  format: "json" | "cef" | "leef" | "syslog";

  /** API key for authentication (optional) */
  apiKey?: string;

  /** Enable/disable SIEM forwarding */
  enabled: boolean;

  /** Batch size for sending logs */
  batchSize: number;

  /** Flush interval in milliseconds */
  flushInterval: number;

  /** Maximum retry attempts */
  retryAttempts: number;

  /** Retry delay in milliseconds */
  retryDelay: number;

  /** Enable SSL/TLS */
  sslEnabled: boolean;

  /** Path to SSL certificate (optional) */
  certPath?: string;

  /** Custom headers */
  customHeaders?: Record<string, string>;

  /** Timeout for HTTP requests (ms) */
  timeout: number;
}

/**
 * Default SIEM configuration
 */
export const defaultSIEMConfig: Partial<SIEMConfig> = {
  format: "json",
  enabled: true,
  batchSize: 100,
  flushInterval: 30000,
  retryAttempts: 3,
  retryDelay: 1000,
  sslEnabled: true,
  timeout: 30000,
};

// ==================== SIEM EVENT TYPES ====================

/**
 * SIEM-specific event format
 */
export interface SIEMEvent {
  timestamp: string;
  eventType: string;
  severity: AuditSeverity;
  source: string;
  sourceAddress?: string;
  sourcePort?: number;
  destinationAddress?: string;
  destinationPort?: number;
  userId?: string;
  userName?: string;
  action?: string;
  outcome?: "success" | "failure" | "unknown";
  resourceType?: string;
  resourceId?: string;
  tenantId?: string;
  requestId?: string;
  correlationId?: string;
  raw: Record<string, unknown>;
}

/**
 * SIEM streaming result
 */
export interface SIEMResult {
  success: boolean;
  eventId?: string;
  error?: string;
  timestamp: Date;
}

/**
 * SIEM batch streaming result
 */
export interface SIEMBatchResult {
  totalEvents: number;
  successCount: number;
  failedCount: number;
  results: SIEMResult[];
  processingTimeMs: number;
}

/**
 * SIEM health check result
 */
export interface SIEMHealthResult {
  healthy: boolean;
  endpoint: string;
  latencyMs: number;
  lastSuccess?: Date;
  lastError?: string;
}

// ==================== ALERT CONFIGURATION ====================

export type AlertConditionOperator =
  | "eq"
  | "ne"
  | "gt"
  | "lt"
  | "gte"
  | "lte"
  | "contains"
  | "in";

export interface AlertCondition {
  field: string;
  operator: AlertConditionOperator;
  value: unknown;
}

export type AlertActionType = "email" | "slack" | "pagerduty" | "webhook";

export interface AlertAction {
  type: AlertActionType;
  target: string;
  template?: string;
}

export interface AlertConfig {
  alertId: string;
  name: string;
  description: string;
  enabled: boolean;
  conditions: AlertCondition[];
  actions: AlertAction[];
  severity: AuditSeverity;
  threshold: number;
  timeWindow: number;
}

// ==================== HTTP CLIENT ====================

export interface HttpClient {
  get(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
  post(
    url: string,
    data: unknown,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse>;
  put(
    url: string,
    data: unknown,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse>;
  delete(url: string, options?: HttpRequestOptions): Promise<HttpResponse>;
}

export interface HttpRequestOptions {
  headers?: Record<string, string>;
  timeout?: number;
  validateSSL?: boolean;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: unknown;
  latencyMs: number;
}

class DefaultHttpClient implements HttpClient {
  async get(url: string, options?: HttpRequestOptions): Promise<HttpResponse> {
    return this.request("GET", url, undefined, options);
  }

  async post(
    url: string,
    data: unknown,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse> {
    return this.request("POST", url, data, options);
  }

  async put(
    url: string,
    data: unknown,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse> {
    return this.request("PUT", url, data, options);
  }

  async delete(
    url: string,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse> {
    return this.request("DELETE", url, undefined, options);
  }

  private async request(
    method: string,
    url: string,
    data?: unknown,
    options?: HttpRequestOptions,
  ): Promise<HttpResponse> {
    const startTime = Date.now();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...options?.headers,
    };

    try {
      const controller = new AbortController();
      const timeout = options?.timeout || 30000;
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      const response = await fetch(url, {
        method,
        headers,
        body: data ? JSON.stringify(data) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      let body: unknown;
      const contentType = response.headers.get("content-type");
      if (contentType?.includes("application/json")) {
        body = await response.json();
      } else {
        body = await response.text();
      }

      return {
        status: response.status,
        headers: Object.fromEntries(response.headers.entries()),
        body,
        latencyMs: Date.now() - startTime,
      };
    } catch (error) {
      return {
        status: 0,
        headers: {},
        body: error instanceof Error ? error.message : String(error),
        latencyMs: Date.now() - startTime,
      };
    }
  }
}

// ==================== LOGGER INTERFACE ====================

export interface Logger {
  info(message: string, data?: Record<string, unknown>): void;
  error(message: string, data?: Record<string, unknown>): void;
  warn(message: string, data?: Record<string, unknown>): void;
  debug(message: string, data?: Record<string, unknown>): void;
}

class DefaultLogger implements Logger {
  info(message: string, data?: Record<string, unknown>): void {
    console.log(`[SIEM] INFO: ${message}`, data ? JSON.stringify(data) : "");
  }

  error(message: string, data?: Record<string, unknown>): void {
    console.error(`[SIEM] ERROR: ${message}`, data ? JSON.stringify(data) : "");
  }

  warn(message: string, data?: Record<string, unknown>): void {
    console.warn(`[SIEM] WARN: ${message}`, data ? JSON.stringify(data) : "");
  }

  debug(message: string, data?: Record<string, unknown>): void {
    if (process.env.DEBUG === "true") {
      console.log(`[SIEM] DEBUG: ${message}`, data ? JSON.stringify(data) : "");
    }
  }
}

// ==================== SIEM INTEGRATION CLASS ====================

export class SIEMIntegration {
  private readonly config: SIEMConfig;
  private readonly eventQueue: AuditEvent[] = [];
  private readonly alertConfigs: Map<string, AlertConfig> = new Map();
  private readonly alertHistory: Map<
    string,
    { count: number; lastTrigger: Date }
  > = new Map();
  private flushInterval: NodeJS.Timeout | null = null;
  private httpClient: HttpClient;
  private logger: Logger;
  private isShuttingDown = false;

  constructor(
    config: Partial<SIEMConfig>,
    httpClient?: HttpClient,
    logger?: Logger,
  ) {
    this.config = {
      ...defaultSIEMConfig,
      ...config,
    } as SIEMConfig;
    this.httpClient = httpClient || new DefaultHttpClient();
    this.logger = logger || new DefaultLogger();

    if (this.config.enabled) {
      this.startPeriodicFlush();
    }
  }

  async streamEvent(event: AuditEvent): Promise<SIEMResult> {
    if (!this.config.enabled) {
      return {
        success: false,
        error: "SIEM integration is disabled",
        timestamp: new Date(),
      };
    }

    try {
      const siemEvent = this.toSIEMFormat(event);
      const formattedPayload = this.formatPayload(siemEvent);
      const result = await this.sendToSIEM(formattedPayload);
      this.evaluateAlerts(event);
      return result;
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      this.logger.error("Failed to stream event to SIEM", {
        eventId: event.eventId,
        error: errorMessage,
      });
      return {
        success: false,
        error: errorMessage,
        timestamp: new Date(),
      };
    }
  }

  async streamBatch(events: AuditEvent[]): Promise<SIEMBatchResult> {
    const startTime = Date.now();
    const results: SIEMResult[] = [];
    let successCount = 0;
    let failedCount = 0;

    for (const event of events) {
      const result = await this.streamEvent(event);
      results.push(result);

      if (result.success) {
        successCount++;
      } else {
        failedCount++;
      }
    }

    return {
      totalEvents: events.length,
      successCount,
      failedCount,
      results,
      processingTimeMs: Date.now() - startTime,
    };
  }

  toSIEMFormat(event: AuditEvent, format?: "cef" | "leef" | "json"): SIEMEvent {
    const targetFormat = format || this.mapFormat(this.config.format);

    switch (targetFormat) {
      case "cef":
        return this.toCEFFormat(event);
      case "leef":
        return this.toLEEFFormat(event);
      default:
        return this.toJSONFormat(event);
    }
  }

  private toCEFFormat(event: AuditEvent): SIEMEvent {
    const severity: AuditSeverity =
      event.decision?.result === "DENY" ? "ERROR" : "INFO";

    return {
      timestamp: event.timestamp.toISOString(),
      eventType: event.eventType,
      severity,
      source: event.metadata.service,
      sourceAddress: event.context.ip,
      userId: event.subject.id,
      userName: event.subject.attributes?.email as string | undefined,
      action: event.action.name,
      outcome: event.decision?.result === "ALLOW" ? "success" : "failure",
      resourceType: event.resource.type,
      resourceId: event.resource.id,
      tenantId: event.tenantId,
      requestId: event.context.requestId,
      correlationId: event.metadata.correlationId,
      raw: {
        cefVersion: "0",
        deviceVendor: "ExampleIAM",
        deviceProduct: event.metadata.service,
        deviceVersion: event.metadata.traceId || "1.0",
        signatureId: event.eventType,
        name: event.decision?.reason || event.eventType,
        severity: severity as string,
        ...event,
      },
    };
  }

  private toLEEFFormat(event: AuditEvent): SIEMEvent {
    const severity: AuditSeverity =
      event.decision?.result === "DENY" ? "ERROR" : "INFO";

    return {
      timestamp: event.timestamp.toISOString(),
      eventType: event.eventType,
      severity,
      source: event.metadata.service,
      sourceAddress: event.context.ip,
      userId: event.subject.id,
      userName: event.subject.attributes?.email as string | undefined,
      action: event.action.name,
      outcome: event.decision?.result === "ALLOW" ? "success" : "failure",
      resourceType: event.resource.type,
      resourceId: event.resource.id,
      tenantId: event.tenantId,
      requestId: event.context.requestId,
      raw: {
        leefVersion: "1.0",
        deviceVendor: "ExampleIAM",
        deviceProduct: event.metadata.service,
        deviceVersion: "1.0",
        signatureId: event.eventType,
        severity: severity as string,
        ...event,
      },
    };
  }

  private toJSONFormat(event: AuditEvent): SIEMEvent {
    return {
      timestamp: event.timestamp.toISOString(),
      eventType: event.eventType,
      severity: "INFO",
      source: event.metadata.service,
      sourceAddress: event.context.ip,
      userId: event.subject.id,
      userName: event.subject.attributes?.email as string | undefined,
      action: event.action.name,
      outcome: event.decision?.result === "ALLOW" ? "success" : "failure",
      resourceType: event.resource.type,
      resourceId: event.resource.id,
      tenantId: event.tenantId,
      requestId: event.context.requestId,
      correlationId: event.metadata.correlationId,
      raw: {
        eventId: event.eventId,
        eventType: event.eventType,
        tenantId: event.tenantId,
        timestamp: event.timestamp.toISOString(),
        subject: event.subject,
        action: event.action,
        resource: event.resource,
        context: event.context,
        decision: event.decision,
        metadata: event.metadata,
        compliance: event.compliance,
        signature: event.signature,
      },
    };
  }

  private formatPayload(siemEvent: SIEMEvent): string {
    switch (this.config.format) {
      case "cef":
        return this.formatCEF(siemEvent);
      case "leef":
        return this.formatLEEF(siemEvent);
      case "syslog":
        return this.formatSyslog(siemEvent);
      default:
        return JSON.stringify(siemEvent);
    }
  }

  private formatCEF(event: SIEMEvent): string {
    const extension = this.buildCEFExtension(event);
    return `CEF:0|${event.raw.deviceVendor}|${event.raw.deviceProduct}|${event.raw.deviceVersion}|${event.raw.signatureId}|${event.raw.name}|${event.severity}|${extension}`;
  }

  private buildCEFExtension(event: SIEMEvent): string {
    const extParts: string[] = [];

    if (event.tenantId) extParts.push(`tenantId=${event.tenantId}`);
    if (event.userId) extParts.push(`suser=${event.userId}`);
    if (event.sourceAddress) extParts.push(`src=${event.sourceAddress}`);
    if (event.resourceType) extParts.push(`spt=${event.resourceType}`);
    if (event.action) extParts.push(`requestClientApplication=${event.action}`);
    if (event.outcome) extParts.push(`outcome=${event.outcome}`);
    if (event.requestId) extParts.push(`requestId=${event.requestId}`);

    return extParts.join(" ");
  }

  private formatLEEF(event: SIEMEvent): string {
    const sevPrty = this.mapSeverityToLEEFNumber(event.severity);
    const extensions = this.buildLEEFFExtension(event);
    return `LEEF:${event.raw.leefVersion}|${event.raw.deviceVendor}|${event.raw.deviceProduct}|${event.raw.deviceVersion}|${event.raw.signatureId}|sevPrty=${sevPrty}|${extensions}`;
  }

  private buildLEEFFExtension(event: SIEMEvent): string {
    const extParts: string[] = [];

    if (event.tenantId) extParts.push(`tenantId=${event.tenantId}`);
    if (event.userId) extParts.push(`usrName=${event.userId}`);
    if (event.userId) extParts.push(`usrId=${event.userId}`);
    if (event.sourceAddress) extParts.push(`src=${event.sourceAddress}`);
    if (event.resourceType) extParts.push(`resType=${event.resourceType}`);
    if (event.resourceId) extParts.push(`resId=${event.resourceId}`);
    if (event.action) extParts.push(`act=${event.action}`);
    if (event.outcome) extParts.push(`outcome=${event.outcome}`);
    if (event.requestId) extParts.push(`requestId=${event.requestId}`);

    return extParts.join(" ");
  }

  private formatSyslog(event: SIEMEvent): string {
    const priority = this.mapSeverityToSyslogPriority(event.severity);
    const timestamp = event.timestamp;
    const hostname = event.source || "iam-service";
    const message = JSON.stringify(event.raw);

    return `<${priority}>1 ${timestamp} ${hostname} ${event.eventType} - ${message}`;
  }

  private async sendToSIEM(payload: string): Promise<SIEMResult> {
    const headers: Record<string, string> = {
      "Content-Type": this.getContentType(),
      ...this.config.customHeaders,
    };

    if (this.config.apiKey) {
      headers["Authorization"] = `Bearer ${this.config.apiKey}`;
      headers["X-API-Key"] = this.config.apiKey;
    }

    let lastError: string | undefined;

    for (let attempt = 1; attempt <= this.config.retryAttempts; attempt++) {
      try {
        const response = await this.httpClient.post(
          this.config.endpoint,
          payload,
          {
            headers,
            timeout: this.config.timeout,
            validateSSL: this.config.sslEnabled,
          },
        );

        if (response.status >= 200 && response.status < 300) {
          this.logger.info("Event sent to SIEM successfully", {
            endpoint: this.config.endpoint,
            status: response.status,
          });
          return {
            success: true,
            eventId: generateUUID(),
            timestamp: new Date(),
          };
        }

        lastError = `HTTP ${response.status}: ${JSON.stringify(response.body)}`;
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
      }

      if (attempt < this.config.retryAttempts) {
        await this.sleep(this.config.retryDelay * attempt);
      }
    }

    this.logger.error("Failed to send event to SIEM", { error: lastError });
    return {
      success: false,
      error: lastError,
      timestamp: new Date(),
    };
  }

  async healthCheck(): Promise<SIEMHealthResult> {
    const startTime = Date.now();

    try {
      const response = await this.httpClient.get(this.config.endpoint, {
        timeout: 10000,
        validateSSL: this.config.sslEnabled,
      });

      return {
        healthy: response.status >= 200 && response.status < 400,
        endpoint: this.config.endpoint,
        latencyMs: Date.now() - startTime,
        lastSuccess: response.status >= 200 ? new Date() : undefined,
        lastError:
          response.status >= 400 ? `HTTP ${response.status}` : undefined,
      };
    } catch (error) {
      return {
        healthy: false,
        endpoint: this.config.endpoint,
        latencyMs: Date.now() - startTime,
        lastError: error instanceof Error ? error.message : String(error),
      };
    }
  }

  addAlertConfig(config: AlertConfig): void {
    this.alertConfigs.set(config.alertId, config);
  }

  removeAlertConfig(alertId: string): boolean {
    return this.alertConfigs.delete(alertId);
  }

  getAlertConfigs(): AlertConfig[] {
    return Array.from(this.alertConfigs.values());
  }

  private evaluateAlerts(event: AuditEvent): void {
    for (const [alertId, config] of this.alertConfigs) {
      if (!config.enabled) continue;

      const triggered = this.evaluateConditions(event, config.conditions);

      if (triggered) {
        this.triggerAlert(alertId, config, event);
      }
    }
  }

  private evaluateConditions(
    event: AuditEvent,
    conditions: AlertCondition[],
  ): boolean {
    for (const condition of conditions) {
      const fieldValue = this.getFieldValue(event, condition.field);

      if (
        !this.compareValues(fieldValue, condition.operator, condition.value)
      ) {
        return false;
      }
    }
    return true;
  }

  private getFieldValue(event: AuditEvent, field: string): unknown {
    const parts = field.split(".");
    let current: unknown = event;

    for (const part of parts) {
      if (current === null || current === undefined) {
        return undefined;
      }
      current = (current as Record<string, unknown>)[part];
    }

    return current;
  }

  private compareValues(
    actual: unknown,
    operator: AlertConditionOperator,
    expected: unknown,
  ): boolean {
    switch (operator) {
      case "eq":
        return actual === expected;
      case "ne":
        return actual !== expected;
      case "gt":
        return (
          typeof actual === "number" &&
          typeof expected === "number" &&
          actual > expected
        );
      case "lt":
        return (
          typeof actual === "number" &&
          typeof expected === "number" &&
          actual < expected
        );
      case "gte":
        return (
          typeof actual === "number" &&
          typeof expected === "number" &&
          actual >= expected
        );
      case "lte":
        return (
          typeof actual === "number" &&
          typeof expected === "number" &&
          actual <= expected
        );
      case "contains":
        return (
          typeof actual === "string" &&
          typeof expected === "string" &&
          actual.includes(expected)
        );
      case "in":
        return Array.isArray(expected) && expected.includes(actual);
      default:
        return false;
    }
  }

  private triggerAlert(
    alertId: string,
    config: AlertConfig,
    event: AuditEvent,
  ): void {
    const historyKey = `${alertId}:${event.tenantId}`;
    const now = new Date();

    const history = this.alertHistory.get(historyKey);
    if (history) {
      const windowStart = new Date(now.getTime() - config.timeWindow * 1000);
      if (history.lastTrigger > windowStart) {
        // Within time window
      }
    }

    this.alertHistory.set(historyKey, { count: 1, lastTrigger: now });

    for (const action of config.actions) {
      this.executeAlertAction(action, config, event);
    }

    this.logger.warn("Alert triggered", {
      alertId,
      alertName: config.name,
      eventId: event.eventId,
      severity: config.severity,
    });
  }

  private executeAlertAction(
    action: AlertAction,
    config: AlertConfig,
    event: AuditEvent,
  ): void {
    const message = this.formatAlertMessage(action, config, event);

    switch (action.type) {
      case "email":
        this.sendEmailAlert(action.target, message);
        break;
      case "slack":
        this.sendSlackAlert(action.target, message);
        break;
      case "pagerduty":
        this.sendPagerDutyAlert(action.target, message);
        break;
      case "webhook":
        this.sendWebhookAlert(action.target, message);
        break;
    }
  }

  private formatAlertMessage(
    action: AlertAction,
    config: AlertConfig,
    event: AuditEvent,
  ): string {
    if (action.template) {
      return action.template
        .replace("{alertName}", config.name)
        .replace("{eventId}", event.eventId)
        .replace("{tenantId}", event.tenantId)
        .replace("{severity}", config.severity)
        .replace("{description}", config.description);
    }

    return `[${config.severity}] ${config.name}: ${config.description} - Event: ${event.eventId}`;
  }

  private sendEmailAlert(target: string, message: string): void {
    this.logger.info("Email alert", {
      target,
      message: message.substring(0, 100),
    });
  }

  private sendSlackAlert(target: string, message: string): void {
    this.logger.info("Slack alert", {
      target,
      message: message.substring(0, 100),
    });
  }

  private sendPagerDutyAlert(target: string, message: string): void {
    this.logger.info("PagerDuty alert", {
      target,
      message: message.substring(0, 100),
    });
  }

  private sendWebhookAlert(target: string, message: string): void {
    this.logger.info("Webhook alert", {
      target,
      message: message.substring(0, 100),
    });
  }

  private startPeriodicFlush(): void {
    this.flushInterval = setInterval(() => {
      this.flushQueue().catch((error) => {
        this.logger.error("Error in periodic flush", { error });
      });
    }, this.config.flushInterval);
  }

  private async flushQueue(): Promise<void> {
    if (this.eventQueue.length === 0) {
      return;
    }

    const events = [...this.eventQueue];
    this.eventQueue.length = 0;

    await this.streamBatch(events);
  }

  stop(): void {
    this.isShuttingDown = true;

    if (this.flushInterval) {
      clearInterval(this.flushInterval);
      this.flushInterval = null;
    }

    this.flushQueue().catch((error) => {
      this.logger.error("Error in final flush", { error });
    });
  }

  getStats(): {
    queueSize: number;
    enabled: boolean;
    format: string;
    endpoint: string;
    alertCount: number;
  } {
    return {
      queueSize: this.eventQueue.length,
      enabled: this.config.enabled,
      format: this.config.format,
      endpoint: this.config.endpoint,
      alertCount: this.alertConfigs.size,
    };
  }

  private mapFormat(format: string): "cef" | "leef" | "json" {
    switch (format) {
      case "cef":
        return "cef";
      case "leef":
        return "leef";
      default:
        return "json";
    }
  }

  private mapSeverityToCEF(severity: AuditSeverity): string {
    switch (severity) {
      case "DEBUG":
        return "0";
      case "INFO":
        return "3";
      case "WARNING":
        return "5";
      case "ERROR":
        return "7";
      case "CRITICAL":
        return "10";
      default:
        return "3";
    }
  }

  private mapSeverityToLEEF(severity: AuditSeverity): string {
    switch (severity) {
      case "DEBUG":
        return "0";
      case "INFO":
        return "3";
      case "WARNING":
        return "5";
      case "ERROR":
        return "7";
      case "CRITICAL":
        return "10";
      default:
        return "3";
    }
  }

  private mapSeverityToLEEFNumber(severity: AuditSeverity): number {
    return parseInt(this.mapSeverityToLEEF(severity), 10) || 3;
  }

  private mapSeverityToSyslogPriority(severity: AuditSeverity): number {
    const severityPriority: Record<AuditSeverity, number> = {
      DEBUG: 56,
      INFO: 54,
      WARNING: 52,
      ERROR: 50,
      CRITICAL: 48,
    };
    return severityPriority[severity] || 54;
  }

  private getContentType(): string {
    switch (this.config.format) {
      case "cef":
        return "text/plain";
      case "leef":
        return "text/plain";
      case "syslog":
        return "text/plain";
      default:
        return "application/json";
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}
