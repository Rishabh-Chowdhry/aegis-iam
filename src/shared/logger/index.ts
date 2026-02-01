import { config } from "../config";

export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

class Logger {
  private level: LogLevel;

  constructor() {
    this.level = this.parseLogLevel(config.logLevel);
  }

  private parseLogLevel(level: string): LogLevel {
    switch (level.toLowerCase()) {
      case "error":
        return LogLevel.ERROR;
      case "warn":
        return LogLevel.WARN;
      case "info":
        return LogLevel.INFO;
      case "debug":
        return LogLevel.DEBUG;
      default:
        return LogLevel.INFO;
    }
  }

  private shouldLog(level: LogLevel): boolean {
    return level <= this.level;
  }

  private formatMessage(level: string, message: string, meta?: any): string {
    const timestamp = new Date().toISOString();
    const metaStr = meta ? ` ${JSON.stringify(meta)}` : "";
    return `[${timestamp}] ${level}: ${message}${metaStr}`;
  }

  error(message: string, meta?: any): void {
    if (this.shouldLog(LogLevel.ERROR)) {
      console.error(this.formatMessage("ERROR", message, meta));
    }
  }

  warn(message: string, meta?: any): void {
    if (this.shouldLog(LogLevel.WARN)) {
      console.warn(this.formatMessage("WARN", message, meta));
    }
  }

  info(message: string, meta?: any): void {
    if (this.shouldLog(LogLevel.INFO)) {
      console.info(this.formatMessage("INFO", message, meta));
    }
  }

  debug(message: string, meta?: any): void {
    if (this.shouldLog(LogLevel.DEBUG)) {
      console.debug(this.formatMessage("DEBUG", message, meta));
    }
  }

  // Specialized logging methods
  logRequest(req: any, res: any, responseTime: number): void {
    const { method, url, ip } = req;
    const { statusCode } = res;
    this.info("Request completed", {
      method,
      url,
      statusCode,
      responseTime: `${responseTime}ms`,
      ip,
      userAgent: req.get("User-Agent"),
    });
  }

  logError(error: Error, req?: any): void {
    const context = req
      ? {
          method: req.method,
          url: req.url,
          ip: req.ip,
          userId: req.user?.id,
          tenantId: req.tenantId,
        }
      : {};

    this.error("Error occurred", {
      error: error.message,
      stack: error.stack,
      ...context,
    });
  }

  logAuth(action: string, userId?: string, details?: any): void {
    this.info("Authentication/Authorization event", {
      action,
      userId,
      ...details,
    });
  }

  logAudit(
    userId: string,
    action: string,
    resource: string,
    resourceId?: string,
    details?: any,
  ): void {
    this.info("Audit log entry", {
      userId,
      action,
      resource,
      resourceId,
      ...details,
    });
  }
}

export const logger = new Logger();
