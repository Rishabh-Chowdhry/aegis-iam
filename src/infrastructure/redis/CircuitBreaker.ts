/**
 * Circuit Breaker Implementation for Redis Fail-Safe
 *
 * This module implements the Circuit Breaker pattern to prevent cascading failures
 * when Redis becomes unavailable. The circuit breaker has three states:
 *
 * - CLOSED: Normal operation, requests pass through
 * - OPEN: Redis unavailable, requests fail immediately
 * - HALF_OPEN: Testing recovery, limited requests allowed
 */

export enum CircuitState {
  CLOSED = "CLOSED",
  OPEN = "OPEN",
  HALF_OPEN = "HALF_OPEN",
}

export interface CircuitBreakerConfig {
  failureThreshold: number; // Number of failures before opening
  recoveryTimeout: number; // Time in ms before attempting recovery
  successThreshold: number; // Successes needed in HALF_OPEN to close
  monitoringWindow: number; // Time window for counting failures
}

export interface CircuitBreakerMetrics {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailureTime: number | null;
  lastSuccessTime: number | null;
  nextAttemptTime: number | null;
}

export class CircuitBreaker {
  private state: CircuitState = CircuitState.CLOSED;
  private failureCount: number = 0;
  private successCount: number = 0;
  private lastFailureTime: number = 0;
  private lastSuccessTime: number = 0;
  private nextAttemptTime: number | null = null;
  private failureTimestamps: number[] = [];

  constructor(private readonly config: CircuitBreakerConfig) {
    if (config.failureThreshold < 1) {
      throw new Error("Failure threshold must be at least 1");
    }
    if (config.recoveryTimeout < 1000) {
      throw new Error("Recovery timeout must be at least 1000ms");
    }
  }

  /**
   * Execute an operation with circuit breaker protection
   */
  async execute<T>(operation: () => Promise<T>): Promise<T> {
    this.cleanupOldFailures();

    if (this.state === CircuitState.OPEN) {
      if (this.shouldAttemptReset()) {
        this.state = CircuitState.HALF_OPEN;
        this.successCount = 0;
        this.failureCount = 0;
      } else {
        throw new CircuitOpenError(
          "Circuit breaker is OPEN. Redis is unavailable.",
          this.getMetrics(),
        );
      }
    }

    try {
      const result = await operation();
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  /**
   * Execute an operation that doesn't return a value
   */
  async executeVoid(operation: () => Promise<void>): Promise<void> {
    await this.execute(async () => {
      await operation();
      return undefined;
    });
  }

  /**
   * Check if the circuit should attempt to reset
   */
  private shouldAttemptReset(): boolean {
    if (this.nextAttemptTime === null) {
      return true;
    }
    return Date.now() >= this.nextAttemptTime;
  }

  /**
   * Handle successful operation
   */
  private onSuccess(): void {
    this.lastSuccessTime = Date.now();
    this.successCount++;

    if (this.state === CircuitState.HALF_OPEN) {
      if (this.successCount >= this.config.successThreshold) {
        this.close();
      }
    }
  }

  /**
   * Handle failed operation
   */
  private onFailure(): void {
    this.lastFailureTime = Date.now();
    this.failureCount++;
    this.failureTimestamps.push(Date.now());

    if (this.state === CircuitState.HALF_OPEN) {
      this.open();
    } else if (this.failureCount >= this.config.failureThreshold) {
      this.open();
    }
  }

  /**
   * Open the circuit
   */
  private open(): void {
    this.state = CircuitState.OPEN;
    this.nextAttemptTime = Date.now() + this.config.recoveryTimeout;
  }

  /**
   * Close the circuit
   */
  private close(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.nextAttemptTime = null;
    this.failureTimestamps = [];
  }

  /**
   * Clean up failures older than the monitoring window
   */
  private cleanupOldFailures(): void {
    const cutoff = Date.now() - this.config.monitoringWindow;
    this.failureTimestamps = this.failureTimestamps.filter(
      (timestamp) => timestamp > cutoff,
    );
    this.failureCount = this.failureTimestamps.length;
  }

  /**
   * Get current circuit state
   */
  getState(): CircuitState {
    this.cleanupOldFailures();
    return this.state;
  }

  /**
   * Get circuit breaker metrics
   */
  getMetrics(): CircuitBreakerMetrics {
    this.cleanupOldFailures();
    return {
      state: this.state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime || null,
      lastSuccessTime: this.lastSuccessTime || null,
      nextAttemptTime: this.nextAttemptTime,
    };
  }

  /**
   * Force the circuit into a specific state (for testing/admin)
   */
  forceState(state: CircuitState): void {
    this.state = state;
    if (state === CircuitState.CLOSED) {
      this.failureCount = 0;
      this.successCount = 0;
      this.nextAttemptTime = null;
      this.failureTimestamps = [];
    } else if (state === CircuitState.OPEN) {
      this.nextAttemptTime = Date.now() + this.config.recoveryTimeout;
    }
  }

  /**
   * Reset the circuit breaker to initial state
   */
  reset(): void {
    this.state = CircuitState.CLOSED;
    this.failureCount = 0;
    this.successCount = 0;
    this.lastFailureTime = 0;
    this.lastSuccessTime = 0;
    this.nextAttemptTime = null;
    this.failureTimestamps = [];
  }
}

/**
 * Error thrown when circuit breaker is open
 */
export class CircuitOpenError extends Error {
  constructor(
    message: string,
    public readonly metrics: CircuitBreakerMetrics,
  ) {
    super(message);
    this.name = "CircuitOpenError";
  }
}

/**
 * Create a default circuit breaker configuration
 */
export function createDefaultConfig(): CircuitBreakerConfig {
  return {
    failureThreshold: 5,
    recoveryTimeout: 30000, // 30 seconds
    successThreshold: 3,
    monitoringWindow: 60000, // 1 minute
  };
}
