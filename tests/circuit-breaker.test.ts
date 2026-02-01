/**
 * Unit Tests for Circuit Breaker
 */

import {
  CircuitBreaker,
  CircuitState,
  CircuitOpenError,
  createDefaultConfig,
} from "../../src/infrastructure/redis/CircuitBreaker";

describe("CircuitBreaker", () => {
  let circuitBreaker: CircuitBreaker;

  beforeEach(() => {
    circuitBreaker = new CircuitBreaker(createDefaultConfig());
  });

  afterEach(() => {
    circuitBreaker.reset();
  });

  describe("Initial State", () => {
    it("should start in CLOSED state", () => {
      expect(circuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });

    it("should have zero failures initially", () => {
      const metrics = circuitBreaker.getMetrics();
      expect(metrics.failureCount).toBe(0);
      expect(metrics.successCount).toBe(0);
    });
  });

  describe("Successful Operations", () => {
    it("should execute successful operation in CLOSED state", async () => {
      const result = await circuitBreaker.execute(async () => {
        return "success";
      });

      expect(result).toBe("success");
      expect(circuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });

    it("should increment success count in HALF_OPEN state", async () => {
      // Open the circuit first by causing failures
      circuitBreaker = new CircuitBreaker({
        ...createDefaultConfig(),
        failureThreshold: 1,
        successThreshold: 2,
      });

      // Force open state
      circuitBreaker.forceState(CircuitState.OPEN);

      // Wait for recovery timeout (in test we use forceState to simulate)
      circuitBreaker.forceState(CircuitState.HALF_OPEN);

      // First success
      await circuitBreaker.execute(async () => "success");
      expect(circuitBreaker.getMetrics().successCount).toBe(1);

      // Second success should close the circuit
      await circuitBreaker.execute(async () => "success");
      expect(circuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });
  });

  describe("Failed Operations", () => {
    it("should count failures in CLOSED state", async () => {
      await expect(
        circuitBreaker.execute(async () => {
          throw new Error("Test error");
        }),
      ).rejects.toThrow("Test error");

      const metrics = circuitBreaker.getMetrics();
      expect(metrics.failureCount).toBe(1);
    });

    it("should open circuit after reaching failure threshold", async () => {
      circuitBreaker = new CircuitBreaker({
        ...createDefaultConfig(),
        failureThreshold: 3,
      });

      for (let i = 0; i < 3; i++) {
        await expect(
          circuitBreaker.execute(async () => {
            throw new Error("Test error");
          }),
        ).rejects.toThrow("Test error");
      }

      expect(circuitBreaker.getState()).toBe(CircuitState.OPEN);
    });

    it("should throw CircuitOpenError when circuit is open", async () => {
      circuitBreaker = new CircuitBreaker({
        ...createDefaultConfig(),
        failureThreshold: 1,
      });

      // Cause one failure to open circuit
      await expect(
        circuitBreaker.execute(async () => {
          throw new Error("Test error");
        }),
      ).rejects.toThrow("Test error");

      expect(circuitBreaker.getState()).toBe(CircuitState.OPEN);

      // Next call should throw CircuitOpenError
      await expect(
        circuitBreaker.execute(async () => "should not execute"),
      ).rejects.toThrow(CircuitOpenError);
    });

    it("should move to HALF_OPEN after recovery timeout", async () => {
      circuitBreaker = new CircuitBreaker({
        ...createDefaultConfig(),
        failureThreshold: 1,
        recoveryTimeout: 100, // 100ms for testing
      });

      // Open the circuit
      await expect(
        circuitBreaker.execute(async () => {
          throw new Error("Test error");
        }),
      ).rejects.toThrow("Test error");

      expect(circuitBreaker.getState()).toBe(CircuitState.OPEN);

      // Wait for recovery timeout
      await new Promise((resolve) => setTimeout(resolve, 150));

      // Next call should move to HALF_OPEN
      const result = await circuitBreaker.execute(async () => "recovery");
      expect(result).toBe("recovery");
      expect(circuitBreaker.getState()).toBe(CircuitState.HALF_OPEN);
    });
  });

  describe("Reset", () => {
    it("should reset to initial state", async () => {
      // Cause some failures
      for (let i = 0; i < 3; i++) {
        await expect(
          circuitBreaker.execute(async () => {
            throw new Error("Test error");
          }),
        ).rejects.toThrow("Test error");
      }

      expect(circuitBreaker.getState()).toBe(CircuitState.OPEN);

      // Reset
      circuitBreaker.reset();

      expect(circuitBreaker.getState()).toBe(CircuitState.CLOSED);
      expect(circuitBreaker.getMetrics().failureCount).toBe(0);
    });
  });

  describe("Force State", () => {
    it("should force state to OPEN", () => {
      circuitBreaker.forceState(CircuitState.OPEN);
      expect(circuitBreaker.getState()).toBe(CircuitState.OPEN);
    });

    it("should force state to CLOSED", () => {
      circuitBreaker.forceState(CircuitState.OPEN);
      circuitBreaker.forceState(CircuitState.CLOSED);
      expect(circuitBreaker.getState()).toBe(CircuitState.CLOSED);
    });
  });

  describe("Configuration", () => {
    it("should throw error for invalid failure threshold", () => {
      expect(
        () =>
          new CircuitBreaker({
            ...createDefaultConfig(),
            failureThreshold: 0,
          }),
      ).toThrow("Failure threshold must be at least 1");
    });

    it("should throw error for invalid recovery timeout", () => {
      expect(
        () =>
          new CircuitBreaker({
            ...createDefaultConfig(),
            recoveryTimeout: 500,
          }),
      ).toThrow("Recovery timeout must be at least 1000ms");
    });
  });
});

describe("CircuitOpenError", () => {
  it("should include metrics in error", () => {
    const metrics = {
      state: CircuitState.OPEN,
      failureCount: 5,
      successCount: 0,
      lastFailureTime: Date.now(),
      lastSuccessTime: null,
      nextAttemptTime: Date.now() + 30000,
    };

    const error = new CircuitOpenError("Circuit is open", metrics);

    expect(error.message).toBe("Circuit is open");
    expect(error.metrics).toEqual(metrics);
    expect(error.name).toBe("CircuitOpenError");
  });
});
