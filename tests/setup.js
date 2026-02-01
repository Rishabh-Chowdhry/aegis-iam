/**
 * Jest Test Setup
 *
 * This file is run before each test file and provides:
 * - Global mocks
 * - Test environment setup
 * - Cleanup functions
 */

// Set test environment variables
process.env.NODE_ENV = "test";
process.env.JWT_SECRET = "test-secret-key-for-testing-only";
process.env.JWT_REFRESH_SECRET = "test-refresh-secret-key-for-testing-only";
process.env.DATABASE_URL = "mongodb://localhost:27017/test-iam";
process.env.REDIS_URL = "redis://localhost:6379";

// Increase test timeout
jest.setTimeout(10000);
