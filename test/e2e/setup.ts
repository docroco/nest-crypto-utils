/**
 * Global setup for E2E tests.
 * Runs before each test suite.
 */

// Increase timeout for E2E tests that may involve async operations
jest.setTimeout(30_000)

// Set test environment variables if needed
process.env.NODE_ENV = 'test'
