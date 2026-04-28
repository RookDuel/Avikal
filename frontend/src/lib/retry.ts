/**
 * Standalone retry utility for transient network failures.
 *
 * Requirements: 7.8, 7.10
 */

import { logger } from './logger'

export interface RetryOptions {
  /** Maximum number of retry attempts (default: 2) */
  maxRetries?: number
  /** Delay in milliseconds between retries (default: 1000) */
  delayMs?: number
  /**
   * Predicate that decides whether to retry on a given error.
   * Defaults to retrying only on network errors, not on 4xx/5xx HTTP errors.
   */
  shouldRetry?: (err: unknown) => boolean
}

/** Returns true for network-level errors (fetch failures, timeouts, aborts). */
function isNetworkError(err: unknown): boolean {
  if (err instanceof Error) {
    const msg = err.message.toLowerCase()
    // AbortError = timeout triggered by AbortController
    if (err.name === 'AbortError') return true
    // TypeError is thrown by fetch when the network is unreachable
    if (err instanceof TypeError) return true
    if (
      msg.includes('network error') ||
      msg.includes('failed to fetch') ||
      msg.includes('connection refused') ||
      msg.includes('econnrefused') ||
      msg.includes('request timed out')
    ) {
      return true
    }
  }
  return false
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

/**
 * Execute `fn` and retry up to `maxRetries` times on transient failures.
 *
 * @example
 * const data = await withRetry(() => fetch('/api/data').then(r => r.json()))
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const { maxRetries = 2, delayMs = 1000, shouldRetry = isNetworkError } = options

  let lastError: unknown

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (err) {
      lastError = err

      const isLast = attempt === maxRetries
      if (isLast || !shouldRetry(err)) {
        throw err
      }

      logger.warn(
        `Request failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delayMs}ms…`,
        'withRetry',
        { error: err instanceof Error ? err.message : String(err) },
      )

      await delay(delayMs)
    }
  }

  // Should never reach here, but satisfies TypeScript
  throw lastError
}
