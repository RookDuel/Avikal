export type ErrorCode =
  | 'auth_failed'
  | 'time_locked'
  | 'wrong_password'
  | 'file_corrupted'
  | 'network_error'
  | 'ntp_failed'
  | 'file_not_found'
  | 'permission_denied'
  | 'unknown'

export interface AppError {
  code: ErrorCode
  userMessage: string
  suggestion: string
  details?: string
  rawMessage?: string
}

const ERROR_CATALOG: Record<ErrorCode, Omit<AppError, 'code' | 'details' | 'rawMessage'>> = {
  auth_failed: {
    userMessage: 'Authentication failed.',
    suggestion: 'Sign in again and verify that your account has access to this operation.',
  },
  time_locked: {
    userMessage: 'This time-capsule is still locked.',
    suggestion: 'Wait until the unlock time arrives, then try again.',
  },
  wrong_password: {
    userMessage: 'Incorrect password or keyphrase.',
    suggestion: 'Check the password, keyphrase, and PQC keyfile, then retry.',
  },
  file_corrupted: {
    userMessage: 'The archive failed integrity verification.',
    suggestion: 'Use the original .avk and matching companion files. The archive may be corrupted or mismatched.',
  },
  network_error: {
    userMessage: 'Network communication failed.',
    suggestion: 'Confirm that the local backend and any required network services are reachable, then retry.',
  },
  ntp_failed: {
    userMessage: 'Trusted time verification failed.',
    suggestion: 'Check your internet connection and system clock, then retry the time-capsule action.',
  },
  file_not_found: {
    userMessage: 'The requested file could not be found.',
    suggestion: 'Verify that the selected path still exists and retry.',
  },
  permission_denied: {
    userMessage: 'Permission was denied.',
    suggestion: 'Choose a location you can access, or run the app with the required permissions.',
  },
  unknown: {
    userMessage: 'An unexpected error occurred.',
    suggestion: 'Retry the operation. If it keeps failing, inspect the logs for more detail.',
  },
}

function normalizeErrorInput(error: unknown): string {
  if (typeof error === 'string') return error
  if (error instanceof Error) return error.message || String(error)
  return String(error ?? '')
}

function inferErrorCode(message: string): ErrorCode {
  const text = message.toLowerCase()
  if (text.includes('authentication failed') || text.includes('session expired') || text.includes('unauthorized')) return 'auth_failed'
  if (text.includes('time-capsule locked') || text.includes('still locked') || text.includes('unlocks in')) return 'time_locked'
  if (text.includes('incorrect password') || text.includes('wrong password') || text.includes('keyphrase') || text.includes('pqc keyfile')) return 'wrong_password'
  if (text.includes('integrity') || text.includes('corrupt') || text.includes('capsule verification failed')) return 'file_corrupted'
  if (text.includes('network error') || text.includes('fetch failed') || text.includes('timed out') || text.includes('service unavailable')) return 'network_error'
  if (text.includes('ntp') || text.includes('trusted time') || text.includes('trusted network time') || text.includes('time verification failed')) return 'ntp_failed'
  if (text.includes('not found') || text.includes('no such file')) return 'file_not_found'
  if (text.includes('permission') || text.includes('access is denied') || text.includes('eperm')) return 'permission_denied'
  return 'unknown'
}

export function parseError(error: unknown): AppError {
  const rawMessage = normalizeErrorInput(error).trim()
  const code = inferErrorCode(rawMessage)
  const base = ERROR_CATALOG[code]

  return {
    code,
    userMessage: base.userMessage,
    suggestion: base.suggestion,
    details: rawMessage || undefined,
    rawMessage: rawMessage || undefined,
  }
}

export function getErrorMessage(error: unknown, fallback: string): string {
  const rawMessage = normalizeErrorInput(error).trim()
  return rawMessage || fallback
}
