/**
 * Frontend error logger with timestamp and context.
 * Logs to console and persists to localStorage for debugging.
 */

const LOG_KEY = 'avikal_error_log'
const MAX_LOG_ENTRIES = 200
const MAX_REDACTION_DEPTH = 4
const SENSITIVE_KEY_PATTERN = /password|keyphrase|token|secret|authorization|pqc_keyfile_password/i
const SENSITIVE_TEXT_PATTERN = /\b(password|keyphrase|token|secret|authorization|pqc_keyfile_password)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;]+)/gi

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LogEntry {
  timestamp: string
  level: LogLevel
  message: string
  context?: string
  details?: unknown
}

function redactText(value: string): string {
  return value.replace(SENSITIVE_TEXT_PATTERN, '$1=[redacted]')
}

function redactDetails(value: unknown, depth = 0, seen = new WeakSet<object>()): unknown {
  if (typeof value === 'string') return redactText(value)
  if (typeof value !== 'object' || value === null) return value
  if (depth >= MAX_REDACTION_DEPTH) return '[redacted-depth-limit]'
  if (seen.has(value)) return '[redacted-circular]'
  seen.add(value)

  if (Array.isArray(value)) {
    return value.map(item => redactDetails(item, depth + 1, seen))
  }

  const output: Record<string, unknown> = {}
  for (const [key, nested] of Object.entries(value as Record<string, unknown>)) {
    output[key] = SENSITIVE_KEY_PATTERN.test(key)
      ? '[redacted]'
      : redactDetails(nested, depth + 1, seen)
  }
  return output
}

function getStoredLogs(): LogEntry[] {
  try {
    const raw = localStorage.getItem(LOG_KEY)
    return raw ? (JSON.parse(raw) as LogEntry[]) : []
  } catch {
    return []
  }
}

function persistLog(entry: LogEntry): void {
  try {
    const logs = getStoredLogs()
    logs.push(entry)
    // Keep only the most recent entries
    if (logs.length > MAX_LOG_ENTRIES) {
      logs.splice(0, logs.length - MAX_LOG_ENTRIES)
    }
    localStorage.setItem(LOG_KEY, JSON.stringify(logs))
  } catch {
    // Silently fail – storage may be unavailable
  }
}

function createEntry(level: LogLevel, message: string, context?: string, details?: unknown): LogEntry {
  return {
    timestamp: new Date().toISOString(),
    level,
    message: redactText(message),
    context,
    details: redactDetails(details),
  }
}

function formatConsole(entry: LogEntry): string {
  const ctx = entry.context ? ` [${entry.context}]` : ''
  return `[${entry.timestamp}]${ctx} ${entry.message}`
}

export const logger = {
  debug(message: string, context?: string, details?: unknown): void {
    const entry = createEntry('debug', message, context, details)
    console.debug(formatConsole(entry), details ?? '')
    persistLog(entry)
  },

  info(message: string, context?: string, details?: unknown): void {
    const entry = createEntry('info', message, context, details)
    console.info(formatConsole(entry), details ?? '')
    persistLog(entry)
  },

  warn(message: string, context?: string, details?: unknown): void {
    const entry = createEntry('warn', message, context, details)
    console.warn(formatConsole(entry), details ?? '')
    persistLog(entry)
  },

  error(message: string, context?: string, details?: unknown): void {
    const entry = createEntry('error', message, context, details)
    console.error(formatConsole(entry), details ?? '')
    persistLog(entry)
  },

  /** Log an Error object with full stack trace */
  logError(err: unknown, context?: string): void {
    if (err instanceof Error) {
      this.error(err.message, context, { stack: err.stack, name: err.name })
    } else {
      this.error(String(err), context, err)
    }
  },

  /** Retrieve all stored log entries */
  getLogs(): LogEntry[] {
    return getStoredLogs()
  },

  /** Clear stored logs */
  clearLogs(): void {
    try {
      localStorage.removeItem(LOG_KEY)
    } catch {
      // Silently fail
    }
  },
}
