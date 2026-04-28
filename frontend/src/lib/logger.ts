/**
 * Frontend error logger with timestamp and context.
 * Logs to console and persists to localStorage for debugging.
 */

const LOG_KEY = 'avikal_error_log'
const MAX_LOG_ENTRIES = 200

export type LogLevel = 'debug' | 'info' | 'warn' | 'error'

export interface LogEntry {
  timestamp: string
  level: LogLevel
  message: string
  context?: string
  details?: unknown
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
    message,
    context,
    details,
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
