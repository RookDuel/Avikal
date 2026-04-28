export interface BackendProgressEvent {
  type: 'progress'
  operation: string
  status: 'running' | 'completed' | 'error'
  stage: string
  percentage: number | null
  currentOperation: string
  etaSeconds: number | null
  fileSize: number | null
  compressionRatio: number | null
}

const PREFIX = '__AVIKAL_PROGRESS__'

export function parseBackendProgressChunk(message: string): BackendProgressEvent[] {
  const events: BackendProgressEvent[] = []
  for (const line of message.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed.startsWith(PREFIX)) continue
    const payload = trimmed.slice(PREFIX.length)
    try {
      const parsed = JSON.parse(payload) as BackendProgressEvent
      if (parsed?.type === 'progress') {
        events.push(parsed)
      }
    } catch {
      // Ignore malformed progress lines and keep normal logs untouched.
    }
  }
  return events
}

export function formatEta(etaSeconds: number | null | undefined): string {
  if (etaSeconds == null || etaSeconds < 0) return 'Estimating...'
  if (etaSeconds < 60) return `~${etaSeconds}s remaining`
  const minutes = Math.floor(etaSeconds / 60)
  const seconds = etaSeconds % 60
  if (minutes < 60) return `~${minutes}m ${seconds}s remaining`
  const hours = Math.floor(minutes / 60)
  const remMinutes = minutes % 60
  return `~${hours}h ${remMinutes}m remaining`
}
