import { motion, AnimatePresence } from 'framer-motion'
import { X, Clock, Cpu, FileText, Zap } from 'lucide-react'
import { cn } from '../lib/utils'
import { formatFileSize } from '../lib/utils'
import Button from './Button'
import Card from './Card'

interface ProgressCardProps {
  /** Current status label shown at the top */
  status: string
  /** Progress percentage (0–100), or null when not calculable */
  percentage: number | null
  /** Current operation description e.g. "Encrypting with AES-256-GCM" */
  currentOperation: string
  /** Raw file size in bytes, or null if unknown */
  fileSize: number | null
  /** Compression ratio as a decimal (e.g. 0.42 = 42% of original), or null */
  compressionRatio: number | null
  /** Called when the user clicks Cancel */
  onCancel: () => void
  /** True while a cancellation is in progress */
  isCancelling: boolean
  /** Elapsed seconds – managed externally so the parent controls the timer */
  elapsedSeconds: number
  /** Approximate ETA in seconds, or null if unknown */
  etaSeconds: number | null
}

/** Map common operation strings to an icon */
function OperationIcon({ operation }: { operation: string }) {
  const lower = operation.toLowerCase()
  if (lower.includes('encrypt') || lower.includes('aes')) {
    return <Zap className="w-4 h-4 text-yellow-400" />
  }
  if (lower.includes('compress')) {
    return <Cpu className="w-4 h-4 text-blue-400" />
  }
  if (lower.includes('read') || lower.includes('file')) {
    return <FileText className="w-4 h-4 text-green-400" />
  }
  return <Cpu className="w-4 h-4 text-primary-400" />
}

function formatElapsed(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}m ${s}s`
}

function formatEta(seconds: number | null): string {
  if (seconds == null) return 'Estimating…'
  if (seconds < 60) return `~${seconds}s left`
  const m = Math.floor(seconds / 60)
  const s = seconds % 60
  return `${m}m ${s}s left`
}

export default function ProgressCard({
  status,
  percentage,
  currentOperation,
  fileSize,
  compressionRatio,
  onCancel,
  isCancelling,
  elapsedSeconds,
  etaSeconds,
}: ProgressCardProps) {
  // Animated progress bar width
  const progressWidth = percentage !== null ? `${Math.min(100, Math.max(0, percentage))}%` : '0%'

  return (
    <Card hover={false} className="p-6 space-y-5">
      {/* Header row */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            {/* Pulsing dot */}
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-primary-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-primary-500" />
            </span>
            <span className="text-sm font-semibold text-av-main">{status}</span>
          </div>

          {/* Current operation */}
          <AnimatePresence mode="wait">
            <motion.div
              key={currentOperation}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -4 }}
              transition={{ duration: 0.2 }}
              className="flex items-center gap-1.5 text-xs text-av-muted"
            >
              <OperationIcon operation={currentOperation} />
              <span>{currentOperation || 'Initializing…'}</span>
            </motion.div>
          </AnimatePresence>
        </div>

        {/* Elapsed timer */}
        <div className="flex flex-col items-end gap-1 text-xs text-av-muted shrink-0">
          <div className="flex items-center gap-1.5">
            <Clock className="w-3.5 h-3.5" />
            <span className="tabular-nums font-mono">{formatElapsed(elapsedSeconds)}</span>
          </div>
          <span className="tabular-nums font-mono">{formatEta(etaSeconds)}</span>
        </div>
      </div>

      {/* Progress bar */}
      <div className="space-y-1.5">
        <div className="flex justify-between text-xs text-av-muted">
          <span>Progress</span>
          <span className="tabular-nums font-mono">
            {percentage !== null ? `${Math.round(percentage)}%` : '—'}
          </span>
        </div>
        <div className="h-2 w-full bg-av-border/20 dark:bg-white/10 rounded-full overflow-hidden">
          {percentage !== null ? (
            <motion.div
              className="h-full rounded-full bg-gradient-to-r from-primary-600 to-primary-400"
              initial={{ width: 0 }}
              animate={{ width: progressWidth }}
              transition={{ duration: 0.4, ease: 'easeOut' }}
            />
          ) : (
            /* Indeterminate shimmer when percentage is unknown */
            <motion.div
              className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-primary-500 to-transparent"
              animate={{ x: ['0%', '300%'] }}
              transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
            />
          )}
        </div>
      </div>

      {/* File stats row */}
      <AnimatePresence>
        {(fileSize !== null || compressionRatio !== null) && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="flex gap-4 text-xs text-av-muted"
          >
            {fileSize !== null && (
              <div className="flex items-center gap-1">
                <FileText className="w-3.5 h-3.5" />
                <span>{formatFileSize(fileSize)}</span>
              </div>
            )}
            {compressionRatio !== null && (
              <div className="flex items-center gap-1">
                <Cpu className="w-3.5 h-3.5" />
                <span>
                  {Math.round(compressionRatio * 100)}% of original
                </span>
              </div>
            )}
          </motion.div>
        )}
      </AnimatePresence>

      {/* Cancel button / cancelling state */}
      <div className="pt-1">
        <AnimatePresence mode="wait">
          {isCancelling ? (
            <motion.div
              key="cancelling"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center gap-2 text-sm text-yellow-400"
            >
              <motion.div
                animate={{ rotate: 360 }}
                transition={{ duration: 1, repeat: Infinity, ease: 'linear' }}
                className="w-4 h-4 border-2 border-yellow-400/30 border-t-yellow-400 rounded-full"
              />
              <span>Cancelling operation…</span>
            </motion.div>
          ) : (
            <motion.div key="cancel-btn" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Button
                variant="danger"
                size="sm"
                onClick={onCancel}
                className={cn('gap-1.5')}
                aria-label="Cancel operation"
              >
                <X className="w-3.5 h-3.5" />
                Cancel
              </Button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </Card>
  )
}
