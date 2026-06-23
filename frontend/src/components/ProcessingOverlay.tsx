import { motion } from 'framer-motion'
import type { ReactNode } from 'react'
import { formatEta } from '../lib/backendProgress'

interface ProcessingOverlayProps {
  title: string
  description: string
  icon: ReactNode
  percentage?: number | null
  etaSeconds?: number | null
  elapsedSeconds?: number
  fileSize?: number | null
  sourceLabel?: string
  statusLabel?: string
  indeterminateText?: string
  children?: ReactNode
}

function formatSourceSize(fileSize: number | null | undefined): string {
  if (fileSize == null) return 'Queued'
  const mib = fileSize / (1024 * 1024)
  if (mib >= 1024) return `${(mib / 1024).toFixed(1)} GB`
  return `${Math.max(1, Math.round(mib))} MB`
}

function formatElapsed(seconds: number): string {
  const safeSeconds = Math.max(0, Math.floor(seconds))
  const minutes = Math.floor(safeSeconds / 60)
  const remainingSeconds = safeSeconds % 60
  if (minutes <= 0) return `${remainingSeconds}s`
  return `${minutes}m ${remainingSeconds.toString().padStart(2, '0')}s`
}

export default function ProcessingOverlay({
  title,
  description,
  icon,
  percentage = null,
  etaSeconds = null,
  elapsedSeconds = 0,
  fileSize = null,
  sourceLabel,
  statusLabel = 'Live',
  indeterminateText = 'Working',
  children,
}: ProcessingOverlayProps) {
  const progressValue = percentage !== null ? Math.max(0, Math.min(100, percentage)) : null
  const progressLabel = progressValue !== null ? `${Math.round(progressValue)}%` : indeterminateText
  const etaLabel = etaSeconds !== null && etaSeconds !== undefined && etaSeconds >= 0 ? formatEta(etaSeconds) : 'Time estimate calibrating'
  const sourceValue = sourceLabel ?? formatSourceSize(fileSize)

  return (
    <div className="av-decode-processing-overlay absolute inset-0 z-20 flex flex-col items-center justify-center p-5 sm:p-8">
      <motion.div
        initial={{ opacity: 0, scale: 0.98, y: 8 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.98, y: 8 }}
        className="av-decode-processing-card w-full max-w-[420px] rounded-[1.65rem] p-6"
      >
        <div className="mb-5 flex items-start gap-4">
          <div className="av-decode-pulse-shell">
            <motion.div
              className="av-decode-pulse-ring"
              animate={{ scale: [0.94, 1.08, 0.94], opacity: [0.28, 0.72, 0.28] }}
              transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut' }}
            />
            <div className="av-decode-pulse-core">{icon}</div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1.5 flex min-w-0 items-center gap-2">
              <h3 className="truncate text-lg font-semibold tracking-tight text-av-main">{title}</h3>
              <span className="shrink-0 rounded-full border border-av-accent/25 bg-av-accent/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.18em] text-av-accent">
                {statusLabel}
              </span>
            </div>
            <p className="line-clamp-2 min-h-[20px] text-sm leading-5 text-av-muted">{description}</p>
          </div>
        </div>

        <div className="mb-4 grid grid-cols-2 gap-2.5">
          <div className="av-decode-processing-stat">
            <p>Elapsed</p>
            <strong>{formatElapsed(elapsedSeconds)}</strong>
          </div>
          <div className="av-decode-processing-stat">
            <p>Input</p>
            <strong>{sourceValue}</strong>
          </div>
        </div>

        <div className="mb-2.5 flex items-center justify-between gap-4 text-xs text-av-muted">
          <span className="truncate font-medium text-av-main">{progressLabel}</span>
          <span className="shrink-0">{etaLabel}</span>
        </div>
        <div className="av-decode-progress-track">
          {progressValue !== null ? (
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${progressValue}%` }}
              className="av-decode-progress-fill"
            />
          ) : (
            <motion.div
              className="av-decode-progress-sweep"
              animate={{ x: ['-35%', '340%'] }}
              transition={{ duration: 1.05, repeat: Infinity, ease: 'easeInOut' }}
            />
          )}
        </div>

        {children && <div className="mt-5 border-t border-av-border/35 pt-4">{children}</div>}
      </motion.div>
    </div>
  )
}
