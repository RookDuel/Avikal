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
  if (fileSize < 1024) return `${fileSize} B`
  if (fileSize < 1024 * 1024) return `${(fileSize / 1024).toFixed(fileSize < 10 * 1024 ? 1 : 0)} KB`
  const mib = fileSize / (1024 * 1024)
  if (mib >= 1024) return `${(mib / 1024).toFixed(1)} GB`
  return `${mib.toFixed(mib < 10 ? 1 : 0)} MB`
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
    <div className="av-decode-processing-overlay absolute inset-0 z-20 flex flex-col items-center justify-center p-4 sm:p-6">
      <motion.div
        initial={{ opacity: 0, scale: 0.99, y: 6 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.99, y: 6 }}
        transition={{ duration: 0.18, ease: 'easeOut' }}
        className="av-decode-processing-card w-full max-w-[380px] rounded-[1.35rem] p-5"
      >
        <div className="mb-4 flex items-start gap-3">
          <div className="av-decode-pulse-shell">
            <div className="av-decode-pulse-core">{icon}</div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex min-w-0 items-center justify-between gap-3">
              <h3 className="truncate text-base font-semibold tracking-tight text-av-main">{title}</h3>
              <span className="shrink-0 text-[9px] font-bold uppercase tracking-[0.18em] text-av-muted">
                {statusLabel}
              </span>
            </div>
            <p className="line-clamp-2 min-h-[18px] text-xs leading-5 text-av-muted">{description}</p>
          </div>
        </div>

        <div className="mb-2.5 flex items-center justify-between gap-4 text-xs">
          <span className="truncate font-semibold text-av-main">{progressLabel}</span>
          <span className="shrink-0 text-av-muted">{etaLabel}</span>
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

        <div className="mt-3 flex items-center justify-between gap-3 text-[11px] font-medium text-av-muted">
          <span>Elapsed {formatElapsed(elapsedSeconds)}</span>
          <span className="truncate">{sourceValue}</span>
        </div>

        {children && <div className="mt-4 border-t border-av-border/35 pt-4">{children}</div>}
      </motion.div>
    </div>
  )
}
