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

  return (
    <div className="av-decode-processing-overlay absolute inset-0 z-20 flex flex-col items-center justify-center p-8">
      <motion.div
        initial={{ opacity: 0, scale: 0.97, y: 10 }}
        animate={{ opacity: 1, scale: 1, y: 0 }}
        exit={{ opacity: 0, scale: 0.97, y: 10 }}
        className="av-decode-processing-card w-full max-w-md rounded-[2rem] p-7"
      >
        <div className="mb-6 flex items-start gap-4">
          <div className="av-decode-pulse-shell">
            <motion.div
              className="av-decode-pulse-ring"
              animate={{ scale: [0.88, 1.12, 0.88], opacity: [0.45, 0.95, 0.45] }}
              transition={{ duration: 1.8, repeat: Infinity, ease: 'easeInOut' }}
            />
            <div className="av-decode-pulse-core">{icon}</div>
          </div>
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex items-center gap-2">
              <h3 className="text-xl font-semibold tracking-tight text-av-main">{title}</h3>
              <span className="rounded-full border border-av-accent/25 bg-av-accent/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.18em] text-av-accent">
                {statusLabel}
              </span>
            </div>
            <p className="min-h-[20px] truncate text-sm font-light text-av-muted">{description}</p>
          </div>
        </div>

        <div className="mb-3 grid grid-cols-3 gap-2">
          {[
            ['Elapsed', `${elapsedSeconds}s`],
            ['Progress', progressValue !== null ? `${Math.round(progressValue)}%` : 'Active'],
            ['Source', sourceLabel ?? formatSourceSize(fileSize)],
          ].map(([label, value]) => (
            <div key={label} className="rounded-2xl border border-av-border/35 bg-av-surface/45 px-3 py-2">
              <p className="text-[9px] font-semibold uppercase tracking-[0.16em] text-av-muted/75">{label}</p>
              <p className="mt-0.5 truncate text-xs font-semibold text-av-main">{value}</p>
            </div>
          ))}
        </div>

        <div className="mb-2 flex items-center justify-between text-xs text-av-muted">
          <span>{progressValue !== null ? `${Math.round(progressValue)}% complete` : indeterminateText}</span>
          <span>{formatEta(etaSeconds)}</span>
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

        {children && <div className="mt-5 border-t border-av-border/20 pt-4">{children}</div>}
      </motion.div>
    </div>
  )
}
