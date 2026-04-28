/**
 * Reusable error display component.
 *
 * Renders a user-friendly error with an appropriate icon, message, and
 * actionable suggestion. Supports optional dismiss and retry callbacks.
 *
 * Requirements: 7.7, 22.1, 22.2, 22.10, 22.12
 */

import React from 'react'
import {
  WifiOff,
  Lock,
  KeyRound,
  FileX2,
  ShieldAlert,
  Clock,
  FileQuestion,
  AlertTriangle,
  X,
  RefreshCw,
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { cn } from '../lib/utils'
import { parseError, type AppError, type ErrorCode } from '../lib/errors'

// ─── Icon map ─────────────────────────────────────────────────────────────────

const ICON_MAP: Record<ErrorCode, React.ElementType> = {
  auth_failed: ShieldAlert,
  time_locked: Lock,
  wrong_password: KeyRound,
  file_corrupted: FileX2,
  network_error: WifiOff,
  ntp_failed: Clock,
  file_not_found: FileQuestion,
  permission_denied: ShieldAlert,
  unknown: AlertTriangle,
}

// ─── Colour map ───────────────────────────────────────────────────────────────

const COLOR_MAP: Record<ErrorCode, { bg: string; border: string; icon: string; text: string }> = {
  auth_failed:           { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
  time_locked:           { bg: 'bg-amber-500/10',  border: 'border-amber-500/30',  icon: 'text-amber-400',  text: 'text-amber-300' },
  wrong_password:        { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
  file_corrupted:        { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
  network_error:         { bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: 'text-orange-400', text: 'text-orange-300' },
  ntp_failed:            { bg: 'bg-orange-500/10', border: 'border-orange-500/30', icon: 'text-orange-400', text: 'text-orange-300' },
  file_not_found:        { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
  permission_denied:     { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
  unknown:               { bg: 'bg-red-500/10',    border: 'border-red-500/30',    icon: 'text-red-400',    text: 'text-red-300' },
}

// ─── Props ────────────────────────────────────────────────────────────────────

interface ErrorMessageProps {
  /** The error to display. Accepts an AppError, a plain string, or null/undefined. */
  error: AppError | string | null | undefined
  /** Called when the user clicks the dismiss (×) button. */
  onDismiss?: () => void
  /** Called when the user clicks the retry button. */
  onRetry?: () => void
  /** Additional Tailwind classes for the wrapper element. */
  className?: string
}

// ─── Component ────────────────────────────────────────────────────────────────

export function ErrorMessage({ error, onDismiss, onRetry, className }: ErrorMessageProps) {
  if (!error) return null

  // Normalise to AppError
  const appError: AppError =
    typeof error === 'string' ? parseError(error) : error

  const Icon = ICON_MAP[appError.code] ?? AlertTriangle
  const colors = COLOR_MAP[appError.code] ?? COLOR_MAP.unknown

  return (
    <AnimatePresence>
      <motion.div
        key="error-message"
        initial={{ opacity: 0, y: -8, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        exit={{ opacity: 0, y: -8, scale: 0.97 }}
        transition={{ duration: 0.2, ease: [0.4, 0, 0.2, 1] }}
        role="alert"
        aria-live="assertive"
        className={cn(
          'relative rounded-xl border p-4',
          colors.bg,
          colors.border,
          className
        )}
      >
        <div className="flex items-start gap-3">
          {/* Icon */}
          <div className={cn('mt-0.5 shrink-0', colors.icon)}>
            <Icon className="w-5 h-5" aria-hidden="true" />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <p className={cn('text-sm font-semibold leading-snug', colors.text)}>
              {appError.userMessage}
            </p>

            {/* Remaining time detail for time-locked errors */}
            {appError.details && (
              <p className="mt-1 text-xs font-medium text-av-main">
                {appError.details}
              </p>
            )}

            {/* Actionable suggestion */}
            <p className="mt-1.5 text-xs text-av-muted leading-relaxed">
              {appError.suggestion}
            </p>

            {/* Action buttons */}
            {onRetry && (
              <button
                onClick={onRetry}
                className={cn(
                  'mt-3 inline-flex items-center gap-1.5 text-xs font-medium',
                  'px-3 py-1.5 rounded-lg border transition-colors',
                  colors.border,
                  colors.text,
                  'hover:bg-av-border/10 dark:hover:bg-white/5'
                )}
              >
                <RefreshCw className="w-3.5 h-3.5" aria-hidden="true" />
                Try again
              </button>
            )}
          </div>

          {/* Dismiss button */}
          {onDismiss && (
            <button
              onClick={onDismiss}
              aria-label="Dismiss error"
              className="shrink-0 text-av-muted hover:text-av-main transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </motion.div>
    </AnimatePresence>
  )
}

export default ErrorMessage
