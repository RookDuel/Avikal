/**
 * Displays current trusted time in the user's local timezone in the application header.
 * Shows a warning if system clock differs by more than 5 minutes.
 */

import { Clock, AlertTriangle, WifiOff } from 'lucide-react'
import { useNTPTime } from '../hooks/useNTPTime'
import { cn } from '../lib/utils'

interface NTPClockProps {
  className?: string
}

export function NTPClock({ className }: NTPClockProps) {
  const { timeDisplay, synced, clockSkewWarning, error } = useNTPTime()

  if (error && !timeDisplay) {
    return (
      <div
        className={cn(
          'flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-xs',
          className
        )}
        title={error}
      >
        <WifiOff className="w-3 h-3 flex-shrink-0" />
        <span>NTP Error</span>
      </div>
    )
  }

  if (!timeDisplay) {
    return (
      <div
        className={cn(
          'flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-av-border/10 dark:bg-white/5 border border-av-border/50 text-av-muted text-xs',
          className
        )}
      >
        <Clock className="w-3 h-3 flex-shrink-0 animate-pulse" />
        <span>Syncing...</span>
      </div>
    )
  }

  return (
    <div
      className={cn(
        'flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-mono',
        clockSkewWarning
          ? 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400'
          : synced
          ? 'bg-av-border/10 dark:bg-white/5 border-av-border/50 text-av-main'
          : 'bg-av-border/10 dark:bg-white/5 border-av-border/50 text-av-muted',
        className
      )}
      title={
        clockSkewWarning
          ? clockSkewWarning
          : synced
          ? 'Trusted network time from time.google.com'
          : 'Using cached NTP time'
      }
    >
      {clockSkewWarning ? (
        <AlertTriangle className="w-3 h-3 flex-shrink-0" />
      ) : (
        <Clock className="w-3 h-3 flex-shrink-0" />
      )}
      <span>{timeDisplay}</span>
    </div>
  )
}
