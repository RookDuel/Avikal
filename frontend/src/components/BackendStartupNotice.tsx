import { AlertCircle, PlugZap } from 'lucide-react'
import { cn } from '../lib/utils'
import type { BackendRuntimeView } from '../hooks/useBackendRuntime'

interface BackendStartupNoticeProps {
  backend: BackendRuntimeView
  compact?: boolean
}

export default function BackendStartupNotice({ backend, compact = false }: BackendStartupNoticeProps) {
  if (backend.isReady) return null

  return (
    <div
      className={cn(
        'rounded-2xl border backdrop-blur-xl transition-colors',
        compact ? 'p-3' : 'p-4',
        backend.isUnavailable
          ? 'border-red-500/25 bg-red-500/10 text-red-500'
          : 'border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-300',
      )}
    >
      <div className="flex items-start gap-3">
        <div
          className={cn(
            'mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border',
            backend.isUnavailable
              ? 'border-red-500/25 bg-red-500/10'
              : 'border-amber-500/25 bg-amber-500/10',
          )}
        >
          {backend.isUnavailable ? (
            <AlertCircle className="h-4 w-4" />
          ) : (
            <PlugZap className="h-4 w-4 animate-pulse" />
          )}
        </div>
        <div className="min-w-0">
          <p className="text-sm font-semibold tracking-tight">{backend.label}</p>
          <p className="mt-1 text-xs leading-relaxed opacity-80">{backend.detail}</p>
        </div>
      </div>
    </div>
  )
}
