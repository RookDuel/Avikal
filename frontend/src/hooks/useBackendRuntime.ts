import { useEffect, useMemo, useState } from 'react'
import { getBackendStatus } from '../lib/backendStatus'
import type { BackendRuntimeStatus } from '../types/electron'

export interface BackendRuntimeView {
  status: BackendRuntimeStatus | null
  isReady: boolean
  isStarting: boolean
  isUnavailable: boolean
  label: string
  detail: string
}

export function useBackendRuntime(): BackendRuntimeView {
  const [status, setStatus] = useState<BackendRuntimeStatus | null>(null)

  useEffect(() => {
    let cancelled = false
    let unsubscribe: (() => void) | undefined

    void (async () => {
      const current = await getBackendStatus()
      if (!cancelled) {
        setStatus(current)
      }
      unsubscribe = window.electron?.onBackendStatus?.((nextStatus) => {
        if (!cancelled) {
          setStatus(nextStatus)
        }
      })
    })()

    return () => {
      cancelled = true
      unsubscribe?.()
    }
  }, [])

  return useMemo(() => {
    const state = status?.state || 'starting'
    const isReady = state === 'ready'
    const isUnavailable = state === 'error' || state === 'stopped'
    const isStarting = !isReady && !isUnavailable

    return {
      status,
      isReady,
      isStarting,
      isUnavailable,
      label: isReady ? 'Secure engine ready' : isUnavailable ? 'Secure engine unavailable' : 'Starting secure engine',
      detail: isReady
        ? 'Encryption services are ready.'
        : isUnavailable
          ? status?.error || 'The local backend is unavailable.'
          : status?.error || 'Preparing local encryption services...',
    }
  }, [status])
}
