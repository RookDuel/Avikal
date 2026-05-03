import type { BackendRuntimeStatus } from '../types/electron'
import { DEFAULT_BACKEND_BASE_URL } from './backend'

const DEFAULT_BROWSER_STATUS: BackendRuntimeStatus = {
  state: 'ready',
  baseUrl: DEFAULT_BACKEND_BASE_URL,
  error: null,
  updatedAt: Date.now(),
}

export async function getBackendStatus(): Promise<BackendRuntimeStatus> {
  if (typeof window === 'undefined' || !window.electron?.getBackendStatus) {
    return DEFAULT_BROWSER_STATUS
  }

  try {
    return await window.electron.getBackendStatus()
  } catch {
    return DEFAULT_BROWSER_STATUS
  }
}

export async function waitForBackendReady(timeoutMs = 60_000): Promise<void> {
  if (typeof window === 'undefined' || !window.electron?.getBackendStatus) {
    return
  }

  const initialStatus = await getBackendStatus()
  if (initialStatus.state === 'ready') return
  if (initialStatus.state === 'error') {
    throw new Error(initialStatus.error || 'Local backend failed to start')
  }

  await new Promise<void>((resolve, reject) => {
    let unsubscribe: (() => void) | undefined
    const timer = window.setTimeout(() => {
      unsubscribe?.()
      reject(new Error(`Local backend was not ready after ${Math.round(timeoutMs / 1000)}s`))
    }, timeoutMs)

    const handleStatus = (status: BackendRuntimeStatus) => {
      if (status.state === 'ready') {
        window.clearTimeout(timer)
        unsubscribe?.()
        resolve()
      } else if (status.state === 'error' || status.state === 'stopped') {
        window.clearTimeout(timer)
        unsubscribe?.()
        reject(new Error(status.error || 'Local backend is unavailable'))
      }
    }

    unsubscribe = window.electron?.onBackendStatus?.(handleStatus)

    if (!unsubscribe) {
      window.clearTimeout(timer)
      resolve()
      return
    }

    void getBackendStatus().then(handleStatus)
  })
}
