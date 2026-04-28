import { useState, useCallback, useRef, useEffect } from 'react'

export type ProgressStatus = 'idle' | 'running' | 'cancelled' | 'completed' | 'error'

export interface ProgressState {
  status: ProgressStatus
  percentage: number | null
  currentOperation: string
  etaSeconds: number | null
  fileSize: number | null
  compressionRatio: number | null
  isCancelling: boolean
  elapsedSeconds: number
}

export interface ProgressControls {
  /** Partially update progress state (cannot touch isCancelling or elapsedSeconds directly) */
  update: (partial: Partial<Omit<ProgressState, 'isCancelling' | 'elapsedSeconds'>>) => void
  /** Trigger cancellation: sets isCancelling, aborts the AbortController, calls optional abort callback */
  cancel: () => void
  /** Reset all state back to idle and clear the abort controller */
  reset: () => void
  /**
   * Register an external abort callback (e.g. to cancel a fetch or IPC call).
   * Pass null to clear it.
   */
  setAbortCallback: (cb: (() => void) | null) => void
  /**
   * Returns a fresh AbortSignal for the current operation.
   * A new controller is created on each call to reset().
   */
  getAbortSignal: () => AbortSignal
}

const initialState: ProgressState = {
  status: 'idle',
  percentage: null,
  currentOperation: '',
  etaSeconds: null,
  fileSize: null,
  compressionRatio: null,
  isCancelling: false,
  elapsedSeconds: 0,
}

export function useProgress(): ProgressState & ProgressControls {
  const [state, setState] = useState<ProgressState>(initialState)

  // External abort callback (e.g. cancel a fetch)
  const abortCallbackRef = useRef<(() => void) | null>(null)

  // AbortController for the current operation
  const abortControllerRef = useRef<AbortController>(new AbortController())

  // Interval ref for the elapsed-time counter
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  // Start/stop the elapsed-time counter based on status
  useEffect(() => {
    if (state.status === 'running' && !timerRef.current) {
      timerRef.current = setInterval(() => {
        setState(prev => ({ ...prev, elapsedSeconds: prev.elapsedSeconds + 1 }))
      }, 1000)
    }

    if (state.status !== 'running' && timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }

    return () => {
      if (timerRef.current) {
        clearInterval(timerRef.current)
        timerRef.current = null
      }
    }
  }, [state.status])

  const update = useCallback(
    (partial: Partial<Omit<ProgressState, 'isCancelling' | 'elapsedSeconds'>>) => {
      setState(prev => ({ ...prev, ...partial }))
    },
    []
  )

  const cancel = useCallback(() => {
    setState(prev => ({ ...prev, isCancelling: true }))

    // Abort via AbortController
    abortControllerRef.current.abort()

    // Call any registered external abort callback
    if (abortCallbackRef.current) {
      abortCallbackRef.current()
    }
  }, [])

  const reset = useCallback(() => {
    // Clear timer
    if (timerRef.current) {
      clearInterval(timerRef.current)
      timerRef.current = null
    }

    // Fresh AbortController for the next operation
    abortControllerRef.current = new AbortController()
    abortCallbackRef.current = null

    setState(initialState)
  }, [])

  const setAbortCallback = useCallback((cb: (() => void) | null) => {
    abortCallbackRef.current = cb
  }, [])

  const getAbortSignal = useCallback((): AbortSignal => {
    return abortControllerRef.current.signal
  }, [])

  return {
    ...state,
    update,
    cancel,
    reset,
    setAbortCallback,
    getAbortSignal,
  }
}
