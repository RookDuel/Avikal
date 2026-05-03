/**
 * Polls the backend /api/ntp-time endpoint every 60 seconds and returns
 * the current trusted time formatted in the user's local timezone.
 */

import { useState, useEffect, useRef } from 'react'
import { fetchBackend } from '../lib/backend'
const POLL_INTERVAL_MS = 60_000

function getLocalTimeZoneLabel(ms: number): string {
  const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(new Date(ms))
  return parts.find((part) => part.type === 'timeZoneName')?.value ?? Intl.DateTimeFormat().resolvedOptions().timeZone ?? 'Local'
}

function formatLocalTime(ms: number): string {
  const label = getLocalTimeZoneLabel(ms)
  const time = new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(ms))
  return `${time} ${label}`
}

export interface NTPTimeState {
  timeDisplay: string | null
  synced: boolean
  clockSkewWarning: string | null
  error: string | null
  timeZoneLabel: string | null
}

export function useNTPTime(): NTPTimeState {
  const [state, setState] = useState<NTPTimeState>({
    timeDisplay: null,
    synced: false,
    clockSkewWarning: null,
    error: null,
    timeZoneLabel: null,
  })

  const ntpRef = useRef<{ ntpMs: number; fetchedAt: number } | null>(null)
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null)

  async function fetchNTPTime() {
    try {
      const res = await fetchBackend('/api/ntp-time', {}, 8000)
      const data = await res.json()

      if (data.success && data.timestamp) {
        const ntpMs = data.timestamp * 1000
        ntpRef.current = { ntpMs, fetchedAt: Date.now() }
        setState({
          timeDisplay: formatLocalTime(ntpMs),
          synced: true,
          clockSkewWarning: data.clock_skew_warning ?? null,
          error: null,
          timeZoneLabel: getLocalTimeZoneLabel(ntpMs),
        })
      } else {
        setState((prev) => ({
          ...prev,
          synced: false,
          error: data.error ?? 'NTP sync failed',
        }))
      }
    } catch {
      setState((prev) => ({
        ...prev,
        synced: false,
        error: 'Time verification failed. Check your internet connection.',
      }))
    }
  }

  function startTick() {
    if (tickRef.current) clearInterval(tickRef.current)
    tickRef.current = setInterval(() => {
      if (!ntpRef.current) return
      const { ntpMs, fetchedAt } = ntpRef.current
      const elapsed = Date.now() - fetchedAt
      const currentMs = ntpMs + elapsed
      setState((prev) => ({
        ...prev,
        timeDisplay: formatLocalTime(currentMs),
        timeZoneLabel: getLocalTimeZoneLabel(currentMs),
      }))
    }, 1000)
  }

  useEffect(() => {
    fetchNTPTime()
    startTick()
    pollRef.current = setInterval(fetchNTPTime, POLL_INTERVAL_MS)

    return () => {
      if (tickRef.current) clearInterval(tickRef.current)
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  return state
}
