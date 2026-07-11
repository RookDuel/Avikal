import { AlertTriangle, WifiOff } from 'lucide-react'
import { useNTPTime } from '../hooks/useNTPTime'

interface TrustedTimeNoticeProps {
  enabled: boolean
  context?: 'timecapsule' | 'decode'
}

export default function TrustedTimeNotice({ enabled, context = 'timecapsule' }: TrustedTimeNoticeProps) {
  const { clockSkewWarning, error } = useNTPTime({ pollIntervalMs: 10_000, forceRefresh: true })

  if (!enabled) return null

  if (clockSkewWarning) {
    return (
      <div className="mx-auto mb-4 w-full max-w-[94rem] px-4 sm:px-6">
        <div className="trusted-time-notice trusted-time-notice-danger flex items-start gap-3 rounded-2xl border px-4 py-3 shadow-[0_14px_34px_rgba(239,68,68,0.12)]">
          <AlertTriangle className="trusted-time-notice-icon mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
          <div className="min-w-0">
            <p className="trusted-time-notice-title text-sm font-bold tracking-tight">System clock is out of sync with trusted network time.</p>
            <p className="trusted-time-notice-body mt-1 text-xs font-medium leading-relaxed">
              Correct your device date and time settings before using drand Time-Capsule operations. This warning will disappear automatically after the clock matches trusted time.
            </p>
            <p className="trusted-time-notice-detail mt-1 text-[11px] font-medium">{clockSkewWarning}</p>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    const action = context === 'decode' ? 'unlock drand Time-Capsule archives' : 'create drand Time-Capsules'
    return (
      <div className="mx-auto mb-4 w-full max-w-[94rem] px-4 sm:px-6">
        <div className="trusted-time-notice trusted-time-notice-warning flex items-start gap-3 rounded-2xl border px-4 py-3 shadow-[0_14px_34px_rgba(245,158,11,0.12)]">
          <WifiOff className="trusted-time-notice-icon mt-0.5 h-5 w-5 shrink-0" strokeWidth={1.8} />
          <div className="min-w-0">
            <p className="trusted-time-notice-title text-sm font-bold tracking-tight">Trusted network time is unavailable.</p>
            <p className="trusted-time-notice-body mt-1 text-xs font-medium leading-relaxed">
              Connect to the internet to {action}. The notice will disappear automatically when Avikal can verify trusted time again.
            </p>
            <p className="trusted-time-notice-detail mt-1 text-[11px] font-medium">{error}</p>
          </div>
        </div>
      </div>
    )
  }

  return null
}
