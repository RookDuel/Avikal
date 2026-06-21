interface PasswordStrengthMeterProps {
  password: string
  title?: string
  compact?: boolean
  invalidMessage?: string
  className?: string
}

function scorePassword(password: string): number {
  if (!password) return 0
  let score = 0
  if (password.length >= 12) score += 35
  else if (password.length >= 8) score += 18
  if (/[A-Z]/.test(password)) score += 15
  if (/[a-z]/.test(password)) score += 15
  if (/[0-9]/.test(password)) score += 15
  if (/[^A-Za-z0-9]/.test(password)) score += 20
  return Math.min(score, 100)
}

export function getPasswordRuleState(password: string) {
  return {
    hasMinLen: password.length >= 12,
    hasUpper: /[A-Z]/.test(password),
    hasLower: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecial: /[^A-Za-z0-9]/.test(password),
  }
}

export function isStrongPassword(password: string): boolean {
  const rules = getPasswordRuleState(password)
  return rules.hasMinLen && rules.hasUpper && rules.hasLower && rules.hasNumber && rules.hasSpecial
}

function getStrengthTone(score: number, invalidMessage?: string) {
  if (invalidMessage) {
    return {
      label: 'BLOCKED',
      labelClass: 'text-red-500',
      barClass: 'bg-red-500',
    }
  }
  if (score < 40) {
    return {
      label: 'WEAK',
      labelClass: 'text-red-500',
      barClass: 'bg-red-500',
    }
  }
  if (score < 80) {
    return {
      label: 'MODERATE',
      labelClass: 'text-amber-500',
      barClass: 'bg-amber-500',
    }
  }
  return {
    label: 'READY',
    labelClass: 'text-emerald-500',
    barClass: 'bg-emerald-500',
  }
}

function RulePill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div
      className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-[11px] font-semibold transition-colors ${
        ok
          ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
          : 'border-av-border/40 bg-av-surface/55 text-av-muted'
      }`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full transition-colors ${
          ok ? 'bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.55)]' : 'bg-av-border/70 dark:bg-white/20'
        }`}
      />
      {label}
    </div>
  )
}

export default function PasswordStrengthMeter({
  password,
  title = 'Password Strength',
  compact = false,
  invalidMessage,
  className = '',
}: PasswordStrengthMeterProps) {
  const rules = getPasswordRuleState(password)
  const score = scorePassword(password)
  const tone = getStrengthTone(score, invalidMessage)
  const displayScore = invalidMessage ? Math.max(score, 8) : score

  return (
    <div
      className={`rounded-2xl border border-av-border/40 bg-white/74 p-4 shadow-[0_12px_30px_rgba(15,23,42,0.06)] backdrop-blur-xl dark:bg-white/[0.045] dark:shadow-[inset_0_1px_0_rgba(255,255,255,0.04)] ${className}`}
    >
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-av-muted">{title}</p>
          {!compact && <p className="mt-1 text-[11px] text-av-muted">12+ chars with mixed case, number, and symbol.</p>}
        </div>
        <span className={`rounded-full border border-current/20 px-2.5 py-1 text-[10px] font-bold tracking-[0.14em] ${tone.labelClass}`}>
          {tone.label}
        </span>
      </div>

      <div className="mb-3 h-2 overflow-hidden rounded-full bg-av-border/35 shadow-inner dark:bg-black/35">
        <div
          style={{ width: `${displayScore}%` }}
          className={`h-full rounded-full transition-all duration-500 ease-out ${tone.barClass}`}
        />
      </div>

      <div className={`grid gap-2 ${compact ? 'grid-cols-2' : 'grid-cols-2 sm:grid-cols-3'}`}>
        <RulePill ok={rules.hasMinLen} label="12+ chars" />
        <RulePill ok={rules.hasUpper} label="Uppercase" />
        <RulePill ok={rules.hasLower} label="Lowercase" />
        <RulePill ok={rules.hasNumber} label="Number" />
        <RulePill ok={rules.hasSpecial} label="Symbol" />
      </div>

      {invalidMessage && (
        <p className="mt-3 rounded-xl border border-red-500/20 bg-red-500/10 px-3 py-2 text-[11px] font-semibold text-red-500">
          {invalidMessage}
        </p>
      )}
    </div>
  )
}
