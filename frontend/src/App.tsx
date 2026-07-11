import { useState, useEffect, type CSSProperties, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Lock, Unlock, Minus, Square, X, Clock, Settings, RotateCw } from 'lucide-react'
import { Toaster } from 'sonner'
import Encrypt from './pages/Encrypt'
import Decrypt from './pages/Decrypt'
import Rekey from './pages/Rekey'
import TimeCapsule from './pages/TimeCapsule'
import { AuthProvider } from './contexts/AuthContext'
import { ThemeProvider, useTheme } from './contexts/ThemeContext'
import SecuritySettings from './components/SecuritySettings'
import { ErrorBoundary } from './components/ErrorBoundary'
import { cn } from './lib/utils'
import { useBackendRuntime } from './hooks/useBackendRuntime'
import type { ExternalLaunchAction, PendingExternalLaunchAction } from './lib/externalLaunch'
import { AVIKAL_IS_BETA } from './lib/appMetadata'
import { loadUserPreferences, USER_PREFERENCES_UPDATED_EVENT, type UserPreferences, type VisualEffectsMode } from './lib/preferences'

type Tab = 'encrypt' | 'decrypt' | 'rekey' | 'timecapsule'
type SettingsTab = 'appearance' | 'aavrit' | 'privacy' | 'defaults' | 'runtime' | 'diagnostics' | 'updates' | 'help'
type RuntimeVisualMode = 'effects' | 'normal'

const NO_DRAG_REGION_STYLE: CSSProperties & { WebkitAppRegion: 'no-drag' } = {
  WebkitAppRegion: 'no-drag',
}

function applyVisualModeClass(mode: RuntimeVisualMode) {
  const root = window.document.documentElement
  root.classList.remove('av-visual-effects', 'av-visual-normal')
  root.classList.add(mode === 'effects' ? 'av-visual-effects' : 'av-visual-normal')
  window.document.body.classList.toggle('effects-enabled', mode === 'effects')
}

async function resolveVisualMode(preference: VisualEffectsMode): Promise<RuntimeVisualMode> {
  if (preference === 'effects' || preference === 'normal') {
    const result = await window.electron?.setVisualMode?.(preference).catch(() => null)
    if (result?.mode === 'effects' || result?.mode === 'normal') return result.mode
    return preference
  }

  const result = await window.electron?.getVisualMode?.().catch(() => null)
  const automaticMode = result?.automaticMode === 'effects' ? 'effects' : 'normal'
  const applied = await window.electron?.setVisualMode?.(automaticMode).catch(() => null)
  return applied?.mode === 'effects' ? 'effects' : automaticMode
}

function BetaBadge({ compact = false }: { compact?: boolean }) {
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border border-av-border/70 bg-av-surface/80 text-av-muted shadow-sm',
        compact ? 'px-1.5 py-0.5 text-[10px] leading-none font-semibold uppercase tracking-[0.22em]' : 'px-2 py-1 text-[11px] leading-none font-semibold uppercase tracking-[0.24em]',
      )}
    >
      Beta
    </span>
  )
}

function BrandLockup({ compact = false }: { compact?: boolean }) {
  return (
    <div className={cn('flex gap-2.5', compact ? 'items-center' : 'items-start')}>
      <span className={cn(compact ? 'text-sm leading-none font-medium tracking-wide text-av-main whitespace-nowrap' : 'text-[2.45rem] leading-none font-light tracking-[0.22em] text-av-main')}>
        RookDuel Avikal
      </span>
      {AVIKAL_IS_BETA && (
        <div className={cn(compact ? 'flex items-center self-center' : 'pt-1')}>
          <BetaBadge compact={compact} />
        </div>
      )}
    </div>
  )
}

function StartupShell({
  isVisible,
  backendLabel,
  backendDetail,
  isUnavailable,
}: {
  isVisible: boolean
  backendLabel: string
  backendDetail: string
  isUnavailable: boolean
}) {
  return (
    <div
      className="flex min-h-screen items-center justify-center px-6 py-10 transition-colors duration-500"
      style={{ background: 'var(--av-bg-gradient)' }}
    >
      <motion.div
        initial={{ opacity: 0, y: 16, scale: 0.985 }}
        animate={{ opacity: isVisible ? 1 : 0, y: isVisible ? 0 : 10, scale: isVisible ? 1 : 0.99 }}
        transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
        className="relative w-full max-w-[34rem] px-2 py-2"
      >
        <div className="relative flex flex-col items-center gap-6 text-center">
          <BrandLockup />
          <div className="w-full max-w-md space-y-3">
            <p className="text-sm font-medium uppercase tracking-[0.24em] text-av-muted">
              {isUnavailable ? 'Connection failed' : AVIKAL_IS_BETA ? 'Initializing beta engine' : 'Initializing secure engine'}
            </p>
            <p className="text-sm leading-7 text-av-muted">
              {isUnavailable
                ? backendDetail
                : AVIKAL_IS_BETA
                  ? 'Avikal Beta opens when the local backend is ready.'
                  : 'Avikal opens when the local backend is ready.'}
            </p>
          </div>
          <div className="w-full max-w-md space-y-3">
            <div className="flex items-center justify-between gap-3 text-xs font-medium uppercase tracking-[0.2em] text-av-muted">
              <span>{backendLabel}</span>
              <span
                className={cn(
                  'inline-flex h-2.5 w-2.5 rounded-full border',
                  isUnavailable ? 'border-red-400 bg-red-500' : 'border-amber-300 bg-amber-400 animate-pulse',
                )}
              />
            </div>
            <div className="h-1 overflow-hidden rounded-full bg-av-border/45">
              <motion.div
                initial={{ x: '-70%' }}
                animate={isUnavailable ? { x: 0 } : { x: ['-70%', '10%', '92%'] }}
                transition={isUnavailable ? { duration: 0.2 } : { duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
                className={cn(
                  'h-full rounded-full',
                  isUnavailable ? 'w-full bg-red-500/80' : AVIKAL_IS_BETA ? 'w-1/4 bg-av-accent' : 'w-1/3 bg-av-main',
                )}
              />
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

function AppContent() {
  const [activeTab, setActiveTab] = useState<Tab>('encrypt')
  const [visitedTabs, setVisitedTabs] = useState<Tab[]>(['encrypt'])
  const [showSecuritySettings, setShowSecuritySettings] = useState(false)
  const [settingsInitialTab, setSettingsInitialTab] = useState<SettingsTab>('appearance')
  const [showContent, setShowContent] = useState(false)
  const [pendingExternalLaunch, setPendingExternalLaunch] = useState<PendingExternalLaunchAction | null>(null)
  const backendRuntime = useBackendRuntime()
  const { actualTheme } = useTheme()

  useEffect(() => {
    let cancelled = false

    const applyFromPreferences = async (prefs: UserPreferences = loadUserPreferences()) => {
      const mode = await resolveVisualMode(prefs.appearance.visual_effects_mode)
      if (!cancelled) applyVisualModeClass(mode)
    }

    void applyFromPreferences()
    const handlePreferenceUpdate = (event: Event) => {
      const next = (event as CustomEvent<UserPreferences>).detail ?? loadUserPreferences()
      void applyFromPreferences(next)
    }
    const removeVisualModeListener = window.electron?.onVisualModeChanged?.((status) => {
      if (!cancelled) applyVisualModeClass(status.mode === 'effects' ? 'effects' : 'normal')
    })

    window.addEventListener(USER_PREFERENCES_UPDATED_EVENT, handlePreferenceUpdate)
    return () => {
      cancelled = true
      window.removeEventListener(USER_PREFERENCES_UPDATED_EVENT, handlePreferenceUpdate)
      removeVisualModeListener?.()
    }
  }, [])

  useEffect(() => {
    if (backendRuntime.isReady) {
      const timer = window.setTimeout(() => setShowContent(true), 180)
      return () => window.clearTimeout(timer)
    }

    setShowContent(false)
    return undefined
  }, [backendRuntime.isReady])

  useEffect(() => {
    const openAavritSettings = () => {
      setSettingsInitialTab('aavrit')
      setShowSecuritySettings(true)
    }
    window.addEventListener('avikal:open-auth-modal', openAavritSettings)
    window.addEventListener('avikal:open-aavrit-settings', openAavritSettings)
    return () => {
      window.removeEventListener('avikal:open-auth-modal', openAavritSettings)
      window.removeEventListener('avikal:open-aavrit-settings', openAavritSettings)
    }
  }, [])

  useEffect(() => {
    setVisitedTabs((current) => (current.includes(activeTab) ? current : [...current, activeTab]))
  }, [activeTab])

  useEffect(() => {
    const handleExternalLaunch = (action: ExternalLaunchAction | null | undefined) => {
      if (!action || (action.target !== 'encrypt' && action.target !== 'timecapsule') || action.paths.length === 0) {
        return
      }

      setActiveTab(action.target)
      setPendingExternalLaunch({
        ...action,
        nonce: Date.now(),
      })
    }

    let unsubscribe: (() => void) | undefined

    void (async () => {
      const pending = await window.electron?.getPendingLaunchAction?.()
      handleExternalLaunch(pending)
      unsubscribe = window.electron?.onLaunchAction?.(handleExternalLaunch)
    })()

    return () => {
      unsubscribe?.()
    }
  }, [])

  const mountedTabs: Tab[] = visitedTabs

  const tabPanels: Record<Tab, ReactNode> = {
    encrypt: (
      <ErrorBoundary context="Encrypt">
        <Encrypt externalLaunchAction={pendingExternalLaunch} />
      </ErrorBoundary>
    ),
    decrypt: (
      <ErrorBoundary context="Decrypt">
        <Decrypt />
      </ErrorBoundary>
    ),
    rekey: (
      <ErrorBoundary context="Rekey">
        <Rekey />
      </ErrorBoundary>
    ),
    timecapsule: (
      <ErrorBoundary context="TimeCapsule">
        <TimeCapsule externalLaunchAction={pendingExternalLaunch} />
      </ErrorBoundary>
    ),
  }

  if (!showContent) {
    return (
      <StartupShell
        isVisible={!showContent}
        backendLabel={backendRuntime.label}
        backendDetail={backendRuntime.detail}
        isUnavailable={backendRuntime.isUnavailable}
      />
    )
  }

  return (
    <div
      className="min-h-screen w-full font-sans flex flex-col transition-all duration-500"
      style={{
        background: 'var(--av-bg-gradient)',
        color: 'var(--av-text-main)',
      }}
    >
      <Toaster position="top-right" theme={actualTheme} richColors />

      <div className="av-titlebar-glass fixed inset-x-0 top-0 z-[220] drag-region transition-all duration-300">
        <div className="flex min-h-16 items-center pl-4 sm:pl-5 lg:pl-6">
          <div className="flex min-w-0 items-center gap-3 pr-4">
            <div className="min-w-0">
              <BrandLockup compact />
            </div>
            <span
              className={cn(
                'h-2.5 w-2.5 shrink-0 rounded-full border',
                backendRuntime.isReady
                  ? 'bg-emerald-500 border-emerald-400'
                  : backendRuntime.isUnavailable
                    ? 'bg-red-500 border-red-400'
                    : 'bg-amber-400 border-amber-300 animate-pulse',
              )}
              title={backendRuntime.detail}
            />
          </div>

          <nav
            className="flex min-w-0 flex-1 items-center gap-1 overflow-x-auto custom-scrollbar px-2 py-2"
            style={NO_DRAG_REGION_STYLE}
          >
            {[
              { id: 'encrypt', icon: Lock, label: 'Encode' },
              { id: 'decrypt', icon: Unlock, label: 'Decode' },
              { id: 'rekey', icon: RotateCw, label: 'Rekey' },
              { id: 'timecapsule', icon: Clock, label: 'Time-Capsule' },
            ].map((tab) => (
              <motion.button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as Tab)}
                className={cn(
                  'relative flex h-10 shrink-0 items-center gap-2 rounded-xl px-3 font-medium transition-all group',
                  activeTab === tab.id
                    ? 'bg-av-border/14 text-av-main shadow-[inset_0_0_0_1px_rgba(58,87,232,0.14)]'
                    : 'text-av-muted hover:bg-av-border/10 hover:text-av-main',
                )}
              >
                <div
                  className={cn(
                    'rounded-lg p-1.5 transition-colors',
                    activeTab === tab.id ? 'bg-av-main/10' : 'group-hover:bg-av-border/20',
                  )}
                >
                  <tab.icon className="w-4 h-4" />
                </div>
                <span className="text-sm font-medium tracking-wide">{tab.label}</span>

                {activeTab === tab.id && (
                  <motion.div
                    layoutId="activeNavTab"
                    className="absolute inset-x-3 bottom-0 h-[3px] rounded-t-full bg-av-accent"
                    transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                  />
                )}
              </motion.button>
            ))}
          </nav>

          <div className="flex shrink-0 items-center gap-2 border-l border-av-border/20 pl-3 sm:gap-3 sm:pl-4" style={NO_DRAG_REGION_STYLE}>
            <motion.button
              whileHover={{ scale: 1.05, rotate: 15 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => {
                setSettingsInitialTab('appearance')
                setShowSecuritySettings(true)
              }}
              className="flex h-9 w-9 items-center justify-center rounded-xl border border-av-border/35 bg-av-surface/82 text-av-muted shadow-[0_1px_2px_rgba(15,23,42,0.05)] transition-all hover:border-av-border/55 hover:bg-av-border/12 hover:text-av-main hover:shadow-[0_10px_22px_rgba(15,23,42,0.08)] dark:bg-white/[0.03] dark:hover:shadow-[0_12px_24px_rgba(0,0,0,0.28)]"
              title="Global Settings"
            >
              <Settings className="w-4 h-4" />
            </motion.button>

            <div className="flex self-stretch border-l border-av-border/20 pl-1">
              <button
                onClick={() => window.electron?.minimizeWindow()}
                className="flex h-full w-11 items-center justify-center text-av-muted transition-all hover:bg-av-border/25 hover:text-av-main hover:shadow-[inset_0_0_0_1px_rgba(24,36,56,0.08)] dark:hover:bg-white/10 sm:w-12"
                title="Minimize"
              >
                <Minus className="w-4 h-4" strokeWidth={1.5} />
              </button>
              <button
                onClick={() => window.electron?.maximizeWindow()}
                className="flex h-full w-11 items-center justify-center text-av-muted transition-all hover:bg-av-border/25 hover:text-av-main hover:shadow-[inset_0_0_0_1px_rgba(24,36,56,0.08)] dark:hover:bg-white/10 sm:w-12"
                title="Maximize"
              >
                <Square className="w-4 h-4" strokeWidth={1.5} />
              </button>
              <button
                onClick={() => window.electron?.closeWindow()}
                className="flex h-full w-11 items-center justify-center text-av-muted transition-colors hover:bg-red-500 hover:text-white sm:w-12"
                title="Close"
              >
                <X className="w-4 h-4 text-inherit" strokeWidth={1.5} />
              </button>
            </div>
          </div>
        </div>
      </div>

      <main className="relative flex-1 min-h-0 pt-16">
        <AnimatePresence initial={false}>
          {mountedTabs.map((tab) => {
            const isActive = activeTab === tab
            return (
              <motion.section
                key={tab}
                initial={false}
                animate={{
                  opacity: isActive ? 1 : 0,
                  scale: isActive ? 1 : 0.985,
                  y: isActive ? 0 : 6,
                }}
                transition={{ duration: 0.22, ease: [0.16, 1, 0.3, 1] }}
                className={cn(
                  'min-h-full w-full',
                  isActive ? 'relative block' : 'hidden',
                )}
                aria-hidden={!isActive}
              >
                {tabPanels[tab]}
              </motion.section>
            )
          })}
        </AnimatePresence>
      </main>

      <SecuritySettings
        isOpen={showSecuritySettings}
        onClose={() => setShowSecuritySettings(false)}
        initialTab={settingsInitialTab}
      />
    </div>
  )
}

function App() {
  return (
    <ErrorBoundary context="App">
      <AuthProvider>
        <ThemeProvider>
          <AppContent />
        </ThemeProvider>
      </AuthProvider>
    </ErrorBoundary>
  )
}

export default App
