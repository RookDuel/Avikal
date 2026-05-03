import { useState, useEffect, type CSSProperties, type ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Lock, Unlock, Info, Minus, Square, X, Shield, LogOut, Clock, Settings, CheckCircle2, PlugZap, AlertCircle } from 'lucide-react'
import { Toaster } from 'sonner'
import Encrypt from './pages/Encrypt'
import Decrypt from './pages/Decrypt'
import TimeCapsule from './pages/TimeCapsule'
import About from './pages/About'
import { AuthProvider, useAuth } from './contexts/AuthContext'
import { ThemeProvider, useTheme } from './contexts/ThemeContext'
import AuthModal from './components/AuthModal'
import SecuritySettings from './components/SecuritySettings'
import { ErrorBoundary } from './components/ErrorBoundary'
import { cn } from './lib/utils'
import { useBackendRuntime } from './hooks/useBackendRuntime'
import type { ExternalLaunchAction, PendingExternalLaunchAction } from './lib/externalLaunch'

type Tab = 'encrypt' | 'decrypt' | 'timecapsule' | 'about'

const NO_DRAG_REGION_STYLE: CSSProperties & { WebkitAppRegion: 'no-drag' } = {
  WebkitAppRegion: 'no-drag',
}

function AppContent() {
  const [activeTab, setActiveTab] = useState<Tab>('encrypt')
  const [visitedTabs, setVisitedTabs] = useState<Tab[]>(['encrypt'])
  const [showAuthModal, setShowAuthModal] = useState(false)
  const [showSecuritySettings, setShowSecuritySettings] = useState(false)
  const [isLoading, setIsLoading] = useState(true)
  const [showContent, setShowContent] = useState(false)
  const [pendingExternalLaunch, setPendingExternalLaunch] = useState<PendingExternalLaunchAction | null>(null)
  const backendRuntime = useBackendRuntime()
  const { isAuthenticated, isAavritConnected, user, logout, aavritMode, aavritServerUrl } = useAuth()
  const { actualTheme } = useTheme()

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false)
      setTimeout(() => setShowContent(true), 300)
    }, 1500)
    return () => clearTimeout(timer)
  }, [])

  useEffect(() => {
    const openAuthModal = () => setShowAuthModal(true)
    window.addEventListener('avikal:open-auth-modal', openAuthModal)
    return () => window.removeEventListener('avikal:open-auth-modal', openAuthModal)
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

  const authModalOpen = showAuthModal && !(isAuthenticated && user)
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
    timecapsule: (
      <ErrorBoundary context="TimeCapsule">
        <TimeCapsule externalLaunchAction={pendingExternalLaunch} />
      </ErrorBoundary>
    ),
    about: (
      <ErrorBoundary context="About">
        <About />
      </ErrorBoundary>
    ),
  }

  if (isLoading || !showContent) {
    return (
      <div
        className="flex flex-col items-center justify-center min-h-screen transition-colors duration-500"
        style={{ background: 'var(--av-bg-gradient)' }}
      >
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: isLoading ? 1 : 0, scale: isLoading ? 1 : 0.95 }}
          transition={{ duration: 0.5, ease: 'easeInOut' }}
          className="flex flex-col items-center"
        >
          <h1 className="text-4xl font-light tracking-widest mb-8 text-av-main">RookDuel Avikal</h1>
          <div className="w-48 h-1 rounded-full bg-av-main/10 overflow-hidden">
            <motion.div
              initial={{ x: '-100%' }}
              animate={{ x: '100%' }}
              transition={{ repeat: Infinity, duration: 1.5, ease: 'easeInOut' }}
              className="w-full h-full bg-av-accent rounded-full"
            />
          </div>
        </motion.div>
      </div>
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

      <div className="h-16 bg-av-surface/40 backdrop-blur-3xl border-b border-av-border/30 flex items-center justify-between pl-6 drag-region sticky top-0 z-50 shadow-[0_8px_32px_rgba(0,0,0,0.06)] transition-all duration-300">
        <div className="flex items-center gap-3 shrink-0 pr-6 border-r border-av-border/20 h-8">
          <span className="text-sm font-medium tracking-wide text-av-main">RookDuel Avikal</span>
          <span
            className={cn(
              'h-2.5 w-2.5 rounded-full border',
              backendRuntime.isReady
                ? 'bg-emerald-500 border-emerald-400'
                : backendRuntime.isUnavailable
                  ? 'bg-red-500 border-red-400'
                  : 'bg-amber-400 border-amber-300 animate-pulse',
            )}
            title={backendRuntime.detail}
          />
        </div>

        <div
          className={cn(
            'hidden xl:flex items-center gap-2 rounded-full border px-3 py-1.5 text-[11px] font-medium transition-colors',
            backendRuntime.isReady
              ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
              : backendRuntime.isUnavailable
                ? 'border-red-500/25 bg-red-500/10 text-red-500'
                : 'border-amber-500/25 bg-amber-500/10 text-amber-600 dark:text-amber-300',
          )}
          title={backendRuntime.detail}
        >
          {backendRuntime.isReady ? (
            <CheckCircle2 className="h-3.5 w-3.5" />
          ) : backendRuntime.isUnavailable ? (
            <AlertCircle className="h-3.5 w-3.5" />
          ) : (
            <PlugZap className="h-3.5 w-3.5 animate-pulse" />
          )}
          <span>{backendRuntime.label}</span>
        </div>

        <nav className="flex items-center gap-4 overflow-x-auto custom-scrollbar flex-1 px-6 h-full" style={NO_DRAG_REGION_STYLE}>
          {[
            { id: 'encrypt', icon: Lock, label: 'Encode' },
            { id: 'decrypt', icon: Unlock, label: 'Decode' },
            { id: 'timecapsule', icon: Clock, label: 'Time-Capsule' },
            { id: 'about', icon: Info, label: 'About' },
          ].map((tab) => (
            <motion.button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as Tab)}
              className={cn(
                'flex items-center gap-2 h-full font-medium transition-all relative shrink-0 group',
                activeTab === tab.id
                  ? 'text-av-main'
                  : 'text-av-muted hover:text-av-main',
              )}
            >
              <div className={cn(
                'p-1.5 rounded-lg transition-colors',
                activeTab === tab.id ? 'bg-av-main/10' : 'group-hover:bg-av-border/20',
              )}>
                <tab.icon className="w-4 h-4" />
              </div>
              <span className="text-sm font-medium tracking-wide">{tab.label}</span>

              {activeTab === tab.id && (
                <motion.div
                  layoutId="activeNavTab"
                  className="absolute bottom-0 left-0 right-0 h-[3px] bg-av-accent rounded-t-full"
                  transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                />
              )}
            </motion.button>
          ))}
        </nav>

        <div className="flex items-center h-full shrink-0" style={NO_DRAG_REGION_STYLE}>
          <div className="flex items-center gap-3 pr-4">
            {isAavritConnected ? (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowAuthModal(true)}
                  className="flex items-center gap-3 px-3 py-1.5 bg-av-border/10 dark:bg-black/10 backdrop-blur-md rounded-xl border border-av-border/30 shadow-inner transition-colors hover:bg-av-border/20 dark:hover:bg-white/10"
                  title="Manage Aavrit Connection"
                >
                  <div className="w-7 h-7 rounded-lg bg-emerald-500/15 flex items-center justify-center shadow-md border border-emerald-500/30">
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500" />
                  </div>
                  <div className="text-left hidden lg:block">
                    <div className="text-sm font-medium tracking-wide text-av-main leading-tight">
                      {aavritMode === 'private' ? (user?.name || 'Aavrit Connected') : 'Aavrit Connected'}
                    </div>
                    <div className="text-[11px] text-av-muted leading-tight">
                      {aavritMode === 'private' ? 'Private session active' : 'Public server ready'}
                    </div>
                  </div>
                </button>
                {aavritMode === 'private' && (
                  <motion.button
                    type="button"
                    whileHover={{ scale: 1.05 }}
                    whileTap={{ scale: 0.95 }}
                    onClick={logout}
                    className="flex items-center justify-center w-9 h-9 bg-av-border/10 dark:bg-black/10 backdrop-blur-md border border-av-border/30 text-av-muted rounded-xl hover:text-red-400 hover:bg-av-border/20 transition-all shadow-sm"
                    title="Disconnect Aavrit"
                  >
                    <LogOut className="w-4 h-4" />
                  </motion.button>
                )}
              </div>
            ) : (
              <motion.button
                whileHover={{ scale: 1.05 }}
                whileTap={{ scale: 0.95 }}
                onClick={() => setShowAuthModal(true)}
                className="flex items-center gap-2 px-3 py-1.5 bg-av-main text-av-surface rounded-lg text-sm font-medium tracking-wide hover:opacity-90 transition-colors shadow-sm"
              >
                {aavritServerUrl ? <PlugZap className="w-4 h-4" /> : <Shield className="w-4 h-4" />}
                {aavritServerUrl && aavritMode === 'private' ? 'Reconnect Aavrit' : 'Connect Aavrit'}
              </motion.button>
            )}

            <motion.button
              whileHover={{ scale: 1.05, rotate: 15 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setShowSecuritySettings(true)}
              className="flex items-center justify-center w-9 h-9 bg-av-surface/40 backdrop-blur-md border border-av-border/30 text-av-muted rounded-xl hover:bg-av-border/50 hover:text-av-main transition-all shadow-sm"
              title="Global Settings"
            >
              <Settings className="w-4 h-4" />
            </motion.button>
          </div>

          <div className="flex h-full border-l border-av-border/20 pl-1">
            <button
              onClick={() => window.electron?.minimizeWindow()}
              className="w-12 h-full flex items-center justify-center text-av-muted hover:bg-av-border/15 dark:hover:bg-white/10 transition-colors"
              title="Minimize"
            >
              <Minus className="w-4 h-4" strokeWidth={1.5} />
            </button>
            <button
              onClick={() => window.electron?.maximizeWindow()}
              className="w-12 h-full flex items-center justify-center text-av-muted hover:bg-av-border/15 dark:hover:bg-white/10 transition-colors"
              title="Maximize"
            >
              <Square className="w-4 h-4" strokeWidth={1.5} />
            </button>
            <button
              onClick={() => window.electron?.closeWindow()}
              className="w-12 h-full flex items-center justify-center text-av-muted hover:bg-red-500 hover:text-white transition-colors"
              title="Close"
            >
              <X className="w-4 h-4 text-inherit" strokeWidth={1.5} />
            </button>
          </div>
        </div>
      </div>

      <main className="relative min-h-[calc(100vh-120px)] overflow-y-auto">
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

      <AuthModal isOpen={authModalOpen} onClose={() => setShowAuthModal(false)} />

      <SecuritySettings
        isOpen={showSecuritySettings}
        onClose={() => setShowSecuritySettings(false)}
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
