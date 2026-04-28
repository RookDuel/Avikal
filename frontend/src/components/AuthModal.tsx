import { useEffect, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, Shield, Loader2, User, LogOut, AlertTriangle, Server, ArrowLeft, KeyRound, Globe } from 'lucide-react'
import { useAuth } from '../contexts/AuthContext'
import { toast } from 'sonner'

const CUSTOM_AAVRIT_REQUEST_URL =
  import.meta.env.VITE_CUSTOM_AAVRIT_REQUEST_URL ||
  'https://avikal.rookduel.tech/custom-aavrit'

interface AuthModalProps {
  isOpen: boolean
  onClose: () => void
  isExpired?: boolean
}

type AuthStep = 'server' | 'credentials'

export default function AuthModal({ isOpen, onClose, isExpired = false }: AuthModalProps) {
  const { isAuthenticated, isAavritConnected, user, logout, disconnectServer, connectServer, login, aavritServerUrl, aavritMode } = useAuth()
  const [step, setStep] = useState<AuthStep>('server')
  const [aavritUrl, setAavritUrl] = useState('')
  const [checkedAavritUrl, setCheckedAavritUrl] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isCheckingServer, setIsCheckingServer] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)

  useEffect(() => {
    if (!isOpen) return

    const initialUrl = aavritServerUrl ?? localStorage.getItem('avikal_aavrit_server_url') ?? ''
    setAavritUrl(initialUrl)
    setCheckedAavritUrl(initialUrl)
    setEmail('')
    setPassword('')
    setStep(aavritMode === 'private' ? 'credentials' : 'server')
  }, [isOpen, aavritMode, aavritServerUrl])

  const handleCheckServer = async () => {
    const nextUrl = aavritUrl.trim()
    if (!nextUrl) {
      toast.error('Enter your Aavrit server URL first')
      return
    }

    setIsCheckingServer(true)
    try {
      const mode = await connectServer(nextUrl)
      setCheckedAavritUrl(nextUrl)
      setAavritUrl(nextUrl)
      if (mode === 'public') {
        toast.success('Aavrit server connected in public mode')
        onClose()
        return
      }

      setStep('credentials')
      toast.success('Aavrit server connected in private mode')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Aavrit server validation failed'
      toast.error(message)
    } finally {
      setIsCheckingServer(false)
    }
  }

  const handleLogin = async () => {
    if (!checkedAavritUrl && !aavritServerUrl) {
      toast.error('Validate your Aavrit server first')
      return
    }
    if (!email.trim() || !password) {
      toast.error('Enter both email and password')
      return
    }

    setIsSubmitting(true)
    try {
      const success = await login({
        aavrit_url: checkedAavritUrl || aavritServerUrl || '',
        email: email.trim(),
        password,
      })
      if (success) {
        toast.success('Aavrit login successful')
        onClose()
      } else {
        toast.error('Aavrit login failed')
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Aavrit login failed'
      toast.error(message)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleLogout = async () => {
    await logout()
    onClose()
  }

  const handleDisconnect = () => {
    disconnectServer()
    onClose()
  }

  const isLoading = isCheckingServer || isSubmitting
  const showSessionCard = isAavritConnected

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="theme-backdrop fixed inset-0 z-50 flex items-center justify-center p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            className="bg-av-surface rounded-2xl border border-av-border p-8 w-full max-w-md shadow-2xl"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-6">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-primary-500 to-primary-600 flex items-center justify-center">
                  <Shield className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-av-main">
                    {showSessionCard ? 'Aavrit Connected' : 'Connect Aavrit'}
                  </h2>
                  <p className="text-sm text-av-muted">
                    {showSessionCard ? 'Manage the current Aavrit connection' : 'Configure the Aavrit server for time-capsules'}
                  </p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="w-8 h-8 rounded-lg bg-av-border/10 hover:bg-av-border/20 flex items-center justify-center transition-colors text-av-muted hover:text-av-main"
                type="button"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {showSessionCard ? (
              <div className="space-y-6">
                <div className="flex items-center gap-4 p-4 bg-av-surface/60 rounded-xl border border-av-border/50">
                  <div className="w-12 h-12 rounded-xl bg-av-main flex items-center justify-center shadow-lg flex-shrink-0">
                    <User className="w-6 h-6 text-av-surface" />
                  </div>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-av-main truncate">
                      {aavritMode === 'private' ? (user?.name || 'Aavrit User') : 'Public Aavrit Connection'}
                    </p>
                    <p className="text-xs text-av-muted truncate">
                      {aavritMode === 'private' ? (user?.email || 'Private Aavrit session') : 'No login required for this server'}
                    </p>
                    <span className="inline-block mt-1 px-2 py-0.5 rounded-md text-xs font-medium bg-green-500/15 text-green-600 dark:text-green-400 border border-green-500/30">
                      {(aavritMode || 'connected').toUpperCase()}
                    </span>
                  </div>
                </div>

                {aavritServerUrl && (
                  <div className="p-4 bg-av-surface/40 rounded-xl border border-av-border/30">
                    <p className="text-xs text-av-muted mb-1">Connected Aavrit Server</p>
                    <p className="text-sm text-av-main break-all">{aavritServerUrl}</p>
                  </div>
                )}

                {aavritMode === 'private' && isAuthenticated ? (
                  <button
                    onClick={handleLogout}
                    className="w-full py-3 bg-red-500/20 hover:bg-red-500/30 text-red-400 font-medium rounded-xl transition-colors border border-red-500/30 flex items-center justify-center gap-2"
                    type="button"
                  >
                    <LogOut className="w-4 h-4" />
                    Logout
                  </button>
                ) : (
                  <button
                    onClick={handleDisconnect}
                    className="w-full py-3 bg-red-500/20 hover:bg-red-500/30 text-red-400 font-medium rounded-xl transition-colors border border-red-500/30 flex items-center justify-center gap-2"
                    type="button"
                  >
                    <LogOut className="w-4 h-4" />
                    Disconnect Aavrit
                  </button>
                )}

                <button
                  onClick={onClose}
                  className="w-full py-3 bg-av-border/10 hover:bg-av-border/20 text-av-muted font-medium rounded-xl transition-colors"
                  type="button"
                >
                  Close
                </button>
              </div>
            ) : (
              <div className="space-y-6">
                {isExpired && (
                  <div className="flex items-start gap-3 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
                    <AlertTriangle className="w-4 h-4 text-amber-500 mt-0.5 flex-shrink-0" />
                    <p className="text-sm text-amber-700 dark:text-amber-300">
                      Your Aavrit session expired. Reconnect to continue using private Aavrit capsules.
                    </p>
                  </div>
                )}

                <div className="text-center">
                  <div className="w-16 h-16 mx-auto mb-4 rounded-2xl bg-av-main flex items-center justify-center shadow-xl">
                    {step === 'server' ? <Server className="w-8 h-8 text-av-surface" /> : <KeyRound className="w-8 h-8 text-av-surface" />}
                  </div>
                  <h3 className="text-lg font-semibold text-av-main mb-2">
                    {step === 'server' ? 'Connect Your Aavrit Server' : 'Login to Aavrit'}
                  </h3>
                  <p className="text-sm text-av-muted mb-6">
                    {step === 'server'
                      ? 'Enter the Aavrit server URL this desktop app should use.'
                      : 'Private Aavrit mode uses Aavrit login. The server validates your credentials internally and returns an Aavrit session.'}
                  </p>
                </div>

                {step === 'server' ? (
                  <div className="space-y-4">
                    <label className="block">
                      <span className="text-sm text-av-main mb-2 block">Aavrit Server URL</span>
                      <input
                        value={aavritUrl}
                        onChange={(event) => setAavritUrl(event.target.value)}
                        placeholder="Enter your Aavrit server URL"
                        className="w-full rounded-xl border border-av-border bg-av-surface/60 px-4 py-3 text-av-main placeholder:text-av-muted outline-none focus:border-av-accent"
                        type="text"
                      />
                    </label>

                    <div className="rounded-xl border border-av-border/40 bg-av-surface/40 p-4">
                      <p className="text-sm text-av-main">
                        Need a custom server? Request one on RookDuel at{' '}
                        <a
                          href={CUSTOM_AAVRIT_REQUEST_URL}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-av-accent underline underline-offset-4"
                        >
                          {CUSTOM_AAVRIT_REQUEST_URL.replace(/^https?:\/\//, '')}
                        </a>
                        .
                      </p>
                    </div>

                    <button
                      onClick={handleCheckServer}
                      disabled={isLoading}
                      className="w-full py-4 bg-av-main text-av-surface hover:opacity-90 font-medium rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3 shadow-lg"
                      type="button"
                    >
                      {isCheckingServer ? (
                        <>
                          <Loader2 className="w-5 h-5 animate-spin" />
                          Checking Aavrit Server...
                        </>
                      ) : (
                        <>
                          <Server className="w-5 h-5" />
                          Continue
                        </>
                      )}
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="p-4 bg-av-surface/40 rounded-xl border border-av-border/30">
                      <div className="flex items-center gap-2 mb-2">
                        <Globe className="w-4 h-4 text-av-muted" />
                        <p className="text-xs text-av-muted">Aavrit Server</p>
                      </div>
                      <p className="text-sm text-av-main break-all">{checkedAavritUrl || aavritServerUrl}</p>
                    </div>

                    <label className="block">
                      <span className="text-sm text-av-main mb-2 block">Email</span>
                      <input
                        value={email}
                        onChange={(event) => setEmail(event.target.value)}
                        placeholder="you@example.com"
                        className="w-full rounded-xl border border-av-border bg-av-surface/60 px-4 py-3 text-av-main placeholder:text-av-muted outline-none focus:border-av-accent"
                        type="email"
                      />
                    </label>

                    <label className="block">
                      <span className="text-sm text-av-main mb-2 block">Password</span>
                      <input
                        value={password}
                        onChange={(event) => setPassword(event.target.value)}
                        placeholder="Enter your password"
                        className="w-full rounded-xl border border-av-border bg-av-surface/60 px-4 py-3 text-av-main placeholder:text-av-muted outline-none focus:border-av-accent"
                        type="password"
                      />
                    </label>

                    <button
                      onClick={handleLogin}
                      disabled={isLoading}
                      className="w-full py-4 bg-av-main text-av-surface hover:opacity-90 font-medium rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3 shadow-lg"
                      type="button"
                    >
                      {isSubmitting ? (
                        <>
                          <Loader2 className="w-5 h-5 animate-spin" />
                          Signing In...
                        </>
                      ) : (
                        <>
                          <Shield className="w-5 h-5" />
                          Login to Aavrit
                        </>
                      )}
                    </button>

                    <button
                      onClick={() => setStep('server')}
                      className="w-full py-3 bg-av-border/10 hover:bg-av-border/20 text-av-muted font-medium rounded-xl transition-colors flex items-center justify-center gap-2"
                      type="button"
                    >
                      <ArrowLeft className="w-4 h-4" />
                      Change Aavrit Server
                    </button>
                  </div>
                )}
              </div>
            )}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}
