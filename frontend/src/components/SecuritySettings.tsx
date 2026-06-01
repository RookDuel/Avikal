import { useState, useEffect, type ReactNode } from 'react'
import {
  Settings,
  X,
  Activity,
  Sun,
  Moon,
  Monitor,
  Download,
  ShieldCheck,
  SlidersHorizontal,
  Server,
  Trash2,
  FolderClock,
  Database,
  CheckCircle2,
  ExternalLink,
  KeyRound,
  LogOut,
  PlugZap,
  RefreshCw,
  BadgeInfo,
  type LucideIcon,
} from 'lucide-react'
import { toast } from 'sonner'
import { motion, AnimatePresence } from 'framer-motion'
import { useTheme } from '../contexts/ThemeContext'
import { useAuth } from '../contexts/AuthContext'
import { callCoreResponse } from '../lib/backend'
import { cn } from '../lib/utils'
import {
  DEFAULT_USER_PREFERENCES,
  loadUserPreferences,
  sanitizeUserPreferences,
  saveUserPreferences,
  type ActivityLogMode,
  type ActivityRetentionDays,
  type TimecapsuleProvider,
  type UserPreferences,
} from '../lib/preferences'

interface SecuritySettingsProps {
  isOpen: boolean
  onClose: () => void
  initialTab?: TabType
}

interface SettingsPayload {
  activity_log?: {
    entry_count: number
    storage_path: string
    last_event_at?: string | null
    export_format?: string
    mode?: string
    retention_days?: number
    chain_status?: string
  }
  preferences?: UserPreferences
  runtime?: {
    version?: string
    preview_root?: string
    log_dir?: string
    native_crypto?: {
      available?: boolean
      import_error?: string | null
    }
    pqc_provider?: {
      available?: boolean
      openssl?: string
      reason?: string
      suite_id?: string
    }
  }
}

type TabType = 'appearance' | 'aavrit' | 'privacy' | 'defaults' | 'runtime' | 'updates' | 'help' | 'diagnostics'
type ThemeOption = 'light' | 'dark' | 'system'

interface AppInfoPayload {
  name: string
  version: string
  platform: string
  arch: string
  packaged: boolean
  updateFeed: string
}

interface UpdateCheckPayload {
  success: boolean
  currentVersion: string
  latestVersion: string
  updateAvailable: boolean
  releaseName: string
  releaseUrl: string
  publishedAt?: string | null
  prerelease?: boolean
  assets?: Array<{ name: string; size: number; url: string }>
}

const CUSTOM_AAVRIT_REQUEST_URL =
  import.meta.env.VITE_CUSTOM_AAVRIT_REQUEST_URL ||
  'https://avikal.rookdue.tech/aavrit'
const DOCS_URL = import.meta.env.VITE_AVIKAL_DOCS_URL || 'https://avikal.rookduel.tech/docs'
const SUPPORT_URL = import.meta.env.VITE_AVIKAL_SUPPORT_URL || 'https://avikal.rookduel.tech/support'
const SECURITY_URL = import.meta.env.VITE_AVIKAL_SECURITY_URL || 'https://avikal.rookduel.tech/security'
const RELEASES_URL = import.meta.env.VITE_AVIKAL_RELEASES_URL || 'https://github.com/RookDuel/Avikal/releases'
const LICENSES_URL = import.meta.env.VITE_AVIKAL_LICENSES_URL || 'https://github.com/RookDuel/Avikal/blob/main/THIRD_PARTY_NOTICES.md'

const THEME_OPTIONS: Array<{ id: ThemeOption; label: string; icon: LucideIcon; desc: string }> = [
  { id: 'light', label: 'Light', icon: Sun, desc: 'Soft professional' },
  { id: 'dark', label: 'Dark', icon: Moon, desc: 'Midnight mist' },
  { id: 'system', label: 'System', icon: Monitor, desc: 'Auto-detect' },
]

const TABS: Array<{ id: TabType; label: string; icon: LucideIcon }> = [
  { id: 'appearance', label: 'Appearance', icon: Sun },
  { id: 'aavrit', label: 'Aavrit', icon: Server },
  { id: 'privacy', label: 'Privacy', icon: ShieldCheck },
  { id: 'defaults', label: 'Archive Defaults', icon: SlidersHorizontal },
  { id: 'runtime', label: 'Runtime', icon: Server },
  { id: 'updates', label: 'Updates', icon: RefreshCw },
  { id: 'help', label: 'Help & Legal', icon: BadgeInfo },
  { id: 'diagnostics', label: 'Diagnostics', icon: Download },
]

interface AavritDiagnosticsPayload {
  server_url?: string
  mode?: 'public' | 'private'
  status?: string
  health?: string
  latency_ms?: number
  public_key?: {
    key_id?: string
    sig_alg?: string
    fingerprint_sha256?: string
  }
}

async function readSettingsError(response: Response, fallback: string): Promise<string> {
  try {
    const data = await response.json()
    return data.detail || data.error || data.message || fallback
  } catch {
    return fallback
  }
}

export default function SecuritySettings({ isOpen, onClose, initialTab = 'appearance' }: SecuritySettingsProps) {
  const { theme, setTheme } = useTheme()
  const auth = useAuth()
  const [settings, setSettings] = useState<SettingsPayload | null>(null)
  const [preferences, setPreferences] = useState<UserPreferences>(() => loadUserPreferences())
  const [aavritUrlInput, setAavritUrlInput] = useState('')
  const [aavritEmail, setAavritEmail] = useState('')
  const [aavritPassword, setAavritPassword] = useState('')
  const [aavritDiagnostics, setAavritDiagnostics] = useState<AavritDiagnosticsPayload | null>(null)
  const [aavritSecureStorage, setAavritSecureStorage] = useState<boolean | null>(null)
  const [checkingAavrit, setCheckingAavrit] = useState(false)
  const [loggingIntoAavrit, setLoggingIntoAavrit] = useState(false)
  const [refreshingAavrit, setRefreshingAavrit] = useState(false)
  const [loading, setLoading] = useState(false)
  const [saving, setSaving] = useState(false)
  const [exportingAuditLog, setExportingAuditLog] = useState(false)
  const [clearingAuditLog, setClearingAuditLog] = useState(false)
  const [cleaningPreviews, setCleaningPreviews] = useState(false)
  const [appInfo, setAppInfo] = useState<AppInfoPayload | null>(null)
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckPayload | null>(null)
  const [checkingUpdates, setCheckingUpdates] = useState(false)
  const [activeTab, setActiveTab] = useState<TabType>('appearance')

  useEffect(() => {
    if (isOpen) {
      loadSettings()
      setActiveTab(initialTab)
      setAavritUrlInput(auth.aavritServerUrl ?? '')
      setAavritEmail('')
      setAavritPassword('')
      void refreshAavritDiagnostics(auth.aavritServerUrl ?? undefined, { silent: true })
      void window.electron?.safeStorage?.isAvailable?.().then(setAavritSecureStorage).catch(() => setAavritSecureStorage(false))
      void window.electron?.getAppInfo?.().then(setAppInfo).catch(() => setAppInfo(null))
    }
  }, [isOpen, initialTab])

  const loadSettings = async () => {
    try {
      setLoading(true)
      const response = await callCoreResponse('security.settings')
      const data = await response.json()

      if (data.success) {
        const nextSettings = data.settings as SettingsPayload
        const nextPreferences = sanitizeUserPreferences(nextSettings.preferences ?? loadUserPreferences())
        setSettings(nextSettings)
        setPreferences(nextPreferences)
        saveUserPreferences(nextPreferences)
      }
    } catch {
      toast.error('Failed to load system settings')
      setPreferences(loadUserPreferences())
    } finally {
      setLoading(false)
    }
  }

  const savePreferences = async (nextPreferences: UserPreferences) => {
    const sanitized = sanitizeUserPreferences(nextPreferences)
    setPreferences(sanitized)
    saveUserPreferences(sanitized)
    setSaving(true)
    try {
      const response = await callCoreResponse('security.preferencesUpdate', {
        method: 'POST',
        body: JSON.stringify({ preferences: sanitized }),
      })
      const data = await response.json()
      if (!response.ok || !data.success) {
        throw new Error(data.detail || data.message || 'Failed to save preferences')
      }
      const persisted = sanitizeUserPreferences(data.preferences)
      setPreferences(persisted)
      saveUserPreferences(persisted)
      setSettings((current) => current ? { ...current, preferences: persisted } : current)
      toast.success('Preferences saved')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save preferences'
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }

  const patchPreferences = (patcher: (current: UserPreferences) => UserPreferences) => {
    void savePreferences(patcher(preferences))
  }

  const exportActivityLog = async () => {
    try {
      setExportingAuditLog(true)
      const response = await callCoreResponse('security.activityLogExport')
      const data = await response.json()
      if (!response.ok || !data.success || !data.markdown) {
        throw new Error(data.detail || data.message || 'Failed to export activity audit log')
      }

      const filename = data.filename || 'avikal-activity-log.md'
      const entryCount = data.entry_count ?? 0
      if (window.electron?.saveTextFile) {
        const selectedPath = await window.electron.saveTextFile({
          defaultPath: filename,
          filters: [{ name: 'Markdown Files', extensions: ['md'] }],
          content: data.markdown,
        })
        if (!selectedPath) return
        toast.success(`Activity audit exported (${entryCount} entr${entryCount === 1 ? 'y' : 'ies'})`)
        return
      }

      const blob = new Blob([data.markdown], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      link.click()
      URL.revokeObjectURL(url)
      toast.success(`Activity audit exported (${entryCount} entr${entryCount === 1 ? 'y' : 'ies'})`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to export activity audit log'
      toast.error(message)
    } finally {
      setExportingAuditLog(false)
    }
  }

  const clearActivityLog = async () => {
    try {
      setClearingAuditLog(true)
      const response = await callCoreResponse('security.activityLogClear', { method: 'POST' })
      const data = await response.json()
      if (!response.ok || !data.success) {
        throw new Error(data.detail || data.message || 'Failed to clear activity log')
      }
      toast.success(`Cleared ${data.removed ?? 0} activity entr${data.removed === 1 ? 'y' : 'ies'}`)
      await loadSettings()
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to clear activity log'
      toast.error(message)
    } finally {
      setClearingAuditLog(false)
    }
  }

  const cleanupPreviews = async () => {
    try {
      setCleaningPreviews(true)
      const response = await callCoreResponse('preview.cleanupAll', { method: 'POST' })
      const data = await response.json()
      if (!response.ok || !data.success) {
        throw new Error(data.detail || data.message || 'Failed to clean preview files')
      }
      toast.success(`Removed ${data.removed ?? 0} preview entr${data.removed === 1 ? 'y' : 'ies'}`)
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to clean preview files'
      toast.error(message)
    } finally {
      setCleaningPreviews(false)
    }
  }

  const resetPreferences = () => {
    void savePreferences(DEFAULT_USER_PREFERENCES)
  }

  const refreshAavritDiagnostics = async (
    explicitUrl?: string,
    options: { silent?: boolean } = {},
  ) => {
    const url = (explicitUrl ?? auth.aavritServerUrl ?? '').trim()
    if (!url) {
      setAavritDiagnostics(null)
      return
    }

    try {
      setRefreshingAavrit(true)
      const response = await callCoreResponse('auth.aavritDiagnostics', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          aavrit_url: url,
          session_token: auth.sessionToken || undefined,
        }),
      })
      if (!response.ok) {
        throw new Error(await readSettingsError(response, 'Aavrit diagnostics failed'))
      }
      const data = await response.json()
      setAavritDiagnostics(data.aavrit ?? null)
      if (!options.silent) toast.success('Aavrit diagnostics refreshed')
    } catch (error) {
      setAavritDiagnostics(null)
      if (!options.silent) toast.error(error instanceof Error ? error.message : 'Aavrit diagnostics failed')
    } finally {
      setRefreshingAavrit(false)
    }
  }

  const connectAavrit = async () => {
    const url = aavritUrlInput.trim()
    if (!url) {
      toast.error('Enter your Aavrit server URL')
      return
    }

    try {
      setCheckingAavrit(true)
      const mode = await auth.connectServer(url)
      await refreshAavritDiagnostics(url, { silent: true })
      toast.success(mode === 'private' ? 'Aavrit private server verified' : 'Aavrit public server connected')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Aavrit server validation failed')
    } finally {
      setCheckingAavrit(false)
    }
  }

  const loginAavrit = async () => {
    if (!auth.aavritServerUrl && !aavritUrlInput.trim()) {
      toast.error('Connect an Aavrit server first')
      return
    }
    if (!aavritEmail.trim() || !aavritPassword) {
      toast.error('Enter both email and password')
      return
    }

    try {
      setLoggingIntoAavrit(true)
      const success = await auth.login({
        aavrit_url: auth.aavritServerUrl || aavritUrlInput.trim(),
        email: aavritEmail.trim(),
        password: aavritPassword,
      })
      setAavritPassword('')
      if (!success) throw new Error('Aavrit login failed')
      await refreshAavritDiagnostics(auth.aavritServerUrl || aavritUrlInput.trim(), { silent: true })
      toast.success('Aavrit login successful')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Aavrit login failed')
    } finally {
      setLoggingIntoAavrit(false)
    }
  }

  const disconnectAavrit = async () => {
    if (auth.aavritMode === 'private' && auth.isAuthenticated) {
      await auth.logout()
    } else {
      auth.disconnectServer()
    }
    setAavritDiagnostics(null)
    setAavritUrlInput('')
    setAavritEmail('')
    setAavritPassword('')
    toast.success('Aavrit disconnected')
  }

  const openCustomAavritRequest = async () => {
    await openExternalUrl(CUSTOM_AAVRIT_REQUEST_URL)
  }

  const openExternalUrl = async (url: string) => {
    if (window.electron?.openExternal) {
      await window.electron.openExternal(url)
      return
    }
    window.open(url, '_blank', 'noopener,noreferrer')
  }

  const checkForUpdates = async () => {
    if (!window.electron?.checkForUpdates) {
      toast.error('Update checking is unavailable in this build')
      return
    }
    try {
      setCheckingUpdates(true)
      const result = await window.electron.checkForUpdates()
      setUpdateInfo(result)
      if (result.updateAvailable) {
        toast.success(`Update available: v${result.latestVersion}`)
      } else {
        toast.success('Avikal is up to date')
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Update check failed')
    } finally {
      setCheckingUpdates(false)
    }
  }

  const formatAuditTimestamp = (value?: string | null) => {
    if (!value) return 'No events yet'
    const parsed = new Date(value)
    if (Number.isNaN(parsed.getTime())) return value
    return parsed.toLocaleString()
  }

  if (!isOpen) return null

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[100] flex items-center justify-center bg-black/35 p-4 backdrop-blur-xl sm:p-6 lg:p-10 dark:bg-black/55"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.97, opacity: 0, y: 16 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.97, opacity: 0, y: 16 }}
          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
          className="flex h-[86vh] max-h-[780px] min-h-0 w-full max-w-5xl flex-col overflow-hidden rounded-[2rem] border border-white/20 bg-av-surface/95 shadow-[0_28px_90px_rgba(0,0,0,0.26)] ring-1 ring-black/5 backdrop-blur-2xl sm:h-[82vh] lg:h-[76vh] lg:min-h-[560px] lg:flex-row dark:border-white/10 dark:bg-av-surface/96 dark:shadow-[0_32px_110px_rgba(0,0,0,0.55)]"
          onClick={(event) => event.stopPropagation()}
        >
          <aside className="flex min-h-0 shrink-0 flex-col border-b border-av-border/50 bg-gradient-to-br from-av-border/10 via-av-surface/70 to-av-surface/40 p-4 lg:w-64 lg:border-b-0 lg:border-r lg:p-5">
            <div className="mb-4 flex items-center justify-between gap-4 lg:mb-7">
              <div className="flex items-center gap-3">
                <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-av-main shadow-lg shadow-black/10">
                  <Settings className="h-5 w-5 text-av-surface" />
                </div>
                <div>
                  <h2 className="text-lg font-bold tracking-tight text-av-main">Settings</h2>
                  <p className="text-xs text-av-muted">Security and defaults</p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="flex h-10 w-10 items-center justify-center rounded-full border border-av-border bg-av-surface/80 text-av-muted transition-colors hover:bg-av-border/15 hover:text-av-main lg:hidden"
                type="button"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <nav className="flex min-h-0 gap-2 overflow-x-auto pb-1 lg:flex-col lg:overflow-y-auto lg:overflow-x-visible lg:pb-0">
              {TABS.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'flex shrink-0 items-center gap-3 rounded-2xl border px-4 py-3 text-sm font-semibold transition-all',
                    activeTab === tab.id
                      ? 'border-av-border/70 bg-av-surface text-av-main shadow-sm ring-1 ring-black/5'
                      : 'border-transparent text-av-muted hover:bg-av-border/12 hover:text-av-main',
                  )}
                  type="button"
                >
                  <tab.icon className="h-4 w-4" />
                  {tab.label}
                </button>
              ))}
            </nav>

          </aside>

          <section className="relative flex min-h-0 flex-1 flex-col bg-av-surface">
            <div className="pointer-events-none absolute right-5 top-5 z-20 hidden justify-end lg:flex">
              <button
                onClick={onClose}
                className="pointer-events-auto flex h-10 w-10 items-center justify-center rounded-full border border-av-border/70 bg-av-surface/90 text-av-muted shadow-sm backdrop-blur transition-colors hover:bg-av-border/15 hover:text-av-main"
                type="button"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="min-h-0 flex-1 overflow-y-auto custom-scrollbar px-5 pb-7 pt-6 sm:px-7 lg:px-10 lg:pb-9 lg:pt-10">
              {loading && !settings ? (
                <LoadingState />
              ) : (
                <AnimatePresence mode="wait">
                  <motion.div
                    key={activeTab}
                    initial={{ opacity: 0, y: 12 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -12 }}
                    transition={{ duration: 0.18 }}
                    className="mx-auto w-full max-w-4xl space-y-7"
                  >
                    {activeTab === 'appearance' && (
                      <AppearanceTab theme={theme} setTheme={setTheme} />
                    )}

                    {activeTab === 'aavrit' && (
                      <AavritTab
                        auth={auth}
                        urlInput={aavritUrlInput}
                        setUrlInput={setAavritUrlInput}
                        email={aavritEmail}
                        setEmail={setAavritEmail}
                        password={aavritPassword}
                        setPassword={setAavritPassword}
                        diagnostics={aavritDiagnostics}
                        secureStorageAvailable={aavritSecureStorage}
                        checking={checkingAavrit}
                        loggingIn={loggingIntoAavrit}
                        refreshing={refreshingAavrit}
                        connect={connectAavrit}
                        login={loginAavrit}
                        disconnect={disconnectAavrit}
                        refresh={() => refreshAavritDiagnostics(undefined)}
                        openCustomRequest={openCustomAavritRequest}
                      />
                    )}

                    {activeTab === 'privacy' && (
                      <PrivacyTab
                        preferences={preferences}
                        settings={settings}
                        saving={saving}
                        patchPreferences={patchPreferences}
                        clearActivityLog={clearActivityLog}
                        clearingAuditLog={clearingAuditLog}
                        formatAuditTimestamp={formatAuditTimestamp}
                      />
                    )}

                    {activeTab === 'defaults' && (
                      <DefaultsTab
                        preferences={preferences}
                        saving={saving}
                        patchPreferences={patchPreferences}
                        resetPreferences={resetPreferences}
                      />
                    )}

                    {activeTab === 'runtime' && (
                      <RuntimeTab
                        settings={settings}
                        saving={saving}
                        cleanupPreviews={cleanupPreviews}
                        cleaningPreviews={cleaningPreviews}
                      />
                    )}

                    {activeTab === 'updates' && (
                      <UpdatesTab
                        appInfo={appInfo}
                        updateInfo={updateInfo}
                        checkingUpdates={checkingUpdates}
                        checkForUpdates={checkForUpdates}
                        openExternalUrl={openExternalUrl}
                      />
                    )}

                    {activeTab === 'help' && (
                      <HelpLegalTab openExternalUrl={openExternalUrl} />
                    )}

                    {activeTab === 'diagnostics' && (
                      <DiagnosticsTab
                        settings={settings}
                        exportingAuditLog={exportingAuditLog}
                        exportActivityLog={exportActivityLog}
                      />
                    )}
                  </motion.div>
                </AnimatePresence>
              )}
            </div>
          </section>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  )
}

function LoadingState() {
  return (
    <div className="flex h-[50vh] flex-col items-center justify-center text-center">
      <Activity className="mb-4 h-8 w-8 animate-spin text-av-main" />
      <p className="text-av-muted">Loading system preferences...</p>
    </div>
  )
}

function SectionHeader({ title, description }: { title: string; description: string }) {
  return (
    <div>
      <h2 className="mb-2 text-2xl font-bold tracking-tight text-av-main sm:text-3xl">{title}</h2>
      <p className="max-w-2xl text-sm leading-6 text-av-muted">{description}</p>
    </div>
  )
}

function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div className={cn('rounded-[1.4rem] border border-av-border/65 bg-av-surface/88 p-5 shadow-[0_12px_34px_rgba(15,23,42,0.055)] backdrop-blur-xl dark:shadow-[0_16px_42px_rgba(0,0,0,0.22)]', className)}>
      {children}
    </div>
  )
}

function SelectRow<T extends string | number>({
  label,
  description,
  value,
  options,
  onChange,
}: {
  label: string
  description: string
  value: T
  options: Array<{ value: T; label: string }>
  onChange: (value: T) => void
}) {
  return (
    <div className="flex flex-col gap-3 rounded-2xl border border-av-border/60 bg-av-border/5 p-4 transition-colors hover:bg-av-border/8 md:flex-row md:items-center md:justify-between">
      <div className="min-w-0">
        <p className="font-semibold text-av-main">{label}</p>
        <p className="mt-1 text-sm leading-5 text-av-muted">{description}</p>
      </div>
      <select
        value={String(value)}
        onChange={(event) => {
          const selected = options.find((option) => String(option.value) === event.target.value)
          if (selected) onChange(selected.value)
        }}
        className="min-w-48 rounded-xl border border-av-border/80 bg-av-surface px-3 py-2.5 text-sm font-semibold text-av-main shadow-sm outline-none transition focus:border-av-accent focus:ring-4 focus:ring-av-accent/10"
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>{option.label}</option>
        ))}
      </select>
    </div>
  )
}

function ToggleRow({
  label,
  description,
  checked,
  onChange,
}: {
  label: string
  description: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <div className="flex items-center justify-between gap-4 rounded-2xl border border-av-border/60 bg-av-border/5 p-4 transition-colors hover:bg-av-border/8">
      <div className="min-w-0">
        <p className="font-semibold text-av-main">{label}</p>
        <p className="mt-1 text-sm leading-5 text-av-muted">{description}</p>
      </div>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative h-8 w-14 shrink-0 rounded-full border p-1 transition-all duration-200 focus:outline-none focus:ring-4 focus:ring-av-accent/15',
          checked
            ? 'border-av-main bg-av-main shadow-inner'
            : 'border-av-border/80 bg-av-border/20 hover:bg-av-border/30',
        )}
      >
        <span
          className={cn(
            'block h-5 w-5 rounded-full bg-white shadow-md transition-transform duration-200',
            checked ? 'translate-x-6' : 'translate-x-0',
          )}
        />
      </button>
    </div>
  )
}

function AppearanceTab({ theme, setTheme }: { theme: ThemeOption; setTheme: (theme: ThemeOption) => void }) {
  return (
    <div className="space-y-7">
      <SectionHeader title="Appearance" description="Customize Avikal's local interface theme." />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        {THEME_OPTIONS.map((option) => (
          <button
            key={option.id}
            onClick={() => setTheme(option.id)}
            className={cn(
              'flex flex-col items-start gap-3 rounded-2xl border p-6 text-left transition-all',
              theme === option.id
                ? 'border-av-accent bg-av-accent/5 ring-2 ring-av-accent/10'
                : 'border-av-border bg-av-surface text-av-muted hover:border-av-accent/30 hover:bg-av-border/10',
            )}
            type="button"
          >
            <div className={cn('rounded-lg p-2', theme === option.id ? 'bg-av-accent text-av-surface' : 'bg-av-border/20 text-av-muted')}>
              <option.icon className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-bold text-av-main">{option.label}</h3>
              <p className="text-xs text-av-muted">{option.desc}</p>
            </div>
          </button>
        ))}
      </div>
      <Card className="bg-av-border/5">
        <h3 className="mb-3 text-sm font-bold text-av-main">Theme Preview</h3>
        <div className="grid grid-cols-2 gap-3">
          <div className="h-12 rounded-xl border border-av-border bg-gradient-to-br from-[#F5F7FF] to-[#FBFBFF]" />
          <div className="h-12 rounded-xl border border-av-border bg-[#050505]" />
        </div>
      </Card>
    </div>
  )
}

function AavritTab({
  auth,
  urlInput,
  setUrlInput,
  email,
  setEmail,
  password,
  setPassword,
  diagnostics,
  secureStorageAvailable,
  checking,
  loggingIn,
  refreshing,
  connect,
  login,
  disconnect,
  refresh,
  openCustomRequest,
}: {
  auth: ReturnType<typeof useAuth>
  urlInput: string
  setUrlInput: (value: string) => void
  email: string
  setEmail: (value: string) => void
  password: string
  setPassword: (value: string) => void
  diagnostics: AavritDiagnosticsPayload | null
  secureStorageAvailable: boolean | null
  checking: boolean
  loggingIn: boolean
  refreshing: boolean
  connect: () => void
  login: () => void
  disconnect: () => void
  refresh: () => void
  openCustomRequest: () => void
}) {
  const connectedLabel = auth.isAavritConnected
    ? auth.aavritMode === 'private'
      ? 'Private session active'
      : 'Public server ready'
    : auth.aavritServerUrl && auth.aavritMode === 'private'
      ? 'Private server needs login'
      : 'Not connected'

  return (
    <div className="space-y-7">
      <SectionHeader title="Aavrit" description="Configure the external release authority used by Aavrit TimeCapsules." />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatusCard title="Connection" ready={auth.isAavritConnected} detail={connectedLabel} />
        <StatusCard title="Mode" ready={Boolean(auth.aavritMode)} detail={auth.aavritMode ? auth.aavritMode.toUpperCase() : 'Unavailable'} />
        <StatusCard
          title="Secure session storage"
          ready={secureStorageAvailable !== false}
          detail={secureStorageAvailable === null ? 'Checking...' : secureStorageAvailable ? 'Available' : 'Unavailable'}
        />
      </div>

      <Card className="space-y-4">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
          <label className="min-w-0 flex-1">
            <span className="mb-2 block text-sm font-semibold text-av-main">Aavrit server URL</span>
            <input
              value={urlInput}
              onChange={(event) => setUrlInput(event.target.value)}
              placeholder="https://your-aavrit-server.example"
              className="w-full rounded-xl border border-av-border/80 bg-av-surface px-4 py-3 text-sm text-av-main outline-none transition focus:border-av-accent focus:ring-4 focus:ring-av-accent/10"
              type="text"
            />
          </label>
          <button
            onClick={connect}
            disabled={checking || refreshing}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-av-main px-5 text-sm font-bold text-av-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            {checking ? <RefreshCw className="h-4 w-4 animate-spin" /> : <PlugZap className="h-4 w-4" />}
            {checking ? 'Checking...' : 'Connect'}
          </button>
        </div>

        <div className="flex flex-col gap-3 rounded-2xl border border-av-border/55 bg-av-border/5 p-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <p className="font-semibold text-av-main">Need an Aavrit server?</p>
            <p className="mt-1 text-sm text-av-muted">Request one from RookDuel.</p>
          </div>
          <button
            onClick={openCustomRequest}
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-av-border/70 px-4 py-2.5 text-sm font-semibold text-av-main transition-colors hover:bg-av-border/10"
            type="button"
          >
            Open request page
            <ExternalLink className="h-4 w-4" />
          </button>
        </div>
      </Card>

      {auth.aavritMode === 'private' && !auth.isAuthenticated && (
        <Card className="space-y-4">
          <div className="flex items-start gap-3">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-av-border/60 bg-av-border/8 text-av-muted">
              <KeyRound className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-semibold text-av-main">Private server login</h3>
              <p className="mt-1 text-sm text-av-muted">Login is required before private Aavrit capsules can be created or opened.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label>
              <span className="mb-2 block text-sm font-semibold text-av-main">Email</span>
              <input
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                placeholder="you@example.com"
                className="w-full rounded-xl border border-av-border/80 bg-av-surface px-4 py-3 text-sm text-av-main outline-none transition focus:border-av-accent focus:ring-4 focus:ring-av-accent/10"
                type="email"
              />
            </label>
            <label>
              <span className="mb-2 block text-sm font-semibold text-av-main">Password</span>
              <input
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Aavrit password"
                className="w-full rounded-xl border border-av-border/80 bg-av-surface px-4 py-3 text-sm text-av-main outline-none transition focus:border-av-accent focus:ring-4 focus:ring-av-accent/10"
                type="password"
              />
            </label>
          </div>

          <button
            onClick={login}
            disabled={loggingIn}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-av-main px-5 py-3 text-sm font-bold text-av-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            {loggingIn ? <RefreshCw className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            {loggingIn ? 'Signing in...' : 'Login to Aavrit'}
          </button>
        </Card>
      )}

      {auth.isAavritConnected && (
        <Card className="space-y-4">
          <div className="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
            <div className="flex min-w-0 items-center gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-emerald-500/30 bg-emerald-500/12 text-emerald-500">
                <CheckCircle2 className="h-5 w-5" />
              </div>
              <div className="min-w-0">
                <p className="font-semibold text-av-main">
                  {auth.aavritMode === 'private' ? auth.user?.name || 'Private Aavrit session' : 'Public Aavrit server'}
                </p>
                <p className="truncate text-sm text-av-muted">
                  {auth.aavritMode === 'private' ? auth.user?.email || 'Authenticated' : 'No login required'}
                </p>
              </div>
            </div>
            <button
              onClick={disconnect}
              className="inline-flex items-center justify-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm font-semibold text-red-500 transition-colors hover:bg-red-500/15"
              type="button"
            >
              <LogOut className="h-4 w-4" />
              Disconnect
            </button>
          </div>
          <PathBlock label="Connected server" value={auth.aavritServerUrl || 'Unavailable'} />
        </Card>
      )}

      <Card className="space-y-4">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="font-semibold text-av-main">Server verification</h3>
            <p className="mt-1 text-sm text-av-muted">Shows the Aavrit key identity Avikal will verify against.</p>
          </div>
          <button
            onClick={refresh}
            disabled={refreshing || !auth.aavritServerUrl}
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-av-border/70 px-4 py-2.5 text-sm font-semibold text-av-main transition-colors hover:bg-av-border/10 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            <RefreshCw className={cn('h-4 w-4', refreshing && 'animate-spin')} />
            Refresh
          </button>
        </div>

        {diagnostics ? (
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Stat label="Status" value={diagnostics.status || 'reachable'} />
            <Stat label="Health" value={diagnostics.health || 'unknown'} />
            <Stat label="Latency" value={typeof diagnostics.latency_ms === 'number' ? `${diagnostics.latency_ms} ms` : 'unknown'} />
            <Stat label="Key ID" value={diagnostics.public_key?.key_id || 'unknown'} />
            <Stat label="Signature" value={diagnostics.public_key?.sig_alg || 'unknown'} />
            <div className="md:col-span-2">
              <PathBlock label="Public-key SHA-256 fingerprint" value={diagnostics.public_key?.fingerprint_sha256 || 'Unavailable'} />
            </div>
          </div>
        ) : (
          <div className="rounded-xl border border-av-border bg-av-border/5 p-4 text-sm text-av-muted">
            Connect or refresh an Aavrit server to view diagnostics.
          </div>
        )}
      </Card>
    </div>
  )
}

function PrivacyTab({
  preferences,
  settings,
  saving,
  patchPreferences,
  clearActivityLog,
  clearingAuditLog,
  formatAuditTimestamp,
}: {
  preferences: UserPreferences
  settings: SettingsPayload | null
  saving: boolean
  patchPreferences: (patcher: (current: UserPreferences) => UserPreferences) => void
  clearActivityLog: () => void
  clearingAuditLog: boolean
  formatAuditTimestamp: (value?: string | null) => string
}) {
  return (
    <div className="space-y-7">
      <SectionHeader title="Privacy" description="Control local activity metadata and diagnostic redaction." />
      <Card className="space-y-4">
        <SelectRow<ActivityLogMode>
          label="Local activity log"
          description="Controls whether archive creation metadata is stored on this device."
          value={preferences.privacy.activity_log_mode}
          options={[
            { value: 'off', label: 'Off' },
            { value: 'minimal', label: 'Minimal' },
            { value: 'detailed', label: 'Detailed' },
          ]}
          onChange={(value) => patchPreferences((current) => ({ ...current, privacy: { ...current.privacy, activity_log_mode: value } }))}
        />
        <SelectRow<ActivityRetentionDays>
          label="Activity retention"
          description="Automatically removes old activity entries. Forever is available but not recommended for privacy."
          value={preferences.privacy.activity_retention_days}
          options={[
            { value: 7, label: '7 days' },
            { value: 30, label: '30 days' },
            { value: 90, label: '90 days' },
            { value: 365, label: '1 year' },
            { value: 0, label: 'Forever' },
          ]}
          onChange={(value) => patchPreferences((current) => ({ ...current, privacy: { ...current.privacy, activity_retention_days: value } }))}
        />
        <ToggleRow
          label="Redact diagnostics export"
          description="Hides system telemetry fields from exported activity logs."
          checked={preferences.privacy.redact_diagnostics}
          onChange={(value) => patchPreferences((current) => ({ ...current, privacy: { ...current.privacy, redact_diagnostics: value } }))}
        />
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Stat label="Entries" value={settings?.activity_log?.entry_count ?? 0} />
          <Stat label="Last event" value={formatAuditTimestamp(settings?.activity_log?.last_event_at)} />
          <Stat label="Mode" value={settings?.activity_log?.mode ?? preferences.privacy.activity_log_mode} />
        </div>
        <Stat label="Integrity chain" value={settings?.activity_log?.chain_status ?? 'empty'} />
        <button
          onClick={clearActivityLog}
          disabled={clearingAuditLog || saving}
          className="inline-flex items-center gap-2 rounded-xl border border-red-500/30 bg-red-500/10 px-4 py-2.5 text-sm font-semibold text-red-500 transition-colors hover:bg-red-500/15 disabled:cursor-not-allowed disabled:opacity-60"
          type="button"
        >
          <Trash2 className="h-4 w-4" />
          {clearingAuditLog ? 'Clearing...' : 'Clear Activity Log'}
        </button>
      </Card>
    </div>
  )
}

function DefaultsTab({
  preferences,
  saving,
  patchPreferences,
  resetPreferences,
}: {
  preferences: UserPreferences
  saving: boolean
  patchPreferences: (patcher: (current: UserPreferences) => UserPreferences) => void
  resetPreferences: () => void
}) {
  return (
    <div className="space-y-7">
      <SectionHeader title="Archive Defaults" description="Set safe defaults for new Encode and TimeCapsule workflows. Existing archives remain unchanged." />
      <Card className="space-y-4">
        <SelectRow
          label="Default PQC storage"
          description="Embedded keeps one .avk file. External creates a separate .avkkey for split possession."
          value={preferences.archive_defaults.pqc_storage_mode}
          options={[
            { value: 'embedded', label: 'Embedded in .avk' },
            { value: 'external', label: 'Separate .avkkey' },
          ]}
          onChange={(value) => patchPreferences((current) => ({ ...current, archive_defaults: { ...current.archive_defaults, pqc_storage_mode: value } }))}
        />
        <SelectRow<TimecapsuleProvider>
          label="Default TimeCapsule provider"
          description="drand is public. Aavrit requires a configured server."
          value={preferences.archive_defaults.default_timecapsule_provider}
          options={[
            { value: 'drand', label: 'drand' },
            { value: 'aavrit', label: 'Aavrit' },
          ]}
          onChange={(value) => patchPreferences((current) => ({ ...current, archive_defaults: { ...current.archive_defaults, default_timecapsule_provider: value } }))}
        />
        <button
          onClick={resetPreferences}
          disabled={saving}
          className="rounded-xl border border-av-border px-4 py-2.5 text-sm font-semibold text-av-main transition-colors hover:bg-av-border/10 disabled:cursor-not-allowed disabled:opacity-60"
          type="button"
        >
          Reset Safe Defaults
        </button>
      </Card>
    </div>
  )
}

function RuntimeTab({
  settings,
  saving,
  cleanupPreviews,
  cleaningPreviews,
}: {
  settings: SettingsPayload | null
  saving: boolean
  cleanupPreviews: () => void
  cleaningPreviews: boolean
}) {
  const nativeReady = Boolean(settings?.runtime?.native_crypto?.available)
  const pqcReady = Boolean(settings?.runtime?.pqc_provider?.available)
  return (
    <div className="space-y-7">
      <SectionHeader title="Runtime" description="Inspect native crypto status and control preview cleanup behavior." />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
        <StatusCard title="Native Rust crypto" ready={nativeReady} detail={nativeReady ? 'Available' : settings?.runtime?.native_crypto?.import_error || 'Unavailable'} />
        <StatusCard title="OpenSSL PQC provider" ready={pqcReady} detail={pqcReady ? 'Available' : settings?.runtime?.pqc_provider?.reason || 'Unavailable'} />
      </div>
      <Card className="space-y-4">
        <p className="text-sm text-av-muted">
          Preview files are decrypted temporary files. Use this to remove every active preview session immediately.
        </p>
        <button
          onClick={cleanupPreviews}
          disabled={cleaningPreviews || saving}
          className="inline-flex items-center gap-2 rounded-xl bg-av-main px-4 py-2.5 text-sm font-semibold text-av-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
          type="button"
        >
          <FolderClock className="h-4 w-4" />
          {cleaningPreviews ? 'Cleaning...' : 'Clean All Preview Files'}
        </button>
      </Card>
    </div>
  )
}

function UpdatesTab({
  appInfo,
  updateInfo,
  checkingUpdates,
  checkForUpdates,
  openExternalUrl,
}: {
  appInfo: AppInfoPayload | null
  updateInfo: UpdateCheckPayload | null
  checkingUpdates: boolean
  checkForUpdates: () => void
  openExternalUrl: (url: string) => Promise<void>
}) {
  const releaseUrl = updateInfo?.releaseUrl || appInfo?.updateFeed || RELEASES_URL
  const installerAssets = updateInfo?.assets?.filter((asset) => /\.(exe|msi|dmg|appimage|deb|rpm|zip)$/i.test(asset.name)) ?? []
  return (
    <div className="space-y-7">
      <SectionHeader title="Updates" description="Check release availability without installing silently." />
      <Card className="space-y-5">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Stat label="Current version" value={appInfo?.version ? `v${appInfo.version}` : 'unknown'} />
          <Stat label="Platform" value={appInfo ? `${appInfo.platform}-${appInfo.arch}` : 'unknown'} />
          <Stat label="Install type" value={appInfo?.packaged ? 'Packaged' : 'Development'} />
        </div>
        {updateInfo && (
          <div className={cn('rounded-2xl border p-4', updateInfo.updateAvailable ? 'border-emerald-500/30 bg-emerald-500/10' : 'border-av-border bg-av-border/5')}>
            <p className="text-sm font-bold text-av-main">
              {updateInfo.updateAvailable ? `Update available: v${updateInfo.latestVersion}` : 'No update available'}
            </p>
            <p className="mt-1 text-sm text-av-muted">
              Latest release: {updateInfo.releaseName || `v${updateInfo.latestVersion}`}
              {updateInfo.publishedAt ? ` · ${new Date(updateInfo.publishedAt).toLocaleDateString()}` : ''}
            </p>
          </div>
        )}
        {installerAssets.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-av-muted">Release assets</p>
            {installerAssets.slice(0, 4).map((asset) => (
              <button
                key={asset.url}
                onClick={() => void openExternalUrl(asset.url)}
                className="flex w-full items-center justify-between gap-3 rounded-xl border border-av-border bg-av-border/5 px-4 py-3 text-left text-sm transition-colors hover:bg-av-border/12"
                type="button"
              >
                <span className="min-w-0 truncate font-semibold text-av-main">{asset.name}</span>
                <span className="shrink-0 text-xs text-av-muted">{formatBytes(asset.size)}</span>
              </button>
            ))}
          </div>
        )}
        <div className="flex flex-wrap gap-3">
          <button
            onClick={checkForUpdates}
            disabled={checkingUpdates}
            className="inline-flex items-center gap-2 rounded-xl bg-av-main px-5 py-3 text-sm font-bold text-av-surface shadow-sm transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            <RefreshCw className={cn('h-4 w-4', checkingUpdates && 'animate-spin')} />
            {checkingUpdates ? 'Checking...' : 'Check for Updates'}
          </button>
          <button
            onClick={() => void openExternalUrl(releaseUrl)}
            className="inline-flex items-center gap-2 rounded-xl border border-av-border px-5 py-3 text-sm font-bold text-av-main transition-colors hover:bg-av-border/12"
            type="button"
          >
            <ExternalLink className="h-4 w-4" />
            Open Releases
          </button>
        </div>
        <p className="text-xs leading-6 text-av-muted">
          Updates are manual-confirmed. Avikal checks the release feed, then opens the signed release page for download and install review.
        </p>
      </Card>
    </div>
  )
}

function HelpLegalTab({ openExternalUrl }: { openExternalUrl: (url: string) => Promise<void> }) {
  const links = [
    { label: 'Documentation', description: 'Usage guides, recovery rules, and feature explanations.', url: DOCS_URL },
    { label: 'Support', description: 'Troubleshooting and issue reporting.', url: SUPPORT_URL },
    { label: 'Security', description: 'Security model and vulnerability reporting.', url: SECURITY_URL },
    { label: 'Release notes', description: 'Version history and download notes.', url: RELEASES_URL },
    { label: 'Licenses', description: 'Open-source licenses and third-party notices.', url: LICENSES_URL },
  ]
  return (
    <div className="space-y-7">
      <SectionHeader title="Help & Legal" description="External resources for documentation, support, releases, and notices." />
      <Card className="space-y-3">
        {links.map((link) => (
          <button
            key={link.url}
            onClick={() => void openExternalUrl(link.url)}
            className="flex w-full items-center justify-between gap-4 rounded-2xl border border-av-border bg-av-border/5 px-4 py-4 text-left transition-colors hover:bg-av-border/12"
            type="button"
          >
            <span className="min-w-0">
              <span className="block text-sm font-bold text-av-main">{link.label}</span>
              <span className="mt-1 block text-sm text-av-muted">{link.description}</span>
            </span>
            <ExternalLink className="h-4 w-4 shrink-0 text-av-muted" />
          </button>
        ))}
      </Card>
    </div>
  )
}

function DiagnosticsTab({
  settings,
  exportingAuditLog,
  exportActivityLog,
}: {
  settings: SettingsPayload | null
  exportingAuditLog: boolean
  exportActivityLog: () => void
}) {
  return (
    <div className="space-y-7">
      <SectionHeader title="Diagnostics" description="Export local operational metadata for troubleshooting without archive contents." />
      <Card className="space-y-4">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Stat label="Activity entries" value={settings?.activity_log?.entry_count ?? 0} />
          <Stat label="Export format" value={settings?.activity_log?.export_format || 'markdown'} />
          <Stat label="Version" value={settings?.runtime?.version || 'unknown'} />
        </div>
        <Stat label="Audit chain" value={settings?.activity_log?.chain_status || 'empty'} />
        <PathBlock label="Raw activity log" value={settings?.activity_log?.storage_path || 'Unavailable'} />
        <PathBlock label="Preview root" value={settings?.runtime?.preview_root || 'Unavailable'} />
        <PathBlock label="Log directory" value={settings?.runtime?.log_dir || 'Unavailable'} />
        <button
          onClick={exportActivityLog}
          disabled={exportingAuditLog}
          className="inline-flex items-center gap-2 rounded-xl bg-av-main px-5 py-3 text-sm font-bold text-av-surface shadow-sm transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
          type="button"
        >
          <Download className="h-4 w-4" />
          {exportingAuditLog ? 'Exporting...' : 'Export Activity Markdown'}
        </button>
      </Card>
    </div>
  )
}

function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '-'
  const units = ['B', 'KB', 'MB', 'GB']
  let next = value
  let unitIndex = 0
  while (next >= 1024 && unitIndex < units.length - 1) {
    next /= 1024
    unitIndex += 1
  }
  return `${next.toFixed(next >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`
}

function Stat({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-xl border border-av-border bg-av-border/5 p-4">
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted">{label}</p>
      <p className="break-words text-sm font-semibold text-av-main">{value}</p>
    </div>
  )
}

function StatusCard({ title, ready, detail }: { title: string; ready: boolean; detail: string }) {
  return (
    <Card>
      <div className="flex items-start gap-3">
        <div className={cn('flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border', ready ? 'border-emerald-500/30 bg-emerald-500/12 text-emerald-500' : 'border-red-500/30 bg-red-500/12 text-red-500')}>
          <Database className="h-5 w-5" />
        </div>
        <div className="min-w-0">
          <p className="font-semibold text-av-main">{title}</p>
          <p className="mt-1 break-words text-sm text-av-muted">{detail}</p>
        </div>
      </div>
    </Card>
  )
}

function PathBlock({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-av-border bg-av-border/5 p-4">
      <p className="mb-1 text-[11px] font-semibold uppercase tracking-[0.18em] text-av-muted">{label}</p>
      <p className="break-all font-mono text-xs text-av-main">{value}</p>
    </div>
  )
}
