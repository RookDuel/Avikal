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
  Copy,
  UserRoundCheck,
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
  type VisualEffectsMode,
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
  diagnostic_log?: {
    entry_count: number
    storage_path: string
    last_event_at?: string | null
    export_format?: string
    max_file_size_bytes?: number
  }
  preferences?: UserPreferences
  runtime?: {
    version?: string
    preview_root?: string
    log_dir?: string
    native_crypto?: {
      available?: boolean
      import_error?: string | null
      memory_lock_available?: boolean
    }
    pqc_provider?: {
      available?: boolean
      openssl?: string
      reason?: string
      suite_id?: string
    }
  }
}

type TabType = 'appearance' | 'aavrit' | 'identities' | 'privacy' | 'defaults' | 'runtime' | 'updates' | 'help' | 'diagnostics'
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
  metadataVerified?: boolean
  recommendedInstallers?: Array<{
    kind: 'windows-gui' | 'windows-cli'
    name: string
    size: number
    url: string
    sha256?: string | null
  }>
}

const CUSTOM_AAVRIT_REQUEST_URL =
  import.meta.env.VITE_CUSTOM_AAVRIT_REQUEST_URL ||
  'https://avikal.rookduel.tech/aavrit'
const DOCS_URL = import.meta.env.VITE_AVIKAL_DOCS_URL || 'https://avikal.rookduel.tech/docs'
let preferenceSaveSequence = 0
const SUPPORT_URL = import.meta.env.VITE_AVIKAL_SUPPORT_URL || 'https://avikal.rookduel.tech/support'
const SECURITY_URL = import.meta.env.VITE_AVIKAL_SECURITY_URL || 'https://avikal.rookduel.tech/security'
const RELEASES_URL = import.meta.env.VITE_AVIKAL_RELEASES_URL || 'https://github.com/RookDuel/Avikal/releases'
const LICENSES_URL = import.meta.env.VITE_AVIKAL_LICENSES_URL || 'https://github.com/RookDuel/Avikal/blob/main/THIRD_PARTY_NOTICES.md'

const THEME_OPTIONS: Array<{ id: ThemeOption; label: string; icon: LucideIcon; desc: string }> = [
  { id: 'light', label: 'Light', icon: Sun, desc: 'Soft professional' },
  { id: 'dark', label: 'Dark', icon: Moon, desc: 'Midnight mist' },
  { id: 'system', label: 'System', icon: Monitor, desc: 'Auto-detect' },
]

const VISUAL_MODE_OPTIONS: Array<{ id: VisualEffectsMode; label: string; desc: string }> = [
  { id: 'auto', label: 'Auto', desc: 'Choose the safest design for this system at startup.' },
  { id: 'effects', label: 'Effects', desc: 'Use native Windows acrylic for supported systems.' },
  { id: 'normal', label: 'Normal', desc: 'Opaque matte interface optimized for lowest-end systems.' },
]

const TABS: Array<{ id: TabType; label: string; icon: LucideIcon }> = [
  { id: 'appearance', label: 'Appearance', icon: Sun },
  { id: 'aavrit', label: 'Aavrit', icon: Server },
  { id: 'identities', label: 'Signing Keys', icon: UserRoundCheck },
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
  protocol?: string
  authority?: {
    authority_id?: string
    encryption_suite?: string
    signature_suite?: string
    key_ids?: Record<string, string>
  }
}

interface CreatorIdentityView {
  identity_id: string
  label: string
  created_at?: string
  status?: 'trusted' | 'revoked'
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
  const [exportingDiagnosticLog, setExportingDiagnosticLog] = useState(false)
  const [clearingAuditLog, setClearingAuditLog] = useState(false)
  const [cleaningPreviews, setCleaningPreviews] = useState(false)
  const [appInfo, setAppInfo] = useState<AppInfoPayload | null>(null)
  const [updateInfo, setUpdateInfo] = useState<UpdateCheckPayload | null>(null)
  const [checkingUpdates, setCheckingUpdates] = useState(false)
  const [activeTab, setActiveTab] = useState<TabType>('appearance')
  const [creatorIdentities, setCreatorIdentities] = useState<CreatorIdentityView[]>([])
  const [trustedIdentities, setTrustedIdentities] = useState<CreatorIdentityView[]>([])
  const [identitySecureStorage, setIdentitySecureStorage] = useState(false)
  const [identityBusy, setIdentityBusy] = useState(false)
  const [identityLabel, setIdentityLabel] = useState('')

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
      void refreshCreatorIdentities()
    }
  }, [isOpen, initialTab])

  const refreshCreatorIdentities = async () => {
    try {
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      const result = await bridge.list()
      setCreatorIdentities((result?.identities || []) as unknown as CreatorIdentityView[])
      setTrustedIdentities((result?.trusted || []) as unknown as CreatorIdentityView[])
      setIdentitySecureStorage(Boolean(result?.secureStorageAvailable))
    } catch {
      setCreatorIdentities([])
      setTrustedIdentities([])
      setIdentitySecureStorage(false)
    }
  }

  const createCreatorIdentity = async (label: string) => {
    const normalizedLabel = label.trim()
    if (!normalizedLabel) {
      toast.error('Enter a label for the signing identity')
      return
    }
    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      await bridge.create(normalizedLabel)
      setIdentityLabel('')
      await refreshCreatorIdentities()
      toast.success('Signing key created')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Identity creation failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const deleteCreatorIdentity = async (identityId: string) => {
    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      const removed = await bridge.delete(identityId)
      if (!removed) throw new Error('Signing key was not found')
      await refreshCreatorIdentities()
      toast.success('Signing key deleted')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Identity deletion failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const importTrustedIdentity = async () => {
    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      const result = await bridge.importTrusted()
      if (result) {
        await refreshCreatorIdentities()
        toast.success('Author fingerprint trusted')
      }
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Public identity import failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const exportCreatorIdentity = async (identityId: string) => {
    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      const outputPath = await bridge.exportPublic(identityId)
      if (outputPath) toast.success('Public author card exported')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Public identity export failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const updateCreatorTrust = async (identityId: string, status: 'trusted' | 'revoked') => {
    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge) throw new Error('Signing key service is unavailable')
      await bridge.setTrust(identityId, status)
      await refreshCreatorIdentities()
      toast.success(status === 'revoked' ? 'Author fingerprint revoked' : 'Author fingerprint trusted')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Trust update failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const deleteTrustedIdentity = async (identityId: string) => {
    const shouldDelete = window.confirm(
      'Remove this trusted author card from this device? Future archives from this author will no longer use your saved trust decision.',
    )
    if (!shouldDelete) return

    try {
      setIdentityBusy(true)
      const bridge = window.electron?.creatorIdentity
      if (!bridge?.deleteTrusted) throw new Error('Trusted author removal is unavailable')
      const removed = await bridge.deleteTrusted(identityId)
      if (!removed) throw new Error('Trusted author card was not found')
      await refreshCreatorIdentities()
      toast.success('Trusted author removed')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Trusted author removal failed')
    } finally {
      setIdentityBusy(false)
    }
  }

  const loadSettings = async () => {
    const saveSequenceAtStart = preferenceSaveSequence
    try {
      setLoading(true)
      const response = await callCoreResponse('security.settings')
      const data = await response.json()

      if (data.success) {
        const nextSettings = data.settings as SettingsPayload
        const cachedPreferences = loadUserPreferences()
        const nextPreferences = sanitizeUserPreferences(nextSettings.preferences ?? cachedPreferences)
        if (
          cachedPreferences.appearance.visual_effects_mode !== 'auto'
          && nextPreferences.appearance.visual_effects_mode === 'auto'
        ) {
          nextPreferences.appearance.visual_effects_mode = cachedPreferences.appearance.visual_effects_mode
        }
        nextSettings.preferences = nextPreferences
        setSettings(nextSettings)
        if (preferenceSaveSequence === saveSequenceAtStart) {
          setPreferences(nextPreferences)
          saveUserPreferences(nextPreferences)
        }
      }
    } catch {
      toast.error('Failed to load system settings')
      setPreferences(loadUserPreferences())
    } finally {
      setLoading(false)
    }
  }

  const applyVisualPreference = async (mode: VisualEffectsMode) => {
    if (!window.electron?.setVisualMode) return
    if (mode === 'effects' || mode === 'normal') {
      await window.electron.setVisualMode(mode)
      return
    }
    const status = await window.electron.getVisualMode?.()
    const automaticMode = status?.automaticMode === 'effects' ? 'effects' : 'normal'
    await window.electron.setVisualMode(automaticMode)
  }

  const savePreferences = async (nextPreferences: UserPreferences) => {
    const saveSequence = preferenceSaveSequence + 1
    preferenceSaveSequence = saveSequence
    const sanitized = sanitizeUserPreferences(nextPreferences)
    setPreferences(sanitized)
    saveUserPreferences(sanitized)
    void applyVisualPreference(sanitized.appearance.visual_effects_mode)
    setSaving(true)
    try {
      const persistOnce = async () => {
        const response = await callCoreResponse('security.preferencesUpdate', {
          method: 'POST',
          body: JSON.stringify({ preferences: sanitized }),
        })
        const data = await response.json()
        if (!response.ok || !data.success) {
          throw new Error(data.detail || data.message || 'Failed to save preferences')
        }
        return sanitizeUserPreferences(data.preferences)
      }

      let persisted = await persistOnce()
      if (persisted.appearance.visual_effects_mode !== sanitized.appearance.visual_effects_mode) {
        await window.electron?.recordDiagnosticEvent?.({
          event: 'preference_persist_mismatch',
          status: 'retrying',
          level: 'warning',
          requested_visual_mode: sanitized.appearance.visual_effects_mode,
          persisted_visual_mode: persisted.appearance.visual_effects_mode,
        }).catch(() => false)
        persisted = await persistOnce()
      }
      if (persisted.appearance.visual_effects_mode !== sanitized.appearance.visual_effects_mode) {
        await window.electron?.recordDiagnosticEvent?.({
          event: 'preference_persist_mismatch',
          status: 'using_local_cache',
          level: 'error',
          requested_visual_mode: sanitized.appearance.visual_effects_mode,
          persisted_visual_mode: persisted.appearance.visual_effects_mode,
        }).catch(() => false)
        persisted = sanitized
      }
      if (preferenceSaveSequence === saveSequence) {
        setPreferences(persisted)
        saveUserPreferences(persisted)
        void applyVisualPreference(persisted.appearance.visual_effects_mode)
        setSettings((current) => current ? { ...current, preferences: persisted } : current)
      }
      toast.success('Preferences saved')
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to save preferences'
      toast.error(message)
    } finally {
      setSaving(false)
    }
  }

  const patchPreferences = (patcher: (current: UserPreferences) => UserPreferences) => {
    setPreferences((current) => {
      const next = sanitizeUserPreferences(patcher(current))
      void savePreferences(next)
      return next
    })
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

  const exportDiagnosticLog = async () => {
    try {
      setExportingDiagnosticLog(true)
      if (window.electron?.exportDiagnostics) {
        const selectedPath = await window.electron.exportDiagnostics()
        if (selectedPath) toast.success('Support diagnostics exported')
        return
      }

      const response = await callCoreResponse('security.diagnosticsExport')
      const data = await response.json()
      if (!response.ok || !data.success || !data.markdown) {
        throw new Error(data.detail || data.message || 'Failed to export support diagnostics')
      }
      const filename = data.filename || 'avikal-diagnostics.md'
      if (window.electron?.saveTextFile) {
        const selectedPath = await window.electron.saveTextFile({
          defaultPath: filename,
          filters: [{ name: 'Markdown Files', extensions: ['md'] }],
          content: data.markdown,
        })
        if (selectedPath) toast.success('Support diagnostics exported')
        return
      }
      const blob = new Blob([data.markdown], { type: 'text/markdown;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = filename
      link.click()
      URL.revokeObjectURL(url)
      toast.success('Support diagnostics exported')
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Failed to export support diagnostics')
    } finally {
      setExportingDiagnosticLog(false)
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
        className="av-modal-backdrop fixed inset-0 z-[320] flex items-center justify-center p-4 sm:p-6 lg:p-10"
        onClick={onClose}
      >
        <motion.div
          initial={{ scale: 0.97, opacity: 0, y: 16 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          exit={{ scale: 0.97, opacity: 0, y: 16 }}
          transition={{ duration: 0.2, ease: [0.22, 1, 0.36, 1] }}
          className="av-modal-surface flex h-[86vh] max-h-[780px] min-h-0 w-full max-w-5xl flex-col overflow-hidden rounded-[2rem] ring-1 ring-black/5 sm:h-[82vh] lg:h-[76vh] lg:min-h-[560px] lg:flex-row"
          onClick={(event) => event.stopPropagation()}
        >
          <aside className="flex min-h-0 shrink-0 flex-col border-b border-av-border/50 bg-av-border/5 p-4 lg:w-64 lg:border-b-0 lg:border-r lg:p-5">
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

            <nav className="settings-tab-list flex min-h-0 gap-2 overflow-x-auto pb-1 lg:flex-col lg:overflow-y-auto lg:overflow-x-visible lg:pb-0">
              {TABS.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    'settings-tab-button flex shrink-0 items-center gap-3 rounded-2xl border px-4 py-3 text-sm font-semibold transition-all',
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
                className="pointer-events-auto flex h-10 w-10 items-center justify-center rounded-full border border-av-border/70 bg-av-surface text-av-muted shadow-sm transition-colors hover:bg-av-border/15 hover:text-av-main"
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
                      <AppearanceTab
                        theme={theme}
                        setTheme={setTheme}
                        preferences={preferences}
                        onVisualModeChange={(visualMode) => patchPreferences((current) => ({
                          ...current,
                          appearance: {
                            ...current.appearance,
                            visual_effects_mode: visualMode,
                          },
                        }))}
                      />
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

                    {activeTab === 'identities' && (
                      <SigningIdentitiesTab
                        identities={creatorIdentities}
                        trusted={trustedIdentities}
                        secureStorageAvailable={identitySecureStorage}
                        busy={identityBusy}
                        identityLabel={identityLabel}
                        setIdentityLabel={setIdentityLabel}
                        createIdentity={createCreatorIdentity}
                        deleteIdentity={deleteCreatorIdentity}
                        exportIdentity={exportCreatorIdentity}
                        importTrusted={importTrustedIdentity}
                        setTrust={updateCreatorTrust}
                        deleteTrusted={deleteTrustedIdentity}
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
                        exportingDiagnosticLog={exportingDiagnosticLog}
                        exportActivityLog={exportActivityLog}
                        exportDiagnosticLog={exportDiagnosticLog}
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
    <div className={cn('rounded-[1.4rem] border border-av-border/65 bg-av-surface/88 p-5 shadow-[0_12px_34px_rgba(15,23,42,0.055)] dark:shadow-[0_16px_42px_rgba(0,0,0,0.22)]', className)}>
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
            ? 'border-emerald-600 bg-emerald-600 shadow-inner dark:border-emerald-500 dark:bg-emerald-500'
            : 'border-av-border/80 bg-av-border/20 hover:bg-av-border/30 dark:bg-white/10',
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

function AppearanceTab({
  theme,
  setTheme,
  preferences,
  onVisualModeChange,
}: {
  theme: ThemeOption
  setTheme: (theme: ThemeOption) => void
  preferences: UserPreferences
  onVisualModeChange: (mode: VisualEffectsMode) => void
}) {
  const visualMode = preferences.appearance.visual_effects_mode
  return (
    <div className="space-y-6">
      <SectionHeader title="Appearance" description="Choose a stable visual profile for this device." />
      <Card className="space-y-4">
        <div>
          <h3 className="text-sm font-bold text-av-main">Theme</h3>
          <p className="mt-1 text-sm leading-6 text-av-muted">Controls color scheme only. It does not change performance mode.</p>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        {THEME_OPTIONS.map((option) => (
          <button
            key={option.id}
            onClick={() => setTheme(option.id)}
            aria-pressed={theme === option.id}
            className={cn(
              'flex min-h-[118px] flex-col items-start gap-3 rounded-2xl border p-4 text-left transition-all duration-200 focus:outline-none focus:ring-4 focus:ring-av-accent/12 active:scale-[0.99]',
              theme === option.id
                ? 'border-av-accent bg-av-accent/10 text-av-main ring-1 ring-av-accent/15 shadow-sm'
                : 'border-av-border/75 bg-av-surface text-av-main hover:-translate-y-0.5 hover:border-av-accent/35 hover:bg-av-border/8 hover:shadow-sm',
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
      </Card>
      <Card className="space-y-4">
        <div>
          <h3 className="text-sm font-bold text-av-main">Visual engine</h3>
          <p className="mt-1 text-sm leading-6 text-av-muted">Effects uses native acrylic where supported. Normal is matte, opaque, and fastest.</p>
        </div>
        <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
          {VISUAL_MODE_OPTIONS.map((option) => (
            <button
              key={option.id}
              type="button"
              onClick={() => onVisualModeChange(option.id)}
              aria-pressed={visualMode === option.id}
              className={cn(
                'group flex min-h-[112px] flex-col items-start justify-between rounded-2xl border p-4 text-left transition-all duration-200 focus:outline-none focus:ring-4 focus:ring-av-accent/12 active:scale-[0.99]',
                visualMode === option.id
                  ? 'border-av-accent bg-av-accent/10 text-av-main ring-1 ring-av-accent/15 shadow-sm'
                  : 'border-av-border/75 bg-av-surface text-av-main hover:-translate-y-0.5 hover:border-av-accent/35 hover:bg-av-border/8 hover:shadow-sm',
              )}
            >
              <div>
                <div className="text-sm font-bold">{option.label}</div>
                <p className="mt-1 text-xs leading-5 text-av-muted">
                  {option.desc}
                </p>
              </div>
              {visualMode === option.id && (
                <span className="rounded-full border border-av-accent/25 bg-av-accent/12 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.16em] text-av-accent">
                  Active
                </span>
              )}
            </button>
          ))}
        </div>
      </Card>
    </div>
  )
}

function SigningIdentitiesTab({ identities, trusted, secureStorageAvailable, busy, identityLabel, setIdentityLabel, createIdentity, deleteIdentity, exportIdentity, importTrusted, setTrust, deleteTrusted }: {
  identities: CreatorIdentityView[]
  trusted: CreatorIdentityView[]
  secureStorageAvailable: boolean
  busy: boolean
  identityLabel: string
  setIdentityLabel: (label: string) => void
  createIdentity: (label: string) => void
  deleteIdentity: (identityId: string) => void
  exportIdentity: (identityId: string) => void
  importTrusted: () => void
  setTrust: (identityId: string, status: 'trusted' | 'revoked') => void
  deleteTrusted: (identityId: string) => void
}) {
  const revokedCount = trusted.filter((identity) => identity.status === 'revoked').length
  const trustedCount = trusted.length - revokedCount

  return (
    <div className="space-y-6">
      <SectionHeader title="Signing Keys" description="Control which author fingerprints this device creates, trusts, blocks, or forgets." />

      <div className="grid gap-3 md:grid-cols-4">
        <StatusCard title="Private storage" ready={secureStorageAvailable} detail={secureStorageAvailable ? 'OS-protected key storage is available' : 'Private signing keys cannot be created on this device'} />
        <Stat label="Private keys" value={identities.length} />
        <Stat label="Trusted authors" value={trustedCount} />
        <Stat label="Revoked authors" value={revokedCount} />
      </div>

      <Card className="overflow-hidden p-0">
        <div className="border-b border-av-border/55 bg-gradient-to-br from-av-border/12 via-av-surface to-av-surface p-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="max-w-2xl">
              <p className="text-[11px] font-bold uppercase tracking-[0.22em] text-av-muted">Trust model</p>
              <h3 className="mt-2 text-xl font-bold tracking-tight text-av-main">Author identity stays local and explicit</h3>
              <p className="mt-2 text-sm leading-6 text-av-muted">
                Private signing keys identify archives you create. Trusted author cards identify public fingerprints you have imported from someone else.
              </p>
            </div>
            <div className="grid min-w-[260px] gap-2 text-sm">
              <div className="flex items-start gap-2 rounded-2xl border border-emerald-500/20 bg-emerald-500/8 p-3 text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />
                <span>Revoke keeps a blocked fingerprint on record.</span>
              </div>
              <div className="flex items-start gap-2 rounded-2xl border border-av-border/55 bg-av-surface/75 p-3 text-av-muted">
                <Trash2 className="mt-0.5 h-4 w-4 shrink-0" />
                <span>Remove forgets an imported author card from this device.</span>
              </div>
            </div>
          </div>
        </div>

        <div className="grid gap-4 p-5 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-end">
          <label className="min-w-0">
            <span className="mb-2 block text-sm font-semibold text-av-main">Create private signing key</span>
            <input
              value={identityLabel}
              onChange={(event) => setIdentityLabel(event.target.value)}
              onKeyDown={(event) => { if (event.key === 'Enter') createIdentity(identityLabel) }}
              maxLength={128}
              placeholder="Example: Product release signing key"
              disabled={busy || !secureStorageAvailable}
              className="w-full rounded-xl border border-av-border/80 bg-av-surface px-4 py-3 text-sm text-av-main outline-none transition focus:border-av-accent focus:ring-4 focus:ring-av-accent/10 disabled:cursor-not-allowed disabled:opacity-50"
            />
            <p className="mt-2 text-xs leading-5 text-av-muted">Use a label you will recognize later. The private material stays outside the renderer.</p>
          </label>
          <button
            disabled={busy || !secureStorageAvailable || !identityLabel.trim()}
            onClick={() => createIdentity(identityLabel)}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-av-main px-5 text-sm font-bold text-av-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
            type="button"
          >
            <UserRoundCheck className="h-4 w-4" />
            Create key
          </button>
        </div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-2">
        <Card className="space-y-4">
          <div className="flex items-start gap-3">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-av-border/60 bg-av-border/10 text-av-main">
              <KeyRound className="h-5 w-5" />
            </div>
            <div>
              <h3 className="font-bold text-av-main">Your private signing keys</h3>
              <p className="mt-1 text-sm leading-6 text-av-muted">Export public author cards for recipients. Delete a private key only when you no longer need to sign or rekey archives with it.</p>
            </div>
          </div>

          <div className="space-y-3">
            {identities.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-av-border p-5">
                <p className="font-semibold text-av-main">No private signing key yet</p>
                <p className="mt-1 text-sm leading-6 text-av-muted">Archives can still use archive-scoped signatures, but recipients will not see a reusable author fingerprint.</p>
              </div>
            ) : identities.map((identity) => (
              <div key={identity.identity_id} className="rounded-2xl border border-av-border/70 bg-av-border/5 p-4 transition-colors hover:bg-av-border/8">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="min-w-0">
                    <p className="font-bold text-av-main">{identity.label || 'Private signing key'}</p>
                    {identity.created_at && <p className="mt-1 text-xs text-av-muted">Created {new Date(identity.created_at).toLocaleString()}</p>}
                  </div>
                  <span className="w-fit rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em] text-emerald-700 dark:text-emerald-300">Private</span>
                </div>
                <p className="mt-3 break-all rounded-xl border border-av-border/50 bg-av-surface/70 p-3 font-mono text-[11px] leading-5 text-av-muted">{identity.identity_id}</p>
                <div className="mt-3 flex flex-wrap gap-2">
                  <button disabled={busy} onClick={() => exportIdentity(identity.identity_id)} className="inline-flex items-center gap-1.5 rounded-lg border border-av-border px-3 py-1.5 text-xs font-bold text-av-main transition-colors hover:bg-av-border/10 disabled:opacity-40" type="button">
                    <Download className="h-3.5 w-3.5" />
                    Export public card
                  </button>
                  <button disabled={busy} onClick={() => deleteIdentity(identity.identity_id)} className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-1.5 text-xs font-bold text-red-700 transition-colors hover:bg-red-500/10 disabled:opacity-40 dark:text-red-300" type="button">
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete key
                  </button>
                </div>
              </div>
            ))}
          </div>
        </Card>

        <Card className="space-y-4">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
            <div className="flex items-start gap-3">
              <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-av-border/60 bg-av-border/10 text-av-main">
                <ShieldCheck className="h-5 w-5" />
              </div>
              <div>
                <h3 className="font-bold text-av-main">Trusted authors</h3>
                <p className="mt-1 text-sm leading-6 text-av-muted">Import public author cards only after checking the fingerprint through a separate trusted channel.</p>
              </div>
            </div>
            <button disabled={busy} onClick={importTrusted} className="shrink-0 rounded-xl border border-av-border px-4 py-2.5 text-sm font-bold text-av-main transition-colors hover:bg-av-border/10 disabled:opacity-40" type="button">Import author card</button>
          </div>

          <div className="space-y-3">
            {trusted.length === 0 ? (
              <div className="rounded-2xl border border-dashed border-av-border p-5">
                <p className="font-semibold text-av-main">No trusted authors saved</p>
                <p className="mt-1 text-sm leading-6 text-av-muted">Imported author cards will appear here with trust, revoke, and remove controls.</p>
              </div>
            ) : trusted.map((identity) => {
              const revoked = identity.status === 'revoked'
              return (
                <div key={identity.identity_id} className={cn(
                  'rounded-2xl border p-4 transition-colors',
                  revoked ? 'border-red-500/25 bg-red-500/5' : 'border-av-border/70 bg-av-border/5 hover:bg-av-border/8',
                )}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <p className="font-bold text-av-main">{identity.label || 'Trusted author'}</p>
                      <p className="mt-1 break-all font-mono text-[11px] leading-5 text-av-muted">{identity.identity_id}</p>
                    </div>
                    <span className={cn(
                      'shrink-0 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.12em]',
                      revoked
                        ? 'border-red-500/30 bg-red-500/10 text-red-700 dark:text-red-300'
                        : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300',
                    )}>
                      {revoked ? 'Revoked' : 'Trusted'}
                    </span>
                  </div>
                  <p className="mt-3 rounded-xl border border-av-border/45 bg-av-surface/65 p-3 text-xs leading-5 text-av-muted">
                    {revoked
                      ? 'Archives from this author are blocked until trust is restored or the card is removed.'
                      : 'Archives from this author can use your saved trust decision during open and verification.'}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      disabled={busy}
                      onClick={() => setTrust(identity.identity_id, revoked ? 'trusted' : 'revoked')}
                      className={cn(
                        'rounded-lg border px-3 py-1.5 text-xs font-bold transition-colors disabled:opacity-40',
                        revoked
                          ? 'border-emerald-500/30 bg-emerald-500/8 text-emerald-700 hover:bg-emerald-500/12 dark:text-emerald-300'
                          : 'border-av-border text-av-main hover:bg-av-border/10',
                      )}
                      type="button"
                    >
                      {revoked ? 'Restore trust' : 'Revoke'}
                    </button>
                    <button disabled={busy} onClick={() => deleteTrusted(identity.identity_id)} className="inline-flex items-center gap-1.5 rounded-lg border border-red-500/30 bg-red-500/5 px-3 py-1.5 text-xs font-bold text-red-700 transition-colors hover:bg-red-500/10 disabled:opacity-40 dark:text-red-300" type="button">
                      <Trash2 className="h-3.5 w-3.5" />
                      Remove
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </Card>
      </div>
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
              <p className="mt-1 text-sm text-av-muted">Login authorizes escrow creation on this private authority. Archive-bound release capabilities do not expose this session.</p>
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
            <p className="mt-1 text-sm text-av-muted">Verifies the authority identity and hybrid-PQC suites used for escrow and release.</p>
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
            <Stat label="Protocol" value={diagnostics.protocol || 'unknown'} />
            <Stat label="Authority signatures" value={diagnostics.authority?.signature_suite || 'unknown'} />
            <div className="md:col-span-2">
              <PathBlock label="Authority ID" value={diagnostics.authority?.authority_id || 'Unavailable'} />
            </div>
            <div className="md:col-span-2">
              <PathBlock label="Release-key envelope" value={diagnostics.authority?.encryption_suite || 'Unavailable'} />
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
  const memoryLockReady = Boolean(settings?.runtime?.native_crypto?.memory_lock_available)
  const pqcReady = Boolean(settings?.runtime?.pqc_provider?.available)
  return (
    <div className="space-y-7">
      <SectionHeader title="Runtime" description="Inspect native crypto status and control preview cleanup behavior." />
      <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
        <StatusCard title="Native Rust crypto" ready={nativeReady} detail={nativeReady ? 'Available' : settings?.runtime?.native_crypto?.import_error || 'Unavailable'} />
        <StatusCard title="Memory lock" ready={memoryLockReady} detail={memoryLockReady ? 'Best-effort native key pinning' : 'Unavailable or denied by OS policy'} />
        <StatusCard title="OpenSSL PQC provider" ready={pqcReady} detail={pqcReady ? 'Available' : settings?.runtime?.pqc_provider?.reason || 'Unavailable'} />
      </div>
      <div className="grid gap-5 lg:grid-cols-[1.1fr_0.9fr]">
        <Card className="space-y-4">
          <div className="flex items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-av-border/60 bg-av-border/8 text-av-muted">
              <Database className="h-5 w-5" />
            </span>
            <div>
              <h3 className="font-bold text-av-main">Runtime paths</h3>
              <p className="mt-1 text-sm leading-6 text-av-muted">Local directories used by the packaged backend and temporary preview sessions.</p>
            </div>
          </div>
          <PathBlock label="Preview root" value={settings?.runtime?.preview_root || 'Unavailable'} />
          <PathBlock label="Log directory" value={settings?.runtime?.log_dir || 'Unavailable'} />
          <PathBlock label="Core version" value={settings?.runtime?.version || 'Unavailable'} />
        </Card>

        <Card className="space-y-4">
          <div className="flex items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-300">
              <FolderClock className="h-5 w-5" />
            </span>
            <div>
              <h3 className="font-bold text-av-main">Preview cleanup</h3>
              <p className="mt-1 text-sm leading-6 text-av-muted">Remove every active decrypted preview session immediately.</p>
            </div>
          </div>
          <button
            onClick={cleanupPreviews}
            disabled={cleaningPreviews || saving}
            className="inline-flex w-full items-center justify-center gap-2 rounded-xl bg-av-main px-4 py-3 text-sm font-semibold text-av-surface transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            <FolderClock className="h-4 w-4" />
            {cleaningPreviews ? 'Cleaning previews...' : 'Clean all preview files'}
          </button>
          <p className="text-xs leading-5 text-av-muted">This does not affect saved archives or exported files.</p>
        </Card>
      </div>
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
  const recommendedInstallers = updateInfo?.recommendedInstallers ?? []
  const copyChecksum = async (hash: string) => {
    try {
      await navigator.clipboard.writeText(hash)
      toast.success('SHA-256 copied')
    } catch {
      toast.error('Could not copy checksum')
    }
  }

  return (
    <div className="space-y-7">
      <SectionHeader title="Updates" description="Check official releases without silent installation." />
      <div className="grid gap-3 md:grid-cols-3">
        <Stat label="Current version" value={appInfo?.version ? `v${appInfo.version}` : 'unknown'} />
        <Stat label="Platform" value={appInfo ? `${appInfo.platform}-${appInfo.arch}` : 'unknown'} />
        <Stat label="Install type" value={appInfo?.packaged ? 'Packaged' : 'Development'} />
      </div>

      <Card className="space-y-5">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
          <div className="flex min-w-0 items-start gap-3">
            <span className={cn(
              'flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border',
              updateInfo?.updateAvailable
                ? 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300'
                : 'border-av-border/60 bg-av-border/8 text-av-muted',
            )}>
              <Download className="h-5 w-5" />
            </span>
            <div className="min-w-0">
              <h3 className="font-bold text-av-main">
                {updateInfo ? (updateInfo.updateAvailable ? `Version ${updateInfo.latestVersion} is available` : 'Avikal is up to date') : 'No update check has been run'}
              </h3>
              <p className="mt-1 text-sm leading-6 text-av-muted">
                {updateInfo
                  ? `${updateInfo.releaseName || `v${updateInfo.latestVersion}`}${updateInfo.publishedAt ? ` - ${new Date(updateInfo.publishedAt).toLocaleDateString()}` : ''}`
                  : 'Run a manual check to verify the latest official GitHub release.'}
              </p>
            </div>
          </div>
          {updateInfo && (
            <span className={cn(
              'shrink-0 rounded-full border px-3 py-1 text-[11px] font-bold uppercase tracking-[0.14em]',
              updateInfo.metadataVerified
                ? 'border-emerald-500/30 bg-emerald-500/10 text-emerald-600 dark:text-emerald-300'
                : 'border-amber-500/30 bg-amber-500/10 text-amber-600 dark:text-amber-300',
            )}>
              {updateInfo.metadataVerified ? 'Metadata verified' : 'Signature unavailable'}
            </span>
          )}
        </div>

        {recommendedInstallers.length > 0 && (
          <div className="space-y-3">
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-av-muted">Verified installers</p>
            {recommendedInstallers.map((asset) => (
              <div key={asset.url} className="rounded-2xl border border-av-border bg-av-border/5 p-4">
                <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <div className="min-w-0">
                    <p className="font-bold text-av-main">
                      {asset.kind === 'windows-gui' ? 'Windows App Installer' : 'Windows CLI Installer'}
                    </p>
                    <p className="mt-1 truncate text-xs text-av-muted">{asset.name} - {formatBytes(asset.size)}</p>
                  </div>
                  <button
                    onClick={() => void openExternalUrl(asset.url)}
                    className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-av-main px-4 py-2.5 text-sm font-bold text-av-surface transition-opacity hover:opacity-90"
                    type="button"
                  >
                    <Download className="h-4 w-4" />
                    Download
                  </button>
                </div>
                {asset.sha256 && (
                  <div className="mt-3 rounded-xl border border-av-border/70 bg-av-surface/70 p-3">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <span className="text-[10px] font-bold uppercase tracking-[0.18em] text-av-muted">SHA-256</span>
                      <button
                        type="button"
                        onClick={() => void copyChecksum(asset.sha256!)}
                        className="inline-flex items-center gap-1.5 rounded-lg border border-av-border px-2.5 py-1 text-[11px] font-bold text-av-main transition-colors hover:bg-av-border/10"
                      >
                        <Copy className="h-3.5 w-3.5" />
                        Copy
                      </button>
                    </div>
                    <p className="break-all font-mono text-[11px] leading-5 text-av-muted">{asset.sha256}</p>
                  </div>
                )}
              </div>
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
          Avikal checks the fixed official GitHub release feed. Updates are never installed silently; download and verify the installer hash before replacing your current version.
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
  exportingDiagnosticLog,
  exportActivityLog,
  exportDiagnosticLog,
}: {
  settings: SettingsPayload | null
  exportingAuditLog: boolean
  exportingDiagnosticLog: boolean
  exportActivityLog: () => void
  exportDiagnosticLog: () => void
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
        <PathBlock label="Support diagnostics log" value={settings?.diagnostic_log?.storage_path || 'Unavailable'} />
        <PathBlock label="Preview root" value={settings?.runtime?.preview_root || 'Unavailable'} />
        <PathBlock label="Log directory" value={settings?.runtime?.log_dir || 'Unavailable'} />
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <button
            onClick={exportActivityLog}
            disabled={exportingAuditLog}
            className="inline-flex items-center justify-center gap-2 rounded-xl border border-av-border bg-av-surface px-5 py-3 text-sm font-bold text-av-main shadow-sm transition-colors hover:bg-av-border/12 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            <Download className="h-4 w-4" />
            {exportingAuditLog ? 'Exporting...' : 'Export Activity Audit'}
          </button>
          <button
            onClick={exportDiagnosticLog}
            disabled={exportingDiagnosticLog}
            className="inline-flex items-center justify-center gap-2 rounded-xl bg-av-main px-5 py-3 text-sm font-bold text-av-surface shadow-sm transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-60"
            type="button"
          >
            <Download className="h-4 w-4" />
            {exportingDiagnosticLog ? 'Exporting...' : 'Export Support Diagnostics'}
          </button>
        </div>
        <p className="text-xs leading-6 text-av-muted">
          Activity audit is user-facing history. Support diagnostics is for debugging production errors and includes redacted IPC/backend failure evidence with correlation IDs.
        </p>
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
