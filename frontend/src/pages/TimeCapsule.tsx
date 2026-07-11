import { useState, useCallback, useEffect, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { motion } from 'framer-motion'
import {
  Lock, Key, Upload, Shield, ShieldAlert, RefreshCw, CheckCircle2,
  ChevronDown, Search, Eye, EyeOff, CheckCircle, ExternalLink,
  DownloadCloud, Copy, Calendar, Clock, Wifi, WifiOff, File, Folder, Fingerprint, MessageSquare, BarChart3
} from 'lucide-react'
import { toast } from 'sonner'
import { api } from '../lib/api'
import { callCoreResponse } from '../lib/backend'
import { waitForBackendReady } from '../lib/backendStatus'
import { parseBackendProgressChunk } from '../lib/backendProgress'
import { getErrorMessage } from '../lib/errors'
import { getDroppedPaths } from '../lib/electron'
import { useProgress } from '../hooks/useProgress'
import ProgressCard from '../components/ProgressCard'
import FileTree, { pruneTreeByPaths, type FileNode } from '../components/FileTree'
import type { PendingExternalLaunchAction } from '../lib/externalLaunch'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'
import ProcessingOverlay from '../components/ProcessingOverlay'
import ArchiveReportModal from '../components/ArchiveReportModal'
import { copyKeyphraseToClipboard, downloadStructuredKeyphrase } from '../lib/keyphraseExport'
import PasswordStrengthMeter from '../components/PasswordStrengthMeter'
import TrustedTimeNotice from '../components/TrustedTimeNotice'
import PqcSuiteSelector from '../components/PqcSuiteSelector'
import {
  DEFAULT_CUSTOM_KEM,
  DEFAULT_CUSTOM_SIGNATURE,
  DEFAULT_CUSTOM_SLH_SIGNATURE,
  DEFAULT_PQC_SUITE_ID,
  PQC_CUSTOM_SUITE_ID,
  pqcSuiteLabel,
  type MlDsaOption,
  type MlKemOption,
  type PqcSuiteId,
  type SlhDsaOption,
} from '../lib/pqcSuites'
import {
  getDefaultPqcStorageMode,
  getDefaultTimecapsuleProvider,
  USER_PREFERENCES_UPDATED_EVENT,
  type TimecapsuleProvider,
  type UserPreferences,
} from '../lib/preferences'

// â”€â”€â”€ Types â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
type PanelType = 'datetime' | 'password' | 'keyphrase' | 'pqc' | null
type PqcStorageMode = 'embedded' | 'external'

function deriveSiblingKeyfilePath(archivePath: string): string {
  return archivePath.replace(/(\.avk)?$/i, '.avkkey')
}

// Local timezone helpers
const USER_TIME_ZONE = Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'

function getLocalTimeZoneLabel(date: Date): string {
  const parts = new Intl.DateTimeFormat(undefined, { timeZoneName: 'short' }).formatToParts(date)
  return parts.find((part) => part.type === 'timeZoneName')?.value ?? USER_TIME_ZONE
}

function pad2(value: number): string {
  return String(value).padStart(2, '0')
}

function buildLocalDate(dateValue: string, timeValue: string): Date | null {
  if (!dateValue || !timeValue) return null

  const [year, month, day] = dateValue.split('-').map(Number)
  const [hour, minute] = timeValue.split(':').map(Number)
  if ([year, month, day, hour, minute].some((value) => Number.isNaN(value))) {
    return null
  }

  const date = new Date(year, month - 1, day, hour, minute, 0, 0)
  if (
    date.getFullYear() !== year ||
    date.getMonth() !== month - 1 ||
    date.getDate() !== day ||
    date.getHours() !== hour ||
    date.getMinutes() !== minute
  ) {
    return null
  }

  return date
}

function formatLocalInput(date: Date): string {
  return [
    date.getFullYear(),
    pad2(date.getMonth() + 1),
    pad2(date.getDate()),
  ].join('-') + `T${pad2(date.getHours())}:${pad2(date.getMinutes())}`
}

function displayLocal(dateValue: string, timeValue: string): string {
  const date = buildLocalDate(dateValue, timeValue)
  if (!date) return ''
  return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })
}

function getLocalTimestamp(dateValue: string, timeValue: string): number | null {
  return buildLocalDate(dateValue, timeValue)?.getTime() ?? null
}

function getLocalIsoString(dateValue: string, timeValue: string): string | null {
  return buildLocalDate(dateValue, timeValue)?.toISOString() ?? null
}

// â”€â”€â”€ NTP fetch â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
async function fetchNTPTime(): Promise<Date> {
  // We use a lightweight public HTTP endpoint that returns the server time in headers.
  // time.google.com is a pure NTP server (UDP), not HTTP â€” so we use the backend NTP endpoint
  // which already calls time.google.com, or fall back to a public HTTP time API.
  try {
    await waitForBackendReady()
    const res = await callCoreResponse('time.ntp', { method: 'GET' })
    if (res.ok) {
      const data = await res.json()
      if (data.timestamp) return new Date(data.timestamp * 1000)
    }
  } catch {
    // backend unavailable â€” try world time API
  }
  throw new Error('Trusted time is currently unavailable')
}

// â”€â”€â”€ Component â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
interface TimeCapsuleProps {
  externalLaunchAction?: PendingExternalLaunchAction | null
}

export default function TimeCapsule({ externalLaunchAction }: TimeCapsuleProps) {
  const { sessionToken, refreshUserProfile, aavritMode, aavritServerUrl } = useAuth()
  const [timecapsuleProvider, setTimecapsuleProvider] = useState<TimecapsuleProvider>(() => getDefaultTimecapsuleProvider())
  const [timecapsuleProviderOverridden, setTimecapsuleProviderOverridden] = useState(false)
  const [authorityExpanded, setAuthorityExpanded] = useState(false)
  const [files, setFiles]               = useState<string[]>([])
  const [treeNodes, setTreeNodes]       = useState<FileNode[]>([])
  const [selectedTreePaths, setSelectedTreePaths] = useState<Set<string>>(() => new Set())
  const [excludedInputPaths, setExcludedInputPaths] = useState<string[]>([])
  const [isDragging, setIsDragging]     = useState(false)
  const [activePanel, setActivePanel]   = useState<PanelType>('datetime')
  const [passwordEnabled, setPasswordEnabled] = useState(false)
  const [keyphraseEnabled, setKeyphraseEnabled] = useState(false)

  const [password, setPassword]         = useState('')
  const [keyphrase, setKeyphrase]       = useState('')
  const [loading, setLoading]           = useState(false)
  const [searchQuery, setSearchQuery]   = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [isEncrypted, setIsEncrypted]   = useState(false)
  const [outputFilePath, setOutputFilePath] = useState('')
  const [createdPqcKeyfilePath, setCreatedPqcKeyfilePath] = useState('')
  const [createdPqcStorageMode, setCreatedPqcStorageMode] = useState<PqcStorageMode>(() => getDefaultPqcStorageMode())
  const [isCopied, setIsCopied]         = useState(false)
  const [pqcEnabled, setPqcEnabled]     = useState(false)
  const [pqcStorageMode, setPqcStorageMode] = useState<PqcStorageMode>(() => getDefaultPqcStorageMode())
  const [pqcKeyfilePath, setPqcKeyfilePath] = useState('')
  const [pqcKeyfilePasswordEnabled, setPqcKeyfilePasswordEnabled] = useState(false)
  const [pqcKeyfilePassword, setPqcKeyfilePassword] = useState('')
  const [showPqcKeyfilePassword, setShowPqcKeyfilePassword] = useState(false)
  const [pqcModeOverridden, setPqcModeOverridden] = useState(false)
  const [pqcSuiteId, setPqcSuiteId] = useState<PqcSuiteId>(DEFAULT_PQC_SUITE_ID)
  const [pqcCustomKem, setPqcCustomKem] = useState<MlKemOption>(DEFAULT_CUSTOM_KEM)
  const [pqcCustomSignature, setPqcCustomSignature] = useState<MlDsaOption>(DEFAULT_CUSTOM_SIGNATURE)
  const [pqcCustomSlhSignature, setPqcCustomSlhSignature] = useState<SlhDsaOption>(DEFAULT_CUSTOM_SLH_SIGNATURE)
  const [senderMessageEnabled, setSenderMessageEnabled] = useState(false)
  const [senderMessage, setSenderMessage] = useState('')
  const [creatorIdentities, setCreatorIdentities] = useState<Array<{ identity_id: string; label: string }>>([])
  const [creatorIdentityId, setCreatorIdentityId] = useState('')
  const [creationReport, setCreationReport] = useState<Record<string, unknown> | null>(null)
  const [showCreationReport, setShowCreationReport] = useState(false)
  const progress = useProgress()
  const backendRuntime = useBackendRuntime()

  // Date & time state (user-local timezone)
  const [unlockDate, setUnlockDate]     = useState('')
  const [unlockTime, setUnlockTime]     = useState('')
  const [ntpTime, setNtpTime]           = useState<Date | null>(null)
  const [ntpSynced, setNtpSynced]       = useState<boolean | null>(null)
  const [timeOffset, setTimeOffset]     = useState<number | null>(null)
  const ntpFetched = useRef(false)
  const filesRef = useRef<string[]>([])

  const normalizeUiPath = (value: string) => value.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
  const isSameOrChildPath = (candidate: string, parent: string) => {
    const candidatePath = normalizeUiPath(candidate)
    const parentPath = normalizeUiPath(parent)
    return candidatePath === parentPath || candidatePath.startsWith(`${parentPath}/`)
  }

  const resetTimecapsulePanel = useCallback(() => {
    setAuthorityExpanded(false)
    setTimecapsuleProvider(getDefaultTimecapsuleProvider())
    setTimecapsuleProviderOverridden(false)
    setActivePanel('datetime')
    setUnlockDate('')
    setUnlockTime('')
    setPasswordEnabled(false)
    setKeyphraseEnabled(false)
    setPassword('')
    setKeyphrase('')
    setShowPassword(false)
    setIsCopied(false)
    setPqcEnabled(false)
    setPqcStorageMode(getDefaultPqcStorageMode())
    setPqcKeyfilePath('')
    setPqcKeyfilePasswordEnabled(false)
    setPqcKeyfilePassword('')
    setShowPqcKeyfilePassword(false)
    setPqcModeOverridden(false)
    setPqcSuiteId(DEFAULT_PQC_SUITE_ID)
    setPqcCustomKem(DEFAULT_CUSTOM_KEM)
    setPqcCustomSignature(DEFAULT_CUSTOM_SIGNATURE)
    setPqcCustomSlhSignature(DEFAULT_CUSTOM_SLH_SIGNATURE)
    setSenderMessageEnabled(false)
    setSenderMessage('')
    setCreatorIdentityId('')
  }, [])

  useEffect(() => {
    void window.electron?.creatorIdentity?.list().then(result => {
      setCreatorIdentities((result.identities || []).map(item => ({ identity_id: String(item.identity_id || ''), label: String(item.label || 'Creator identity') })).filter(item => /^[0-9a-f]{64}$/.test(item.identity_id)))
    }).catch(() => setCreatorIdentities([]))
  }, [])

  useEffect(() => {
    filesRef.current = files
  }, [files])

  useEffect(() => {
    if (!pqcEnabled || pqcStorageMode !== 'external') {
      setPqcKeyfilePasswordEnabled(false)
      setPqcKeyfilePassword('')
      setShowPqcKeyfilePassword(false)
    }
  }, [pqcEnabled, pqcStorageMode])

  useEffect(() => {
    const applyPqcDefault = (mode: PqcStorageMode) => {
      setPqcStorageMode(current => pqcModeOverridden ? current : mode)
    }
    const applyProviderDefault = (provider: TimecapsuleProvider) => {
      setTimecapsuleProvider(current => {
        if (timecapsuleProviderOverridden) return current
        if (provider === 'aavrit' && !aavritServerUrl) return 'drand'
        return provider
      })
    }

    const onPreferencesUpdated = (event: Event) => {
      const detail = (event as CustomEvent<UserPreferences>).detail
      const pqcMode = detail?.archive_defaults?.pqc_storage_mode
      const provider = detail?.archive_defaults?.default_timecapsule_provider
      if (pqcMode === 'embedded' || pqcMode === 'external') applyPqcDefault(pqcMode)
      if (provider === 'drand' || provider === 'aavrit') applyProviderDefault(provider)
    }

    const onFocus = () => {
      applyPqcDefault(getDefaultPqcStorageMode())
      applyProviderDefault(getDefaultTimecapsuleProvider())
    }

    window.addEventListener(USER_PREFERENCES_UPDATED_EVENT, onPreferencesUpdated)
    window.addEventListener('focus', onFocus)
    return () => {
      window.removeEventListener(USER_PREFERENCES_UPDATED_EVENT, onPreferencesUpdated)
      window.removeEventListener('focus', onFocus)
    }
  }, [aavritServerUrl, pqcModeOverridden, timecapsuleProviderOverridden])

  useEffect(() => {
    if (!aavritServerUrl || (aavritMode === 'private' && !sessionToken)) {
      setTimecapsuleProvider('drand')
      setTimecapsuleProviderOverridden(false)
    }
  }, [aavritMode, aavritServerUrl, sessionToken])

  useEffect(() => {
    const unsubscribe = window.electron?.onBackendLog?.((message) => {
      if (!loading && progress.status !== 'running') return
      for (const event of parseBackendProgressChunk(message)) {
        if (event.operation !== 'timecapsule-encrypt') continue
        progress.update({
          status: event.status === 'error' ? 'error' : event.status === 'completed' ? 'completed' : 'running',
          percentage: event.percentage,
          currentOperation: event.currentOperation,
          etaSeconds: event.etaSeconds,
          fileSize: event.fileSize,
          compressionRatio: event.compressionRatio,
          processedBytes: event.processedBytes,
          totalBytes: event.totalBytes,
          throughputBytesPerSecond: event.throughputBytesPerSecond,
        })
      }
    })
    return () => {
      unsubscribe?.()
    }
  }, [loading, progress.status, progress.update])

  // Fetch NTP time on mount
  useEffect(() => {
    if (ntpFetched.current) return
    ntpFetched.current = true
    fetchNTPTime().then(t => {
      setTimeOffset(t.getTime() - Date.now())
      setNtpSynced(true)
    }).catch(() => {
      setTimeOffset(0)
      setNtpSynced(false)
    })
  }, [])

  // Real-time ticking clock
  useEffect(() => {
    if (timeOffset === null) return
    const interval = setInterval(() => {
      setNtpTime(new Date(Date.now() + timeOffset))
    }, 1000)
    setNtpTime(new Date(Date.now() + timeOffset))
    return () => clearInterval(interval)
  }, [timeOffset])

  const keyphraseWords = keyphrase.trim() ? keyphrase.trim().split(/\s+/).filter(Boolean) : []

  // Password strength (Encrypt-parity)
  const hasMinLen = password.length >= 12
  const hasUpper = /[A-Z]/.test(password)
  const hasLower = /[a-z]/.test(password)
  const hasNumber = /[0-9]/.test(password)
  const hasSpecial = /[^A-Za-z0-9]/.test(password)
  const needsPqcKeyfilePassword = pqcEnabled && pqcStorageMode === 'external' && pqcKeyfilePasswordEnabled
  const isValidPqcKeyfilePassword =
    !needsPqcKeyfilePassword ||
    (
      pqcKeyfilePassword.length >= 12 &&
      /[A-Z]/.test(pqcKeyfilePassword) &&
      /[a-z]/.test(pqcKeyfilePassword) &&
      /[0-9]/.test(pqcKeyfilePassword) &&
      /[^A-Za-z0-9]/.test(pqcKeyfilePassword) &&
      (!passwordEnabled || pqcKeyfilePassword !== password)
    )
  const pqcKeyfilePasswordIssue =
    pqcKeyfilePassword && passwordEnabled && pqcKeyfilePassword === password
      ? 'Must be different from archive password.'
      : ''

  const normalizeKeyphrase = (value: unknown): string => {
    if (Array.isArray(value)) return value.filter(Boolean).join(' ')
    if (typeof value === 'string') return value.trim()
    return ''
  }

  const promptAavritLogin = () => {
    window.dispatchEvent(new Event('avikal:open-auth-modal'))
  }

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])
  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  // Scan a single path and create a tree node for the UI
  const scanAndAddPath = useCallback(async (pathStr: string) => {
    const electron = window.electron
    try {
      const node = await electron?.scanDirectory(pathStr) as FileNode | undefined
      if (node) {
        setTreeNodes(prev => {
          if (prev.some(n => n.path === node.path)) return prev
          return [...prev, node]
        })
      }
    } catch {
      setTreeNodes(prev => {
        if (prev.some(n => n.path === pathStr)) return prev
        const basename = pathStr.split(/[/\\]/).pop() || pathStr
        return [...prev, { name: basename, path: pathStr, isDir: false, size: 0 }]
      })
    }
  }, [])

  const addPathsToSelection = useCallback((incomingPaths: string[]) => {
    const sanitized = incomingPaths
      .map((item) => item.trim())
      .filter(Boolean)
    const newPaths = sanitized.filter((item) => !filesRef.current.includes(item))

    if (newPaths.length === 0) {
      return
    }

    setFiles((prev) => [...prev, ...newPaths])
    setSelectedTreePaths(new Set())
    newPaths.forEach((item) => {
      void scanAndAddPath(item)
    })
  }, [scanAndAddPath])

  useEffect(() => {
    if (externalLaunchAction?.target !== 'timecapsule') {
      return
    }

    addPathsToSelection(externalLaunchAction.paths)
  }, [addPathsToSelection, externalLaunchAction])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const dropped = getDroppedPaths(e.dataTransfer.files)
    const newPaths = dropped.filter(f => !files.includes(f))
    if (dropped.length - newPaths.length > 0) toast.error(`${dropped.length - newPaths.length} duplicate(s) skipped`)
    addPathsToSelection(newPaths)
  }, [addPathsToSelection, files])

  const handleBrowseFiles = async () => {
    try {
      const electron = window.electron
      const selected = await electron?.openFile({ properties: ['openFile', 'multiSelections'] }) as string[] | undefined
      if (selected?.length) {
        const newPaths = selected.filter(f => !files.includes(f))
        if (selected.length - newPaths.length > 0) toast.error(`${selected.length - newPaths.length} duplicate(s) skipped`)
        addPathsToSelection(newPaths)
      }
    } catch (error) { console.error(error) }
  }

  const handleBrowseFolders = async () => {
    try {
      const electron = window.electron
      const selected = await electron?.openFolders() as string[] | undefined
      if (selected?.length) {
        const newPaths = selected.filter(f => !files.includes(f))
        if (selected.length - newPaths.length > 0) toast.error(`${selected.length - newPaths.length} duplicate(s) skipped`)
        addPathsToSelection(newPaths)
      }
    } catch (error) { console.error(error) }
  }

  const handleTreeSelectionChange = (paths: string[], selected: boolean) => {
    setSelectedTreePaths(prev => {
      const next = new Set(prev)
      for (const path of paths) {
        if (selected) next.add(path)
        else next.delete(path)
      }
      return next
    })
  }

  const handleRemoveTreePaths = (paths: string[]) => {
    const removeSet = new Set(paths)
    const removedRoots = files.filter(rootPath => removeSet.has(rootPath))
    setFiles(prev => prev.filter(rootPath => !removeSet.has(rootPath)))
    setTreeNodes(prev => pruneTreeByPaths(prev, removeSet))
    setSelectedTreePaths(prev => {
      const next = new Set(prev)
      for (const path of paths) next.delete(path)
      return next
    })
    const nestedExclusions = paths.filter(path =>
      !files.includes(path)
      && !removedRoots.some(rootPath => isSameOrChildPath(path, rootPath))
    )
    setExcludedInputPaths(prev => {
      const next = prev.filter(existing =>
        !removeSet.has(existing)
        && !removedRoots.some(rootPath => isSameOrChildPath(existing, rootPath))
      )
      return Array.from(new Set([...next, ...nestedExclusions]))
    })
  }

  const handleClearAllStagedInputs = () => {
    setFiles([])
    setTreeNodes([])
    setSelectedTreePaths(new Set())
    setExcludedInputPaths([])
    setSearchQuery('')
  }

  // Generate keyphrase via backend
  const handleGenerateKeyphrase = async () => {
    try {
      const result = await api.generateKeyphrase(21)
      if (result.success) {
        const generated = normalizeKeyphrase(result.keyphrase)
        setKeyphrase(generated)
        toast.success('Keyphrase generated! Store it securely.')
      }
    } catch { toast.error('Failed to generate keyphrase') }
  }

  const handleCopyKeyphrase = async () => {
    if (!keyphrase) return
    const copied = await copyKeyphraseToClipboard(keyphrase)
    if (copied) {
      setIsCopied(true)
      toast.success('Keyphrase copied')
      setTimeout(() => setIsCopied(false), 2000)
    } else {
      toast.error('Clipboard copy failed. Use Download instead.')
    }
  }

  const handleDownloadKeyphrase = async () => {
    if (!keyphrase) return
    const saved = await downloadStructuredKeyphrase(keyphrase, 'Time-Capsule recovery keyphrase')
    if (saved) toast.success('Keyphrase document saved')
  }

  const togglePasswordProtection = () => {
    setPasswordEnabled((current) => {
      const next = !current
      if (!next) {
        setPassword('')
        setShowPassword(false)
      }
      return next
    })
  }

  const toggleKeyphraseProtection = () => {
    setKeyphraseEnabled((current) => {
      const next = !current
      if (!next) {
        setKeyphrase('')
        setIsCopied(false)
      }
      return next
    })
  }

  const togglePqcProtection = () => {
    setPqcEnabled((current) => {
      const next = !current
      if (!next) {
        setPqcKeyfilePath('')
        setPqcKeyfilePasswordEnabled(false)
        setPqcKeyfilePassword('')
        setShowPqcKeyfilePassword(false)
        setPqcStorageMode(getDefaultPqcStorageMode())
        setPqcModeOverridden(false)
      }
      return next
    })
  }

  // Validate & submit to integration backend
  const handleEncode = async () => {
    if (!backendRuntime.isReady) {
      toast.info(backendRuntime.detail)
      return
    }
    if (files.length === 0) { toast.error('Please select files to lock'); return }
    if (!unlockDate || !unlockTime) { toast.error('Please set the unlock date & time'); return }

    const unlockMs = getLocalTimestamp(unlockDate, unlockTime)
    const nowMs = ntpTime?.getTime() ?? null
    if (unlockMs === null) { toast.error('Please set the unlock date & time'); return }
    if (ntpSynced && nowMs !== null && unlockMs <= nowMs) {
      toast.error('Unlock time must be in the future according to trusted network time')
      return
    }

    if (usePass) {
      if (!password) { toast.error('Please enter a password'); return }
      if (!isPasswordReady) {
        toast.error('Use a strong password with 12+ characters, uppercase, lowercase, number, and symbol')
        return
      }
    }
    if (useKeyp && !keyphrase) { toast.error('Please generate or enter a keyphrase'); return }
    if (useKeyp && !isKeyphraseReady) {
      toast.error('Time-Capsule keyphrase must contain all 21 words')
      return
    }
    if (pqcEnabled && !hasProtection) {
      toast.error('Quantum keyfile mode requires a password or keyphrase')
      return
    }
    if (needsPqcKeyfilePassword && !isValidPqcKeyfilePassword) {
      toast.error('Use a strong .avkkey password that differs from the archive password')
      return
    }
    if (timecapsuleProvider === 'aavrit' && !aavritServerUrl) {
      toast.error('Aavrit mode requires an Aavrit server connection. Connect to your Aavrit server or switch to drand.')
      promptAavritLogin()
      return
    }
    if (timecapsuleProvider === 'aavrit' && aavritMode === 'private' && !sessionToken) {
      toast.error('Private Aavrit mode requires Aavrit login. Connect to your Aavrit server or switch to drand.')
      promptAavritLogin()
      return
    }

    const unlockIso = getLocalIsoString(unlockDate, unlockTime)
    if (!unlockIso) { toast.error('Please set the unlock date & time'); return }

    try {
      const electron = window.electron
      const outputFile = await electron?.saveFile({
        defaultPath: `timecapsule-${new Date().toISOString().split('T')[0]}.avk`,
        filters: [{ name: 'RookDuel Avikal Time-Capsule', extensions: ['avk'] }]
      })
      if (!outputFile) return

      let nextPqcKeyfilePath = ''
      if (pqcEnabled && pqcStorageMode === 'external') {
        nextPqcKeyfilePath = pqcKeyfilePath
        if (!nextPqcKeyfilePath) {
          const selectedKeyfilePath = await electron?.saveFile({
            defaultPath: deriveSiblingKeyfilePath(outputFile),
            filters: [{ name: 'RookDuel Avikal PQC Keyfile', extensions: ['avkkey'] }]
          })
          if (!selectedKeyfilePath) {
            toast.error('Choose a secure destination for the .avkkey file to continue')
            return
          }
          nextPqcKeyfilePath = selectedKeyfilePath
        }
        if (!nextPqcKeyfilePath) {
          toast.error('Choose a secure destination for the .avkkey file to continue')
          return
        }
        setPqcKeyfilePath(nextPqcKeyfilePath)
      }

      setLoading(true)
      setIsEncrypted(false)
      setOutputFilePath(outputFile)
      setCreatedPqcKeyfilePath('')
      setCreatedPqcStorageMode(pqcStorageMode)
      progress.reset()
      progress.update({
        status: 'running',
        currentOperation: 'Starting Time-Capsule Engine...',
        percentage: 0,
      })

      // Use the current Aavrit session from AuthContext for backend authorization
      // Call the correct Python API endpoint for timecapsule creation
      const result = await api.encrypt({
        input_files: files,
        excluded_input_paths: excludedInputPaths.length > 0 ? excludedInputPaths : undefined,
        output_file: outputFile,
        password: password || undefined,
        keyphrase: keyphrase ? keyphrase.split(' ') : undefined,
        unlock_datetime: unlockIso,
        use_timecapsule: true,
        timecapsule_provider: timecapsuleProvider,
        pqc_enabled: pqcEnabled,
        pqc_storage_mode: pqcEnabled ? pqcStorageMode : undefined,
        pqc_keyfile_output: pqcEnabled && pqcStorageMode === 'external' ? nextPqcKeyfilePath : undefined,
        pqc_keyfile_protection_mode: needsPqcKeyfilePassword ? 'dual_password' : 'archive_secret',
        pqc_keyfile_password: needsPqcKeyfilePassword ? pqcKeyfilePassword : undefined,
        pqc_suite_id: pqcEnabled ? pqcSuiteId : undefined,
        pqc_custom_kem: pqcEnabled && pqcSuiteId === PQC_CUSTOM_SUITE_ID ? pqcCustomKem : undefined,
        pqc_custom_signature: pqcEnabled && pqcSuiteId === PQC_CUSTOM_SUITE_ID ? pqcCustomSignature : undefined,
        pqc_custom_slh_signature: pqcEnabled && pqcSuiteId === PQC_CUSTOM_SUITE_ID ? pqcCustomSlhSignature : undefined,
        sender_message: senderMessageEnabled ? senderMessage : undefined,
        creator_identity_id: creatorIdentityId || undefined,
      }, timecapsuleProvider === 'aavrit' ? (sessionToken || '') : undefined)
      
      if (!result.success) throw new Error(result.message || 'Time-Capsule creation failed')

      setCreatedPqcKeyfilePath(result?.result?.pqc?.keyfile || nextPqcKeyfilePath || '')
      setCreationReport((result?.result?.creation_report as Record<string, unknown> | undefined) || null)
      setIsEncrypted(true)
      if (timecapsuleProvider === 'aavrit' && sessionToken) {
        void refreshUserProfile()
      }
      resetTimecapsulePanel()
      progress.update({
        status: 'completed',
        currentOperation: 'Time-Capsule created',
        percentage: 100,
      })
        toast.success(
          pqcEnabled
            ? pqcStorageMode === 'embedded'
              ? 'Time-Capsule with embedded quantum protection created successfully!'
              : 'Time-Capsule and PQC keyfile created successfully!'
            : timecapsuleProvider === 'drand'
            ? 'drand Time-Capsule created successfully!'
            : 'Aavrit Time-Capsule created successfully!'
      )
      setPassword('')
      setKeyphrase('')
      setPqcKeyfilePassword('')
      setActivePanel('datetime')
    } catch (error: unknown) {
      progress.update({
        status: 'error',
        currentOperation: 'Time-Capsule creation failed',
        percentage: progress.percentage || 0,
      })
      toast.error(getErrorMessage(error, 'Time-Capsule creation failed'))
    } finally {
      setPassword('')
      setKeyphrase('')
      setPqcKeyfilePassword('')
      setLoading(false)
    }
  }

  const usePass = passwordEnabled
  const useKeyp = keyphraseEnabled
  const hasProtection = usePass || useKeyp
  const isBoth = usePass && useKeyp
  const isTrioProtection = isBoth && pqcEnabled
  const isPasswordReady = usePass
    ? hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
    : true
  const isKeyphraseReady = useKeyp ? keyphraseWords.length === 21 : true

  // Compute min datetime from trusted current time in the user's local timezone plus a 2 minute buffer.
  const nowLocalDatetime = ntpTime ? new Date(ntpTime.getTime() + 120 * 1000) : new Date(Date.now() + 120 * 1000)
  const minDateStr = formatLocalInput(nowLocalDatetime).slice(0, 10)
  const minTimeStr = formatLocalInput(nowLocalDatetime).slice(11, 16)
  const isSelectedDateMin = unlockDate === minDateStr
  const unlockMs = getLocalTimestamp(unlockDate, unlockTime)
  const nowMs = ntpTime?.getTime() ?? null
  const currentTimeZoneLabel = ntpTime ? getLocalTimeZoneLabel(ntpTime) : getLocalTimeZoneLabel(new Date())
  const isUnlockReady = unlockMs !== null && (ntpSynced ? nowMs !== null && unlockMs > nowMs : true)
  const isFilesReady = files.length > 0
  const showInlineProgressCard = false
  const senderMessageWordCount = senderMessage.trim().split(/\s+/).filter(Boolean).length
  const senderMessageByteCount = new TextEncoder().encode(senderMessage).length
  const isSenderMessageValid = !senderMessageEnabled || (senderMessageWordCount > 0 && senderMessageWordCount <= 100 && senderMessageByteCount <= 1024)
  const canAttemptCreateTimeCapsule = backendRuntime.isReady && !loading && isFilesReady && unlockMs !== null && isValidPqcKeyfilePassword && isSenderMessageValid
  const isAavritAvailable = Boolean(aavritServerUrl && (aavritMode !== 'private' || sessionToken))
  const providerModeLabel = timecapsuleProvider === 'drand'
    ? 'drand'
    : aavritMode === 'private'
      ? 'Private'
      : 'Public'

  return (
    <div className="av-page-shell">
      <TrustedTimeNotice enabled context="timecapsule" />

      {/* 60/40 Split Architecture */}
      <div className="av-work-grid">

      {/* â”€â”€ Left Panel: File Staging (60%) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <div className="av-primary-panel lg:col-span-3 flex flex-col overflow-hidden relative">
        <div className="av-panel-header z-10 shrink-0">
          <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
            Time <span className="font-light text-av-muted">Capsule</span>
          </h2>
          <p className="text-av-muted text-sm font-light">Protect files until a future date with time-based sealing.</p>
        </div>

        <div
          className="av-left-workspace flex-1 flex flex-col relative overflow-hidden"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {loading && !isEncrypted && (
            <ProcessingOverlay
              title="Creating Time-Capsule"
              description={progress.currentOperation || 'Creating your secure time-locked archive.'}
              icon={<Clock className="h-5 w-5 text-av-accent" strokeWidth={1.7} />}
              percentage={progress.percentage}
              etaSeconds={progress.etaSeconds}
              elapsedSeconds={progress.elapsedSeconds}
              fileSize={progress.fileSize}
              indeterminateText="Sealing archive to release time"
            />
          )}

          {/* Success state */}
          {isEncrypted && (
            <div className="av-processing-overlay flex-1 flex flex-col items-center justify-center p-8 z-20">
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className="av-result-card w-full max-w-md p-8 rounded-3xl flex flex-col items-center text-center relative overflow-hidden"
              >
                <div className="absolute top-0 inset-x-0 h-1 bg-gradient-to-r from-transparent via-green-500/30 to-transparent" />
                <div className="w-20 h-20 rounded-full bg-green-500/10 flex items-center justify-center mb-6 border border-green-500/20">
                  <CheckCircle className="w-10 h-10 text-green-500" />
                </div>
                <h3 className="text-2xl font-semibold text-av-main mb-2">Secure Archive Created!</h3>
                <p className="text-sm text-av-muted mb-2 leading-relaxed">
                  Your files are locked until{' '}
                  <span className="text-av-main font-semibold">{(unlockDate && unlockTime) ? `${displayLocal(unlockDate, unlockTime)} ${currentTimeZoneLabel}` : ''}</span>.
                </p>
                <p className="text-xs text-av-muted mb-8">They will be sealed inside your .avk capsule.</p>

                <div
                  onClick={() => {
                    const electron = window.electron
                    if (outputFilePath && electron?.openPath) {
                      electron.openPath(outputFilePath.substring(0, outputFilePath.lastIndexOf('\\')))
                    }
                  }}
                  className="w-full p-5 rounded-2xl bg-av-border/5 border border-av-border flex items-center gap-4 cursor-pointer hover:border-av-accent/50 group transition-all"
                >
                  <div className="w-12 h-12 rounded-xl bg-av-accent/10 flex items-center justify-center shrink-0">
                    <DownloadCloud className="w-6 h-6 text-av-accent" />
                  </div>
                  <div className="text-left truncate flex-1">
                    <p className="text-[10px] font-bold text-av-muted uppercase tracking-wider mb-0.5">LOCATION</p>
                    <p className="text-sm font-medium text-av-main truncate group-hover:text-av-accent transition-colors">{outputFilePath}</p>
                  </div>
                  <ExternalLink className="w-5 h-5 text-av-muted group-hover:text-av-accent transition-colors" />
                </div>

                {createdPqcStorageMode === 'embedded' && pqcEnabled && !createdPqcKeyfilePath && (
                  <div className="w-full mt-4 p-5 rounded-2xl bg-emerald-500/5 border border-emerald-500/20 flex items-center gap-4 transition-all">
                    <div className="w-12 h-12 rounded-xl bg-emerald-500/10 flex items-center justify-center shrink-0 border border-emerald-500/20">
                      <Fingerprint className="w-6 h-6 text-emerald-500" />
                    </div>
                    <div className="text-left truncate flex-1">
                      <p className="text-[10px] font-bold text-emerald-500 uppercase tracking-wider mb-0.5">Embedded Quantum Protection</p>
                      <p className="text-sm font-medium text-av-main truncate">Stored inside the .avk archive</p>
                      <p className="text-[11px] text-av-muted mt-1">The capsule still needs the correct password or keyphrase after release before embedded quantum unlock can continue.</p>
                    </div>
                  </div>
                )}

                {createdPqcKeyfilePath && (
                  <div className="w-full mt-4 p-5 rounded-2xl bg-amber-500/5 border border-amber-500/20 flex items-center gap-4 transition-all">
                    <div className="w-12 h-12 rounded-xl bg-amber-500/10 flex items-center justify-center shrink-0 border border-amber-500/20">
                      <Fingerprint className="w-6 h-6 text-amber-500" />
                    </div>
                    <div className="text-left truncate flex-1">
                      <p className="text-[10px] font-bold text-amber-500 uppercase tracking-wider mb-0.5">Quantum Keyfile</p>
                      <p className="text-sm font-medium text-av-main truncate">{createdPqcKeyfilePath}</p>
                      <p className="text-[11px] text-av-muted mt-1">Keep this `.avkkey` in a separate secure location. Without it, unlock is impossible.</p>
                    </div>
                  </div>
                )}

                {creationReport && <button type="button" onClick={() => setShowCreationReport(true)} className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl border border-av-border/50 bg-av-surface/70 px-4 py-3 text-sm font-semibold text-av-main"><BarChart3 className="h-4 w-4" />View detailed report</button>}

                <button
                  onClick={() => {
                    setIsEncrypted(false)
                      setFiles([])
                      setTreeNodes([])
                      setSelectedTreePaths(new Set())
                      setExcludedInputPaths([])
                      setPqcEnabled(false)
                      setPqcStorageMode('embedded')
                      setPqcKeyfilePath('')
                      setCreatedPqcKeyfilePath('')
                      setCreationReport(null)
                      setShowCreationReport(false)
                  }}
                  className="mt-8 w-full py-4 rounded-xl bg-av-accent text-white font-bold hover:opacity-90 transition-all shadow-lg shadow-av-accent/20"
                >
                  Done
                </button>
              </motion.div>
            </div>
          )}

          {/* File list / drop zone */}
          {!loading && !isEncrypted && (
            files.length === 0 ? (
              <div className="flex-1 p-8 flex flex-col relative">
                <div
                  className={`av-drop-zone flex-1 rounded-2xl flex flex-col items-center justify-center transition-all duration-300 relative overflow-hidden ${
                    isDragging
                      ? 'av-drop-zone-active'
                      : 'text-av-muted'
                  }`}
                >
                  <div className="pointer-events-none absolute inset-0 opacity-0" />
                  <motion.div animate={{ y: isDragging ? -10 : 0 }} className="z-10 flex flex-col items-center">
                    <div className="w-20 h-20 rounded-2xl bg-av-border/10 flex items-center justify-center mb-6 shadow-sm border border-av-border text-av-main">
                      <Upload className="w-8 h-8" strokeWidth={1.5} />
                    </div>
                    <h3 className="text-xl font-medium text-av-main mb-2">
                      {isDragging ? 'Drop files to add' : 'Select files to protect'}
                    </h3>
                    <p className="text-sm text-av-muted mb-6">Drag & drop, or use the buttons below</p>
                    <div className="flex items-center gap-3">
                      <button
                        onClick={handleBrowseFiles}
                        className="flex items-center gap-2 text-xs bg-av-main text-av-surface font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:opacity-90 active:scale-95"
                      >
                        <File className="w-3.5 h-3.5" /> Add Files
                      </button>
                      <button
                        onClick={handleBrowseFolders}
                        className="flex items-center gap-2 text-xs bg-av-surface border border-av-border text-av-main font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:border-av-border active:scale-95"
                      >
                        <Folder className="w-3.5 h-3.5 text-av-muted" /> Add Folders
                      </button>
                    </div>
                  </motion.div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col relative overflow-hidden">
                {/* Toolbar */}
                <div className="av-explorer-toolbar px-6 py-4 flex items-center justify-between shrink-0">
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-sm font-medium text-av-main">Explorer</span>
                    <span className="bg-av-border/15 border border-av-main/20 text-av-main text-[11px] font-semibold px-2.5 py-0.5 rounded-md">{files.length}</span>
                  </div>
                  <div className="flex-1 max-w-[200px] mx-4">
                    <div className="relative group">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-av-muted group-focus-within:text-av-main transition-colors" />
                      <input
                        type="text"
                        placeholder="Filter..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 bg-av-surface border border-av-border rounded-lg text-xs focus:outline-none focus:border-av-border focus:ring-1 focus:ring-av-border/20 transition-all text-av-main"
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={handleBrowseFiles} className="flex items-center gap-1.5 text-[11px] bg-av-surface border border-av-border text-av-muted hover:text-av-main hover:border-av-border font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                      <File className="w-3 h-3" /> Files
                    </button>
                    <button onClick={handleBrowseFolders} className="flex items-center gap-1.5 text-[11px] bg-av-surface border border-av-border text-av-muted hover:text-av-main hover:border-av-border font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                      <Folder className="w-3 h-3 text-av-muted" /> Folders
                    </button>
                  </div>
                </div>

                {/* Tree View */}
                <div className="flex-1 overflow-hidden">
                  <FileTree
                    nodes={treeNodes}
                    searchQuery={searchQuery}
                    selectedPaths={selectedTreePaths}
                    onSelectionChange={handleTreeSelectionChange}
                    onRemovePaths={handleRemoveTreePaths}
                    onClearAll={handleClearAllStagedInputs}
                  />
                </div>
              </div>
            )
          )}
        </div>
      </div>

      {/* â”€â”€ Right Panel: Security Protocol (40%) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
      <div className={`av-side-stack av-natural-side-stack lg:col-span-2 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>

        <div className="px-2 mb-1">
          <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Time-Lock Settings</h3>
        </div>

        <div className="rounded-[20px] border border-av-border/30 bg-av-surface/40 overflow-hidden shadow-sm">
          <button
            type="button"
            onClick={() => isAavritAvailable && setAuthorityExpanded(value => !value)}
            className={`flex w-full items-start justify-between gap-4 p-5 text-left transition-colors ${
              isAavritAvailable ? 'hover:bg-av-border/5' : 'cursor-default'
            }`}
          >
            <div className="min-w-0">
              <div className="flex items-center gap-3">
                <h3 className="font-semibold text-av-main text-sm">Release Method</h3>
                <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
                  timecapsuleProvider === 'drand'
                    ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                    : 'border-blue-500/20 bg-blue-500/10 text-blue-400'
                }`}>
                  {providerModeLabel}
                </span>
              </div>
              <p className="mt-1 text-xs text-av-muted">{timecapsuleProvider === 'drand' ? 'drand public time release' : 'Aavrit server release'}</p>
            </div>
            {isAavritAvailable && (
              <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-av-muted transition-transform ${authorityExpanded ? 'rotate-180' : ''}`} />
            )}
          </button>

          {isAavritAvailable && authorityExpanded && (
            <div className="border-t border-av-border/30 px-5 pb-5 pt-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                  <button
                    type="button"
                    onClick={() => { setTimecapsuleProvider('drand'); setTimecapsuleProviderOverridden(true) }}
                    className={`rounded-2xl border p-4 text-left transition-all ${
                      timecapsuleProvider === 'drand'
                        ? 'border-emerald-500 bg-emerald-500/10 shadow-sm ring-1 ring-emerald-500/10'
                        : 'border-av-border hover:border-emerald-500/30 hover:bg-av-border/5'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h4 className="text-sm font-semibold text-av-main">drand</h4>
                        <p className="mt-1 text-[11px] text-av-muted">Public beacon</p>
                      </div>
                      <CheckCircle2 className={`h-4 w-4 ${timecapsuleProvider === 'drand' ? 'text-emerald-400' : 'text-transparent'}`} />
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => { setTimecapsuleProvider('aavrit'); setTimecapsuleProviderOverridden(true) }}
                    className={`rounded-2xl border p-4 text-left transition-all ${
                      timecapsuleProvider === 'aavrit'
                        ? 'border-blue-500 bg-blue-500/10 shadow-sm ring-1 ring-blue-500/10'
                        : 'border-av-border hover:border-blue-500/30 hover:bg-av-border/5'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <h4 className="text-sm font-semibold text-av-main">Aavrit</h4>
                        <p className="mt-1 text-[11px] text-av-muted">{aavritMode === 'private' ? 'Private authority' : 'Hybrid-PQC release'}</p>
                      </div>
                      <CheckCircle2 className={`h-4 w-4 ${timecapsuleProvider === 'aavrit' ? 'text-blue-400' : 'text-transparent'}`} />
                    </div>
                  </button>
              </div>
            </div>
          )}

          {showCreationReport && creationReport && <ArchiveReportModal report={creationReport} title="Time-Capsule creation report" onClose={() => { setShowCreationReport(false); setCreationReport(null) }} />}
        </div>

        {/* Accordion 1: Date & Time */}
        <div
          onClick={() => setActivePanel(activePanel === 'datetime' ? null : 'datetime')}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${
            activePanel === 'datetime'
              ? 'bg-av-surface/80 border-blue-500 shadow-[0_8px_30px_rgba(59,130,246,0.08)] ring-1 ring-blue-500/20'
              : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
          }`}
        >
          <div className="p-5 flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-colors ${
                activePanel === 'datetime' ? 'bg-blue-500/15 border-blue-500/30' : 'bg-av-border/10 border-av-border/50'
              }`}>
                <Calendar className={`w-5 h-5 ${activePanel === 'datetime' ? 'text-blue-400' : 'text-av-muted'}`} />
              </div>
              <div>
                <h3 className="font-semibold text-av-main text-sm">Unlock Date & Time</h3>
                <p className="text-av-muted text-xs mt-0.5">
                  {(unlockDate && unlockTime) ? `${displayLocal(unlockDate, unlockTime)} ${currentTimeZoneLabel}` : `Set the future unlock date (${currentTimeZoneLabel})`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {/* NTP sync badge */}
              {ntpSynced !== null && (
                <div className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-[10px] font-medium border ${
                  ntpSynced ? 'bg-green-500/10 text-green-500 border-green-500/20' : 'bg-orange-500/10 text-orange-500 border-orange-500/20'
                }`}>
                  {ntpSynced ? <Wifi className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  {ntpSynced ? 'Trusted' : 'Unsynced'}
                </div>
              )}
              <ChevronDown className={`w-4 h-4 text-av-muted transition-transform ${activePanel === 'datetime' ? 'rotate-180' : ''}`} />
            </div>
          </div>

          {(activePanel === 'datetime') && (
            <div className="px-5 pb-5 space-y-4" onClick={e => e.stopPropagation()}>
              <div className="h-px bg-av-border/50" />

              {/* Current NTP time display */}
              {ntpTime && (
                <div className="flex items-center gap-2 p-3 rounded-xl bg-av-border/5 border border-av-border/50">
                  <Clock className="w-4 h-4 text-av-muted shrink-0" />
                  <div>
                    <p className="text-[10px] font-bold text-av-muted uppercase tracking-wider">Current Trusted Time ({currentTimeZoneLabel})</p>
                    <p className="text-sm font-semibold text-av-main">
                      {ntpTime.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })}
                    </p>
                  </div>
                  <div className={`ml-auto w-2 h-2 rounded-full ${ntpSynced ? 'bg-green-400 animate-pulse' : 'bg-orange-400'}`} />
                </div>
              )}

              <div>
                <label className="block text-xs font-semibold text-av-muted mb-2 uppercase tracking-wider">
                  Select Unlock Date & Time ({currentTimeZoneLabel})
                </label>
                <div className="flex flex-col sm:flex-row gap-3">
                  <div className="flex-1 relative">
                    <input
                      type="date"
                      value={unlockDate}
                      min={minDateStr}
                      onChange={e => setUnlockDate(e.target.value)}
                      className="timecapsule-picker-input w-full px-4 pr-12 py-3 rounded-xl bg-av-surface border border-av-border text-av-main text-sm focus:outline-none focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/10 transition-all cursor-pointer"
                    />
                    <Calendar className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-av-muted" />
                  </div>
                  <div className="flex-1 relative">
                    <input
                      type="time"
                      value={unlockTime}
                      min={isSelectedDateMin ? minTimeStr : undefined}
                      onChange={e => setUnlockTime(e.target.value)}
                      className="timecapsule-picker-input w-full px-4 pr-12 py-3 rounded-xl bg-av-surface border border-av-border text-av-main text-sm focus:outline-none focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/10 transition-all cursor-pointer"
                    />
                    <Clock className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-av-muted" />
                  </div>
                </div>
                <p className="text-[10px] text-av-muted mt-2">
                  All times are interpreted in your current local timezone ({currentTimeZoneLabel}) and stored internally in UTC.
                  {ntpSynced
                    ? ' Trusted time is synced.'
                    : ' Trusted time is unavailable right now, so final validation will happen when you create the time-capsule.'}
                </p>
              </div>
            </div>
          )}
        </div>

        {/* â”€â”€ Accordion 2: Password â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <div className="rounded-[18px] border border-av-border/30 bg-av-surface/35 px-4 py-3 text-[12px] leading-relaxed text-av-muted">
          Unlock date and time are always required. Password and keyphrase stay optional unless you turn them on for an extra protection layer after release.
        </div>

        <div
          onClick={togglePasswordProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${
            passwordEnabled
              ? 'bg-av-surface/80 border-emerald-500 shadow-[0_8px_30px_rgba(16,185,129,0.08)] ring-1 ring-emerald-500/20'
              : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
          }`}
        >
          {passwordEnabled && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-emerald-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 flex items-center justify-between border-b border-transparent relative z-10">
            <div className="flex items-center gap-4">
              <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-colors duration-300 ${passwordEnabled ? 'bg-emerald-500/10 border-emerald-500/30 shadow-inner' : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'}`}>
                <Lock className={`w-[18px] h-[18px] ${passwordEnabled ? 'text-emerald-500' : 'text-av-muted'}`} strokeWidth={1.5} />
              </div>
              <div>
                <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Optional Access Password</h3>
                <p className="text-av-muted text-[13px] font-light">Add a strong password required after release</p>
              </div>
            </div>
            <div className="flex items-center gap-2 pr-1" onClick={e => e.stopPropagation()}>
              <button
                onClick={togglePasswordProtection}
                className={`relative w-11 h-6 rounded-full transition-all duration-300 border shadow-inner ${passwordEnabled ? 'bg-emerald-500 border-emerald-500 shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]' : 'bg-av-border/20 dark:bg-white/10 border-av-border/30 dark:border-white/10'}`}
              >
                <span className={`absolute top-[1px] left-[1px] w-5 h-5 rounded-full bg-white shadow-[0_2px_5px_rgba(0,0,0,0.2)] transition-transform duration-300 ${passwordEnabled ? 'translate-x-[20px]' : ''}`} />
              </button>
            </div>
          </div>

          {passwordEnabled && (
            <div className="px-5 pb-5 space-y-5 pt-1 relative z-10" onClick={e => e.stopPropagation()}>
              <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 group/input">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                   <Fingerprint className={`w-4 h-4 transition-colors duration-300 ${(password.length > 0) ? 'text-emerald-400 opacity-100' : 'text-av-muted opacity-50 group-hover/input:opacity-100 group-hover/input:text-emerald-400'}`} />
                </div>
                <input
                  type={showPassword ? 'text' : 'password'}
                  placeholder="Enter a strong password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  className="w-full pl-10 pr-11 py-3.5 rounded-xl bg-transparent text-av-main text-sm focus:outline-none focus:ring-1 transition-all font-medium placeholder:font-light focus:ring-emerald-500/50"
                />
                <button onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-av-muted hover:text-av-main dark:hover:text-white transition-colors p-1.5 rounded-lg hover:bg-av-border/10 dark:hover:bg-white/10">
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              <PasswordStrengthMeter password={password} />

            </div>
          )}
        </div>

        {/* â”€â”€ Accordion 3: Keyphrase â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <div
          onClick={toggleKeyphraseProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${
            keyphraseEnabled
              ? 'bg-av-surface/80 border-purple-500 shadow-[0_8px_30px_rgba(168,85,247,0.08)] ring-1 ring-purple-500/20'
              : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
          }`}
        >
          {keyphraseEnabled && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-purple-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 flex items-center justify-between relative z-10">
            <div className="flex items-center gap-4">
               <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-colors duration-300 ${keyphraseEnabled ? 'bg-purple-500/10 border-purple-500/30' : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'}`}>
                 <Key className={`w-[18px] h-[18px] ${keyphraseEnabled ? 'text-purple-500' : 'text-av-muted'}`} strokeWidth={1.5} />
               </div>
               <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Optional Security Keyphrase</h3>
                  <p className="text-av-muted text-[13px] font-light">Add a 21-word recovery phrase required after release</p>
               </div>
            </div>
            <div className="flex items-center gap-2 pr-1" onClick={e => e.stopPropagation()}>
               <button
                  onClick={toggleKeyphraseProtection}
                  className={`relative w-11 h-6 rounded-full transition-all duration-300 border shadow-inner ${keyphraseEnabled ? 'bg-purple-500 border-purple-500 shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]' : 'bg-av-border/20 dark:bg-white/10 border-av-border/30 dark:border-white/10'}`}
               >
                  <span className={`absolute top-[1px] left-[1px] w-5 h-5 rounded-full bg-white shadow-[0_2px_5px_rgba(0,0,0,0.2)] transition-transform duration-300 ${keyphraseEnabled ? 'translate-x-[20px]' : ''}`} />
               </button>
            </div>
          </div>

          {keyphraseEnabled && (
             <div className="px-5 pb-5 space-y-4 pt-1 relative z-10" onClick={e => e.stopPropagation()}>
               {!keyphrase ? (
                 <button onClick={handleGenerateKeyphrase} className="keyphrase-generate-button w-full py-3.5 rounded-xl border text-[13px] font-semibold transition-all duration-300 flex items-center justify-center gap-2.5">
                    <RefreshCw className="w-4 h-4" /> Generate Recovery Keyphrase
                 </button>
               ) : (
                 <div className="security-keyphrase-card rounded-2xl p-4">
                   <div className="security-keyphrase-header mb-3 flex items-center justify-between pb-3 text-[10px] font-bold uppercase tracking-[0.16em]">
                      <span>Recovery Keyphrase</span>
                      <span className="security-keyphrase-badge rounded-full px-2 py-0.5">21 Words</span>
                   </div>
                   <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                     {keyphraseWords.map((word, idx) => (
                       <div key={idx} className="security-keyphrase-chip flex min-w-0 overflow-hidden rounded-lg transition-colors">
                          <span className="security-keyphrase-index flex w-7 shrink-0 items-center justify-center py-1 text-[9px] font-bold tracking-wider tabular-nums">{(idx + 1).toString().padStart(2, '0')}</span>
                          <span className="min-w-0 flex-1 truncate px-2 py-1 text-[11px] font-semibold">{word}</span>
                       </div>
                     ))}
                   </div>
                   <div className="security-keyphrase-actions mt-4 flex flex-col gap-2 pt-4 sm:flex-row sm:items-center sm:gap-3">
                      <button onClick={handleCopyKeyphrase} className="security-keyphrase-copy flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-colors duration-300">
                        {isCopied ? <><CheckCircle2 className="w-4 h-4 text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]"/> Copied</> : <><Copy className="w-4 h-4"/> Copy</>}
                      </button>
                      <button onClick={handleDownloadKeyphrase} className="security-keyphrase-secondary flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-colors duration-300">
                        <DownloadCloud className="w-4 h-4" /> Download
                      </button>
                      <button onClick={handleGenerateKeyphrase} className="security-keyphrase-secondary rounded-lg px-4 py-2 text-xs font-semibold transition-colors duration-300">
                        Regenerate
                      </button>
                   </div>
                 </div>
               )}
             </div>
          )}
        </div>

        {/* â”€â”€ Lock button â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <div
          onClick={togglePqcProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${
            pqcEnabled
              ? 'bg-av-surface/80 border-amber-500 shadow-[0_8px_30px_rgba(245,158,11,0.12)] ring-1 ring-amber-500/20'
              : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
          }`}
        >
          {pqcEnabled && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-amber-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 flex items-center justify-between relative z-10">
            <div className="flex items-center gap-4">
              <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-colors duration-300 ${
                pqcEnabled ? 'bg-amber-500/10 border-amber-500/30 shadow-inner' : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'
              }`}>
                <Fingerprint className={`w-[18px] h-[18px] ${pqcEnabled ? 'text-amber-500' : 'text-av-muted'}`} strokeWidth={1.5} />
              </div>
              <div>
                <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Quantum Protection</h3>
                <p className="text-av-muted text-[13px] font-light">{pqcSuiteLabel(pqcSuiteId)} Â· {pqcStorageMode === 'embedded' ? 'Embedded bundle' : 'External .avkkey'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2 pr-1" onClick={e => e.stopPropagation()}>
              <button
                onClick={togglePqcProtection}
                className={`relative w-11 h-6 rounded-full transition-all duration-300 border shadow-inner ${pqcEnabled ? 'bg-amber-500 border-amber-500 shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]' : 'bg-av-border/20 dark:bg-white/10 border-av-border/30 dark:border-white/10'}`}
              >
                <span className={`absolute top-[1px] left-[1px] w-5 h-5 rounded-full bg-white shadow-[0_2px_5px_rgba(0,0,0,0.2)] transition-transform duration-300 ${pqcEnabled ? 'translate-x-[20px]' : ''}`} />
              </button>
            </div>
          </div>

          {pqcEnabled && (
            <div className="px-5 pb-5 space-y-3 pt-1 relative z-10" onClick={e => e.stopPropagation()}>
              <PqcSuiteSelector
                suiteId={pqcSuiteId}
                customKem={pqcCustomKem}
                customSignature={pqcCustomSignature}
                customSlhSignature={pqcCustomSlhSignature}
                onSuiteChange={setPqcSuiteId}
                onCustomKemChange={setPqcCustomKem}
                onCustomSignatureChange={setPqcCustomSignature}
                onCustomSlhSignatureChange={setPqcCustomSlhSignature}
              />
                <div className="grid grid-cols-2 gap-3">
                  <button
                  onClick={() => { setPqcStorageMode('embedded'); setPqcModeOverridden(true); setPqcKeyfilePath(''); setPqcKeyfilePasswordEnabled(false); setPqcKeyfilePassword('') }}
                  className={`rounded-2xl border px-4 py-4 text-left transition-all ${
                    pqcStorageMode === 'embedded'
                      ? 'border-emerald-500/35 bg-emerald-500/10 shadow-sm'
                      : 'border-av-border/40 bg-av-surface/60 hover:border-av-border/70'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-av-main">Embedded in .avk</p>
                      <p className="mt-1 text-[11px] text-av-muted">Single capsule file</p>
                    </div>
                    {pqcStorageMode === 'embedded' && <span className="rounded-full border border-emerald-500/25 bg-emerald-500/10 px-2 py-0.5 text-[10px] font-semibold text-emerald-600 dark:text-emerald-300">Selected</span>}
                  </div>
                </button>
                <button
                  onClick={() => { setPqcStorageMode('external'); setPqcModeOverridden(true); setPqcKeyfilePath('') }}
                  className={`rounded-2xl border px-4 py-4 text-left transition-all ${
                    pqcStorageMode === 'external'
                      ? 'border-amber-500/35 bg-amber-500/10 shadow-sm'
                      : 'border-av-border/40 bg-av-surface/60 hover:border-av-border/70'
                  }`}
                >
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <p className="text-sm font-semibold text-av-main">Separate .avkkey</p>
                      <p className="mt-1 text-[11px] text-av-muted">Split key material</p>
                    </div>
                    {pqcStorageMode === 'external' && <span className="rounded-full border border-amber-500/25 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">Selected</span>}
                  </div>
                </button>
              </div>
              {pqcStorageMode === 'external' && (
                <div className="rounded-xl border border-av-border/35 bg-av-surface/60 p-3">
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="text-xs font-semibold text-av-main">Add .avkkey password</p>
                      <p className="mt-0.5 text-[11px] text-av-muted">Optional second unlock layer</p>
                    </div>
                    <button
                      onClick={() => {
                        setPqcKeyfilePasswordEnabled(value => {
                          const next = !value
                          if (!next) {
                            setPqcKeyfilePassword('')
                            setShowPqcKeyfilePassword(false)
                          }
                          return next
                        })
                      }}
                      className={`relative h-6 w-11 rounded-full border transition-all ${pqcKeyfilePasswordEnabled ? 'border-amber-500 bg-amber-500' : 'border-av-border/40 bg-av-border/20 dark:bg-white/10'}`}
                    >
                      <span className={`absolute left-[1px] top-[1px] h-5 w-5 rounded-full bg-white shadow transition-transform ${pqcKeyfilePasswordEnabled ? 'translate-x-5' : ''}`} />
                    </button>
                  </div>
                  {pqcKeyfilePasswordEnabled && (
                    <div className="mt-3 space-y-2">
                      <div className="flex items-center gap-2 rounded-xl border border-av-border/35 bg-av-border/10 px-3 py-2">
                        <input
                          type={showPqcKeyfilePassword ? 'text' : 'password'}
                          value={pqcKeyfilePassword}
                          onChange={(event) => setPqcKeyfilePassword(event.target.value)}
                          placeholder=".avkkey password"
                          className="min-w-0 flex-1 bg-transparent text-sm text-av-main outline-none placeholder:text-av-muted"
                        />
                        <button
                          type="button"
                          onClick={() => setShowPqcKeyfilePassword(value => !value)}
                          className="text-av-muted transition hover:text-av-main"
                        >
                          {showPqcKeyfilePassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                      <PasswordStrengthMeter
                        password={pqcKeyfilePassword}
                        title=".avkkey Password Strength"
                        compact
                        invalidMessage={pqcKeyfilePasswordIssue}
                      />
                    </div>
                  )}
                  {!pqcKeyfilePasswordEnabled && (
                    <p className="mt-2 text-[11px] text-av-muted">`.avkkey` location is chosen when creation starts.</p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="shrink-0 flex flex-col gap-3 pt-2">
          <div className="rounded-2xl border border-av-border/40 bg-av-surface/65 p-4"><div className="flex items-center justify-between gap-4"><div className="flex items-center gap-3"><MessageSquare className="h-4 w-4 text-av-muted" /><div><p className="text-sm font-semibold text-av-main">Sender message</p><p className="text-[11px] text-av-muted">Released with the authenticated keychain</p></div></div><button type="button" onClick={() => { setSenderMessageEnabled(value => !value); if (senderMessageEnabled) setSenderMessage('') }} className={`relative h-6 w-11 rounded-full border ${senderMessageEnabled ? 'border-av-accent bg-av-accent' : 'border-av-border/50 bg-av-border/20'}`}><span className={`absolute left-[1px] top-[1px] h-5 w-5 rounded-full bg-white shadow transition-transform ${senderMessageEnabled ? 'translate-x-5' : ''}`} /></button></div>{senderMessageEnabled && <div className="mt-3"><textarea value={senderMessage} onChange={event => setSenderMessage(event.target.value)} rows={3} maxLength={1024} className="w-full resize-none rounded-xl border border-av-border/40 bg-av-border/10 px-3 py-2 text-sm text-av-main outline-none focus:border-av-accent" placeholder="Add recovery context for the recipient..." /><div className="mt-1 flex justify-between text-[10px] text-av-muted"><span>{senderMessage.trim().split(/\s+/).filter(Boolean).length}/100 words</span><span>{new TextEncoder().encode(senderMessage).length}/1024 bytes</span></div></div>}{creatorIdentities.length > 0 && <label className="mt-3 block text-[11px] font-medium text-av-muted">Creator signature identity<select value={creatorIdentityId} onChange={event => setCreatorIdentityId(event.target.value)} className="mt-1 w-full rounded-xl border border-av-border/40 bg-av-surface px-3 py-2 text-sm text-av-main"><option value="">Per-archive identity</option>{creatorIdentities.map(identity => <option key={identity.identity_id} value={identity.identity_id}>{identity.label}</option>)}</select></label>}</div>
          {showInlineProgressCard && progress.status !== 'idle' && !loading && !isEncrypted && (
            <ProgressCard
              status={progress.status === 'running' ? 'Creatingâ€¦' : progress.status === 'completed' ? 'Completed' : progress.status === 'error' ? 'Error' : progress.status === 'cancelled' ? 'Cancelled' : 'Preparingâ€¦'}
              percentage={progress.percentage}
              currentOperation={progress.currentOperation || 'Executingâ€¦'}
              fileSize={progress.fileSize}
              compressionRatio={progress.compressionRatio}
              onCancel={progress.cancel}
              isCancelling={progress.isCancelling}
              elapsedSeconds={progress.elapsedSeconds}
              etaSeconds={progress.etaSeconds}
            />
          )}

          {isBoth && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-4 rounded-[16px] bg-red-500/10 border border-red-500/30 flex items-start gap-3 shadow-inner">
              <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
              <div>
                <p className="text-[13px] font-bold text-red-500 uppercase tracking-wide mb-1 drop-shadow-[0_0_8px_rgba(239,68,68,0.3)]">
                  {isTrioProtection ? 'Trio High Protection Enabled' : 'Dual High Protection Enabled'}
                </p>
                <p className="text-xs text-red-400/90 font-medium leading-relaxed">
                  {isTrioProtection
                    ? 'This capsule will require release time, password, 21-word keyphrase, and PQC material. Store every required secret carefully before you continue.'
                    : 'This capsule will require both the access password and the 21-word keyphrase after release. Keep both stored safely before you continue.'}
                </p>
              </div>
            </motion.div>
          )}

          <BackendStartupNotice backend={backendRuntime} compact />

          <button
            onClick={handleEncode}
            disabled={!canAttemptCreateTimeCapsule}
            className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${
              !canAttemptCreateTimeCapsule
                ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner'
                : 'bg-av-main hover:opacity-90 text-av-surface shadow-[0_10px_30px_rgba(0,0,0,0.15)] hover:shadow-[0_10px_40px_rgba(0,0,0,0.2)] hover:-translate-y-0.5'
            }`}
          >
            {loading ? (
              <><RefreshCw className="w-5 h-5 animate-spin" /> Creating Secure Archive...</>
            ) : !backendRuntime.isReady ? (
              <><Shield className="w-5 h-5" /> Starting Secure Engine...</>
            ) : (
              <><Shield className="w-5 h-5" /> Create Time-Capsule</>
            )}
          </button>

          <p className="text-center text-[11px] text-av-muted mt-1 font-light">
            {!backendRuntime.isReady
              ? backendRuntime.detail
              : (!unlockDate || !unlockTime)
              ? 'Set an unlock date and time to continue.'
              : !isUnlockReady
              ? 'Choose a future unlock date and time.'
              : usePass && !isPasswordReady
              ? 'Use a strong password with 12+ characters, uppercase, lowercase, number, and symbol.'
              : useKeyp && !isKeyphraseReady
              ? 'Generate or enter the full 21-word keyphrase.'
              : pqcEnabled && !hasProtection
              ? 'Quantum keyfile mode requires a password or keyphrase.'
              : timecapsuleProvider === 'aavrit' && (!aavritServerUrl || (aavritMode === 'private' && !sessionToken))
              ? 'Aavrit requires a connected server, and private mode also requires an active login.'
              : !hasProtection
              ? timecapsuleProvider === 'aavrit'
                ? 'Aavrit will verify a capability-bound, triple-signed release before decryption.'
                : 'drand release will unlock the archive once the public round is available.'
              : usePass && useKeyp
              ? 'Password and keyphrase will both be required after release.'
              : usePass
              ? 'Password protection is enabled.'
              : 'Keyphrase protection is enabled.'}
          </p>
        </div>
      </div>
      </div>
    </div>
  )
}


