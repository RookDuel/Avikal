import { useState, useCallback, useEffect, useRef } from 'react'
import { useAuth } from '../contexts/AuthContext'
import { motion } from 'framer-motion'
import {
  Lock, Key, Upload, Shield, RefreshCw, CheckCircle2,
  ChevronDown, Search, Eye, EyeOff, CheckCircle, ExternalLink,
  DownloadCloud, Copy, Calendar, Clock, Wifi, WifiOff, File, Folder, Fingerprint
} from 'lucide-react'
import { toast } from 'sonner'
import { api } from '../lib/api'
import { fetchBackend } from '../lib/backend'
import { waitForBackendReady } from '../lib/backendStatus'
import { formatEta, parseBackendProgressChunk } from '../lib/backendProgress'
import { getErrorMessage } from '../lib/errors'
import { getDroppedPaths } from '../lib/electron'
import { useProgress } from '../hooks/useProgress'
import ProgressCard from '../components/ProgressCard'
import FileTree, { type FileNode } from '../components/FileTree'
import type { PendingExternalLaunchAction } from '../lib/externalLaunch'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'

// ─── Types ────────────────────────────────────────────────────────────────────
type PanelType = 'datetime' | 'password' | 'keyphrase' | 'pqc' | null

function deriveSiblingKeyfilePath(archivePath: string): string {
  return archivePath.replace(/(\.avk)?$/i, '.avkkey')
}

function deriveDefaultKeyfileName(files: string[]): string {
  const first = files[0]?.split(/[/\\]/).pop() || 'timecapsule'
  const base = first.replace(/\.[^.]+$/, '')
  return `${base || 'timecapsule'}.avkkey`
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

// ─── NTP fetch ────────────────────────────────────────────────────────────────
async function fetchNTPTime(): Promise<Date> {
  // We use a lightweight public HTTP endpoint that returns the server time in headers.
  // time.google.com is a pure NTP server (UDP), not HTTP — so we use the backend NTP endpoint
  // which already calls time.google.com, or fall back to a public HTTP time API.
  try {
    await waitForBackendReady()
    const res = await fetchBackend('/api/ntp-time', { method: 'GET' })
    if (res.ok) {
      const data = await res.json()
      if (data.timestamp) return new Date(data.timestamp * 1000)
    }
  } catch {
    // backend unavailable — try world time API
  }
  throw new Error('Trusted time is currently unavailable')
}

// ─── Password strength ────────────────────────────────────────────────────────
function getStrength(pass: string): number {
  if (!pass) return 0
  let s = 0
  if (pass.length > 8)  s += 25
  if (pass.length > 11) s += 25
  if (/[A-Z]/.test(pass)) s += 15
  if (/[0-9]/.test(pass)) s += 15
  if (/[^A-Za-z0-9]/.test(pass)) s += 20
  return Math.min(100, s)
}

// ─── Component ────────────────────────────────────────────────────────────────
interface TimeCapsuleProps {
  externalLaunchAction?: PendingExternalLaunchAction | null
}

export default function TimeCapsule({ externalLaunchAction }: TimeCapsuleProps) {
  const { sessionToken, refreshUserProfile, aavritMode, aavritServerUrl } = useAuth()
  const [timecapsuleProvider, setTimecapsuleProvider] = useState<'drand' | 'aavrit'>('drand')
  const [authorityExpanded, setAuthorityExpanded] = useState(false)
  const [files, setFiles]               = useState<string[]>([])
  const [treeNodes, setTreeNodes]       = useState<FileNode[]>([])
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
  const [isCopied, setIsCopied]         = useState(false)
  const [pqcEnabled, setPqcEnabled]     = useState(false)
  const [pqcKeyfilePath, setPqcKeyfilePath] = useState('')
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

  const resetTimecapsulePanel = useCallback(() => {
    setAuthorityExpanded(false)
    setTimecapsuleProvider('drand')
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
    setPqcKeyfilePath('')
  }, [])

  useEffect(() => {
    filesRef.current = files
  }, [files])

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
  const strength = getStrength(password)
  const strengthColor = strength < 40 ? 'bg-red-400' : strength < 80 ? 'bg-amber-400' : 'bg-emerald-400'
  const strengthLabel = strength < 40 ? 'WEAK' : strength < 80 ? 'MODERATE' : 'OPTIMAL'
  const strengthLabelColor = strength < 40 ? 'text-red-400' : strength < 80 ? 'text-amber-400' : 'text-emerald-400'

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
    if (newPaths.length > 0) {
      setFiles(prev => [...prev, ...newPaths])
      newPaths.forEach(p => {
        void scanAndAddPath(p)
      })
    }
  }, [files])

  const handleBrowseFiles = async () => {
    try {
      const electron = window.electron
      const selected = await electron?.openFile({ properties: ['openFile', 'multiSelections'] }) as string[] | undefined
      if (selected?.length) {
        const newPaths = selected.filter(f => !files.includes(f))
        if (selected.length - newPaths.length > 0) toast.error(`${selected.length - newPaths.length} duplicate(s) skipped`)
        if (newPaths.length > 0) {
          setFiles(prev => [...prev, ...newPaths])
          newPaths.forEach(p => {
            void scanAndAddPath(p)
          })
        }
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
        if (newPaths.length > 0) {
          setFiles(prev => [...prev, ...newPaths])
          newPaths.forEach(p => {
            void scanAndAddPath(p)
          })
        }
      }
    } catch (error) { console.error(error) }
  }

  const handleRemoveRoot = (rootPath: string) => {
    setFiles(prev => prev.filter(f => f !== rootPath))
    setTreeNodes(prev => prev.filter(n => n.path !== rootPath))
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

  const handleCopyKeyphrase = () => {
    if (!keyphrase) return
    navigator.clipboard.writeText(keyphrase)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 2000)
  }

  const handleChoosePqcKeyfile = async () => {
    const electron = window.electron
    const selected = await electron?.saveFile({
      defaultPath: pqcKeyfilePath || deriveDefaultKeyfileName(files),
      filters: [{ name: 'RookDuel Avikal PQC Keyfile', extensions: ['avkkey'] }]
    })
    if (selected) setPqcKeyfilePath(selected)
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
      if (pqcEnabled) {
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
        output_file: outputFile,
        password: password || undefined,
        keyphrase: keyphrase ? keyphrase.split(' ') : undefined,
        unlock_datetime: unlockIso,
        use_timecapsule: true,
        timecapsule_provider: timecapsuleProvider,
        pqc_enabled: pqcEnabled,
        pqc_keyfile_output: pqcEnabled ? nextPqcKeyfilePath : undefined,
      }, timecapsuleProvider === 'aavrit' ? (sessionToken || '') : undefined)
      
      if (!result.success) throw new Error(result.message || 'Time-Capsule creation failed')

      setCreatedPqcKeyfilePath(result?.result?.pqc?.keyfile || nextPqcKeyfilePath || '')
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
          ? 'Time-Capsule and PQC keyfile created successfully!'
          : timecapsuleProvider === 'drand'
          ? 'drand Time-Capsule created successfully!'
          : 'Aavrit Time-Capsule created successfully!'
      )
      setPassword('')
      setKeyphrase('')
      setActivePanel('datetime')
    } catch (error: unknown) {
      progress.update({
        status: 'error',
        currentOperation: 'Time-Capsule creation failed',
        percentage: progress.percentage || 0,
      })
      toast.error(getErrorMessage(error, 'Time-Capsule creation failed'))
    } finally {
      setLoading(false)
    }
  }

  const usePass = passwordEnabled
  const useKeyp = keyphraseEnabled
  const hasProtection = usePass || useKeyp
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
  const isProviderReady = timecapsuleProvider !== 'aavrit' || !!aavritServerUrl && (aavritMode !== 'private' || !!sessionToken)
  const isPqcReady = !pqcEnabled || hasProtection
  const showInlineProgressCard = false
  const canAttemptCreateTimeCapsule = backendRuntime.isReady && !loading && isFilesReady && unlockMs !== null
  const providerModeLabel = timecapsuleProvider === 'drand'
    ? 'No Login'
    : aavritMode === 'private'
      ? 'Private'
      : 'Public'
  const providerSummaryText = timecapsuleProvider === 'drand'
    ? 'Public quicknet unlock with no account requirement.'
    : !aavritServerUrl
      ? 'Connect an Aavrit server to enable signed commit/reveal release.'
      : aavritMode === 'private'
        ? 'Private Aavrit server with authenticated release flow.'
        : 'Public Aavrit server with signed reveal verification.'

  return (
    <div className="min-h-full w-full max-w-[1600px] mx-auto p-6 lg:p-10 box-border">

      {/* 60/40 Split Architecture */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">

      {/* ── Left Panel: File Staging (60%) ───────────────────────── */}
      <div className="lg:col-span-3 min-h-[550px] bg-av-surface/60 backdrop-blur-3xl rounded-[24px] shadow-[0_8px_40px_rgba(0,0,0,0.06)] border border-av-border/30 flex flex-col overflow-hidden relative transition-colors duration-300">
        <div className="px-8 py-7 border-b border-av-border/30 bg-gradient-to-b from-av-surface/80 to-av-surface/40 z-10 shrink-0">
          <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
            Time <span className="font-light text-av-muted">Capsule</span>
          </h2>
          <p className="text-av-muted text-sm font-light">Protect files until a future date with time-based sealing.</p>
        </div>

        <div
          className="flex-1 flex flex-col relative overflow-hidden bg-av-border/5"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
          {loading && !isEncrypted && (
            <div className="absolute inset-0 z-20 bg-av-surface/80 backdrop-blur-xl flex flex-col items-center justify-center p-8">
              <div className="w-full max-w-md rounded-3xl bg-av-surface/90 border border-av-border/40 p-8 shadow-[0_20px_60px_rgba(0,0,0,0.12)]">
                <div className="flex items-center gap-3 mb-5">
                  <div className="p-3 rounded-2xl bg-av-accent/10 border border-av-accent/30">
                    <RefreshCw className="w-6 h-6 text-av-accent" strokeWidth={1.5} />
                  </div>
                  <div>
                    <h3 className="text-xl font-medium tracking-tight text-av-main">Creating Time-Capsule</h3>
                    <p className="text-sm text-av-muted font-light">
                      {progress.currentOperation || 'Creating your secure time-locked archive.'}
                    </p>
                  </div>
                </div>
                <div className="flex items-center justify-between text-xs text-av-muted mb-2">
                  <span>{progress.percentage !== null ? `${Math.round(progress.percentage)}% complete` : 'Working...'}</span>
                  <span>{formatEta(progress.etaSeconds)}</span>
                </div>
                <div className="h-2.5 w-full bg-av-border/30 rounded-full overflow-hidden">
                  {progress.percentage !== null ? (
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${Math.max(0, Math.min(100, progress.percentage))}%` }}
                      className="h-full bg-av-accent rounded-full"
                      transition={{ duration: 0.35, ease: 'easeOut' }}
                    />
                  ) : (
                    <motion.div
                      className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-av-accent to-transparent"
                      animate={{ x: ['0%', '280%'] }}
                      transition={{ duration: 1.3, repeat: Infinity, ease: 'easeInOut' }}
                    />
                  )}
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-av-muted">
                  <span>{progress.elapsedSeconds}s elapsed</span>
                  {progress.fileSize !== null && (
                    <span>{(progress.fileSize / (1024 * 1024)).toFixed(progress.fileSize >= 1024 * 1024 * 1024 ? 1 : 2)} MB source</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Success state */}
          {isEncrypted && (
            <div className="flex-1 flex flex-col items-center justify-center p-8 bg-av-surface/40 backdrop-blur-sm z-20">
              <motion.div
                initial={{ scale: 0.9, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                className="w-full max-w-md p-8 rounded-3xl bg-av-surface border border-green-500/20 shadow-2xl flex flex-col items-center text-center relative overflow-hidden"
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

                <button
                  onClick={() => {
                    setIsEncrypted(false)
                    setFiles([])
                    setPqcEnabled(false)
                    setPqcKeyfilePath('')
                    setCreatedPqcKeyfilePath('')
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
                  className={`flex-1 rounded-2xl border-2 border-dashed flex flex-col items-center justify-center transition-all duration-300 relative overflow-hidden ${
                    isDragging
                      ? 'border-av-main bg-av-border/10'
                      : 'border-av-border bg-av-surface hover:border-av-accent/50 hover:bg-av-border/5 text-av-muted'
                  }`}
                >
                  <div className="absolute inset-0 bg-gradient-to-b from-transparent to-av-border/10 pointer-events-none" />
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
                        className="flex items-center gap-2 text-xs bg-av-surface border border-av-border text-av-main font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:border-av-accent/40 active:scale-95"
                      >
                        <Folder className="w-3.5 h-3.5 text-amber-400" /> Add Folders
                      </button>
                    </div>
                  </motion.div>
                </div>
              </div>
            ) : (
              <div className="flex-1 flex flex-col relative overflow-hidden">
                {/* Toolbar */}
                <div className="px-6 py-4 flex items-center justify-between border-b border-av-border bg-av-border/10 shrink-0">
                  <div className="flex items-center gap-3 shrink-0">
                    <span className="text-sm font-medium text-av-main">Explorer</span>
                    <span className="bg-av-main text-av-surface text-xs font-bold px-2.5 py-1 rounded-full">{files.length}</span>
                  </div>
                  <div className="flex-1 max-w-[200px] mx-4">
                    <div className="relative group">
                      <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-av-muted group-focus-within:text-av-accent transition-colors" />
                      <input
                        type="text"
                        placeholder="Filter..."
                        value={searchQuery}
                        onChange={e => setSearchQuery(e.target.value)}
                        className="w-full pl-8 pr-3 py-1.5 bg-av-surface border border-av-border rounded-lg text-xs focus:outline-none focus:border-av-accent/50 transition-all text-av-main"
                      />
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button onClick={handleBrowseFiles} className="flex items-center gap-1.5 text-[11px] bg-av-surface border border-av-border text-av-muted hover:text-av-main hover:border-av-accent/40 font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                      <File className="w-3 h-3" /> Files
                    </button>
                    <button onClick={handleBrowseFolders} className="flex items-center gap-1.5 text-[11px] bg-av-surface border border-av-border text-av-muted hover:text-av-main hover:border-av-accent/40 font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                      <Folder className="w-3 h-3 text-amber-400" /> Folders
                    </button>
                  </div>
                </div>

                {/* Tree View */}
                <div className="flex-1 overflow-hidden">
                  <FileTree
                    nodes={treeNodes}
                    searchQuery={searchQuery}
                    onRemoveRoot={handleRemoveRoot}
                  />
                </div>
              </div>
            )
          )}
        </div>
      </div>

      {/* ── Right Panel: Security Protocol (40%) ───────────────────── */}
      <div className={`lg:col-span-2 flex flex-col gap-5 pb-6 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>

        <div className="px-2 mb-1">
          <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Time-Lock Settings</h3>
        </div>

        <div className="rounded-[20px] border border-av-border/30 bg-av-surface/40 backdrop-blur-xl overflow-hidden shadow-sm">
          <button
            type="button"
            onClick={() => setAuthorityExpanded(value => !value)}
            className="flex w-full items-start justify-between gap-4 p-5 text-left transition-colors hover:bg-av-border/5"
          >
            <div className="min-w-0">
              <div className="flex items-center gap-3">
                <h3 className="font-semibold text-av-main text-sm">Unlock Authority</h3>
                <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold ${
                  timecapsuleProvider === 'drand'
                    ? 'border-emerald-500/20 bg-emerald-500/10 text-emerald-400'
                    : 'border-blue-500/20 bg-blue-500/10 text-blue-400'
                }`}>
                  {providerModeLabel}
                </span>
              </div>
              <p className="mt-1 text-xs text-av-muted">
                {timecapsuleProvider === 'drand' ? 'drand' : 'Aavrit'} selected. {providerSummaryText}
              </p>
            </div>
            <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-av-muted transition-transform ${authorityExpanded ? 'rotate-180' : ''}`} />
          </button>

          {authorityExpanded && (
            <div className="border-t border-av-border/30 px-5 pb-5 pt-4">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <button
                  type="button"
                  onClick={() => setTimecapsuleProvider('drand')}
                  className={`rounded-2xl border p-4 text-left transition-all ${
                    timecapsuleProvider === 'drand'
                      ? 'border-emerald-500 bg-emerald-500/10 shadow-sm ring-1 ring-emerald-500/10'
                      : 'border-av-border hover:border-emerald-500/30 hover:bg-av-border/5'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-emerald-500/20 bg-emerald-500/10">
                      <Shield className="h-5 w-5 text-emerald-400" />
                    </div>
                    <CheckCircle2 className={`h-4 w-4 ${timecapsuleProvider === 'drand' ? 'text-emerald-400' : 'text-transparent'}`} />
                  </div>
                  <h4 className="mt-3 text-sm font-semibold text-av-main">drand</h4>
                  <p className="mt-1 text-xs leading-relaxed text-av-muted">
                    Unlimited public capsules with decentralized unlock timing and no account requirement.
                  </p>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    setTimecapsuleProvider('aavrit')
                    if (!aavritServerUrl || (aavritMode === 'private' && !sessionToken)) {
                      toast.info('Connect your Aavrit server to use Aavrit release mode.')
                      promptAavritLogin()
                    }
                  }}
                  className={`rounded-2xl border p-4 text-left transition-all ${
                    timecapsuleProvider === 'aavrit'
                      ? 'border-blue-500 bg-blue-500/10 shadow-sm ring-1 ring-blue-500/10'
                      : 'border-av-border hover:border-blue-500/30 hover:bg-av-border/5'
                  }`}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-blue-500/20 bg-blue-500/10">
                      <Lock className="h-5 w-5 text-blue-400" />
                    </div>
                    <CheckCircle2 className={`h-4 w-4 ${timecapsuleProvider === 'aavrit' ? 'text-blue-400' : 'text-transparent'}`} />
                  </div>
                  <h4 className="mt-3 text-sm font-semibold text-av-main">Aavrit</h4>
                  <p className="mt-1 text-xs leading-relaxed text-av-muted">
                    Signed commit/reveal verification with public or Appwrite-protected private deployments.
                  </p>
                </button>
              </div>

              <div className={`mt-4 rounded-xl border p-3 text-xs leading-relaxed ${
                timecapsuleProvider === 'drand'
                  ? 'border-emerald-500/20 bg-emerald-500/5 text-emerald-700 dark:text-emerald-300'
                  : 'border-blue-500/20 bg-blue-500/5 text-blue-700 dark:text-blue-300'
              }`}>
                {timecapsuleProvider === 'drand'
                  ? 'drand stays self-contained in the archive and unlocks once the selected quicknet round becomes public.'
                  : !aavritServerUrl
                    ? 'Connect an Aavrit server before creating an Aavrit time-capsule.'
                    : aavritMode === 'private'
                      ? sessionToken
                        ? 'Private Aavrit is connected and ready.'
                        : 'Sign in to your Aavrit server before creating a private Aavrit time-capsule.'
                      : 'Public Aavrit is connected and ready.'}
              </div>

              {timecapsuleProvider === 'aavrit' && (!aavritServerUrl || (aavritMode === 'private' && !sessionToken)) && (
                <button
                  type="button"
                  onClick={promptAavritLogin}
                  className="mt-3 flex w-full items-center justify-center gap-2 rounded-xl bg-blue-500 py-3 text-sm font-semibold text-white transition-opacity hover:opacity-90"
                >
                  <ExternalLink className="h-4 w-4" />
                  Connect Aavrit Server
                </button>
              )}
            </div>
          )}
        </div>

        {/* Accordion 1: Date & Time */}
        <div
          onClick={() => setActivePanel(activePanel === 'datetime' ? null : 'datetime')}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${
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

        {/* ── Accordion 2: Password ──────────────────────────── */}
        <div className="rounded-[18px] border border-av-border/30 bg-av-surface/35 px-4 py-3 text-[12px] leading-relaxed text-av-muted">
          Unlock date and time are always required. Password and keyphrase stay optional unless you turn them on for an extra protection layer after release.
        </div>

        <div
          onClick={togglePasswordProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${
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
              <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md group/input">
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

              <div className="p-4 bg-container-bg border border-av-border/30 rounded-xl shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md">
                 <div className="flex items-center justify-between text-[10px] font-bold text-av-muted mb-2.5 uppercase tracking-[0.15em]">
                   <span>Password Strength</span>
                   <span className={`${strengthLabelColor} transition-colors duration-300`}>{strengthLabel}</span>
                 </div>
                 <div className="h-1.5 bg-av-border/40 dark:bg-black/40 rounded-full overflow-hidden mb-4 shadow-[inset_0_2px_4px_rgba(0,0,0,0.5)]">
                   <div style={{ width: `${strength}%` }} className={`h-full rounded-full transition-all duration-500 ease-out ${strengthColor}`} />
                 </div>
                 <div className="grid grid-cols-2 gap-y-2.5 text-[11px] font-medium text-av-muted tracking-wide">
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasMinLen ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`}/> Length &ge; 12</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasUpper ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`}/> Uppercase</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasLower ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`}/> Lowercase</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasNumber ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`}/> Numeric</div>
                    <div className="flex items-center gap-2 col-span-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasSpecial ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`}/> Symbolic Character</div>
                 </div>
              </div>

            </div>
          )}
        </div>

        {/* ── Accordion 3: Keyphrase ─────────────────────────── */}
        <div
          onClick={toggleKeyphraseProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${
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
                 <button onClick={handleGenerateKeyphrase} className="w-full py-3.5 rounded-xl border border-purple-500/20 bg-purple-500/10 shadow-sm hover:bg-purple-500/15 text-[13px] font-semibold transition-all duration-300 flex items-center justify-center gap-2.5 text-purple-700 dark:text-purple-300 hover:border-purple-500/40">
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
                   <div className="security-keyphrase-actions mt-4 flex items-center gap-3 pt-4">
                      <button onClick={handleCopyKeyphrase} className="security-keyphrase-copy flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-colors duration-300">
                        {isCopied ? <><CheckCircle2 className="w-4 h-4 text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]"/> Copied</> : <><Copy className="w-4 h-4"/> Copy</>}
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

        {/* ── Lock button ────────────────────────────────────── */}
        <div
          onClick={togglePqcProtection}
          className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${
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
                <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Quantum Keyfile</h3>
                <p className="text-av-muted text-[13px] font-light">Add a separate `.avkkey` file on top of time release</p>
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
            <div className="px-5 pb-5 space-y-4 pt-1 relative z-10" onClick={e => e.stopPropagation()}>
              <div className="security-pqc-info rounded-2xl p-4">
                <div className="flex items-start gap-3">
                  <div className="security-pqc-icon flex h-9 w-9 shrink-0 items-center justify-center rounded-xl">
                    <Fingerprint className="h-4 w-4" />
                  </div>
                  <p className="text-[12px] leading-relaxed">
                    This mode keeps the capsule portable while adding a fixed hybrid quantum suite through a separate protected <span className="font-semibold">.avkkey</span> file that must be present during unlock.
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleChoosePqcKeyfile}
                  className="flex-1 py-3 rounded-xl bg-av-main text-av-surface border border-av-main text-sm font-semibold hover:opacity-90 transition-all shadow-sm"
                >
                  {pqcKeyfilePath ? 'Change .avkkey Destination' : 'Choose .avkkey Destination'}
                </button>
                {pqcKeyfilePath && (
                  <button
                    onClick={() => setPqcKeyfilePath('')}
                    className="py-3 px-4 rounded-xl bg-av-surface border border-av-border/70 text-av-main text-sm font-semibold hover:border-red-500/30 hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-300 transition-all"
                  >
                    Clear
                  </button>
                )}
              </div>
              <div className="security-keyfile-destination rounded-xl p-3">
                <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-1">Keyfile Destination</p>
                <p className="break-all text-sm">{pqcKeyfilePath || 'You will be prompted before capsule creation starts.'}</p>
              </div>
              <p className="security-keyfile-warning rounded-xl px-3 py-2 text-[11px] leading-relaxed">
                Losing the `.avkkey` means the capsule cannot be opened, even after the Aavrit or drand release succeeds.
              </p>
            </div>
          )}
        </div>

        <div className="shrink-0 flex flex-col gap-3 mt-auto pt-2">
          {pqcEnabled && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="security-external-keyfile-card mb-2 overflow-hidden rounded-[18px]"
            >
              <div className="h-1.5 w-full bg-gradient-to-r from-amber-500 via-orange-500 to-yellow-400" />
              <div className="flex items-start gap-3 p-4">
                <div className="security-pqc-icon flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl">
                  <Fingerprint className="h-5 w-5" />
                </div>
                <div className="min-w-0 flex-1">
                  <div className="mb-2 flex items-center gap-2">
                    <p className="text-[13px] font-bold uppercase tracking-[0.18em] text-av-main">External Keyfile Required</p>
                    <span className="rounded-full border border-av-border/60 bg-av-border/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-av-muted">
                      Required
                    </span>
                  </div>
                  <p className="text-[13px] leading-relaxed text-av-main">
                    This capsule also needs the separate <span className="font-semibold">.avkkey</span> file during unlock. Keep it stored away from the <span className="font-semibold">.avk</span> archive.
                  </p>
                  <p className="mt-2 text-[11px] leading-relaxed text-av-muted">
                    Without the matching keyfile, unlock cannot complete even after the release time is reached.
                  </p>
                </div>
              </div>
            </motion.div>
          )}
          {showInlineProgressCard && progress.status !== 'idle' && !loading && !isEncrypted && (
            <ProgressCard
              status={progress.status === 'running' ? 'Creating…' : progress.status === 'completed' ? 'Completed' : progress.status === 'error' ? 'Error' : progress.status === 'cancelled' ? 'Cancelled' : 'Preparing…'}
              percentage={progress.percentage}
              currentOperation={progress.currentOperation || 'Executing…'}
              fileSize={progress.fileSize}
              compressionRatio={progress.compressionRatio}
              onCancel={progress.cancel}
              isCancelling={progress.isCancelling}
              elapsedSeconds={progress.elapsedSeconds}
              etaSeconds={progress.etaSeconds}
            />
          )}

          <BackendStartupNotice backend={backendRuntime} compact />

          <button
            onClick={handleEncode}
            disabled={!canAttemptCreateTimeCapsule}
            className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${
              !canAttemptCreateTimeCapsule
                ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner backdrop-blur-sm'
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
                ? 'Aavrit release will verify the signed reveal before payload decryption.'
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


