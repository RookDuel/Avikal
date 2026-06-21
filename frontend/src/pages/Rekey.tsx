import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { Archive, CheckCircle2, ChevronDown, Download, Eye, EyeOff, File, FileKey2, Fingerprint, Key, RotateCw, ShieldAlert, X } from 'lucide-react'
import { toast } from 'sonner'

import { api } from '../lib/api'
import type { KeyphraseWordPair } from '../lib/api'
import { getErrorMessage } from '../lib/errors'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'
import KeyphraseAssistInput, { splitKeyphraseWords } from '../components/KeyphraseAssistInput'
import ProcessingOverlay from '../components/ProcessingOverlay'
import { copyKeyphraseToClipboard, downloadStructuredKeyphrase } from '../lib/keyphraseExport'
import PasswordStrengthMeter from '../components/PasswordStrengthMeter'

interface ArchiveInspectHints {
  provider?: 'aavrit' | 'drand' | null
  archive_type?: 'single_file' | 'multi_file' | null
  metadata_accessible?: boolean
  metadata_requires_secret?: boolean
  password_hint?: boolean | null
  keyphrase_hint?: boolean | null
  pqc_required?: boolean | null
  pqc_storage_mode?: 'embedded' | 'external' | null
  unlock_timestamp?: number | null
  drand_round?: number | null
  keyphrase_wordlist_id?: string | null
}

interface RekeyResult {
  ok: boolean
  mode: 'rekey'
  input_file: string
  output_file: string
  in_place: boolean
  payload_rewritten: boolean
  metadata_version: number
}

function deriveDefaultRekeyPath(inputFile: string): string {
  if (!inputFile) return 'rekeyed.avk'
  const normalized = inputFile.replace(/\\/g, '/')
  const lastSlash = normalized.lastIndexOf('/')
  const directory = lastSlash >= 0 ? inputFile.slice(0, inputFile.lastIndexOf('\\') >= 0 ? inputFile.lastIndexOf('\\') : inputFile.lastIndexOf('/')) : ''
  const fileName = lastSlash >= 0 ? normalized.slice(lastSlash + 1) : normalized
  const base = fileName.replace(/\.avk$/i, '')
  const nextName = `${base || 'archive'}-rekeyed.avk`
  if (!directory) return nextName
  const separator = inputFile.includes('\\') ? '\\' : '/'
  return `${directory}${separator}${nextName}`
}

function formatProtectionSet(passwordEnabled: boolean, keyphraseEnabled: boolean): string {
  if (passwordEnabled && keyphraseEnabled) return 'Password + Keyphrase'
  if (passwordEnabled) return 'Password only'
  if (keyphraseEnabled) return 'Keyphrase only'
  return 'No protection selected'
}

export default function Rekey() {
  const backendRuntime = useBackendRuntime()

  const [archivePath, setArchivePath] = useState('')
  const [archiveHints, setArchiveHints] = useState<ArchiveInspectHints | null>(null)
  const [inspectLoading, setInspectLoading] = useState(false)

  const [oldPassword, setOldPassword] = useState('')
  const [oldKeyphrase, setOldKeyphrase] = useState('')
  const [newPasswordEnabled, setNewPasswordEnabled] = useState(true)
  const [newPassword, setNewPassword] = useState('')
  const [newKeyphraseEnabled, setNewKeyphraseEnabled] = useState(false)
  const [newKeyphrase, setNewKeyphrase] = useState('')
  const [outputFilePath, setOutputFilePath] = useState('')

  const [showOldPassword, setShowOldPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showCurrentCredentialsPanel, setShowCurrentCredentialsPanel] = useState(false)
  const [showNewCredentialsPanel, setShowNewCredentialsPanel] = useState(false)
  const [loading, setLoading] = useState(false)
  const [rekeyResult, setRekeyResult] = useState<RekeyResult | null>(null)
  const [keyphraseWordPairs, setKeyphraseWordPairs] = useState<KeyphraseWordPair[]>([])
  const [isCopied, setIsCopied] = useState(false)

  const resetRightPanel = useCallback(() => {
    setOldPassword('')
    setOldKeyphrase('')
    setNewPasswordEnabled(true)
    setNewPassword('')
    setNewKeyphraseEnabled(false)
    setNewKeyphrase('')
    setOutputFilePath('')
    setShowOldPassword(false)
    setShowNewPassword(false)
    setIsCopied(false)
  }, [])

  const resetAll = useCallback(() => {
    setArchivePath('')
    setArchiveHints(null)
    setRekeyResult(null)
    resetRightPanel()
  }, [resetRightPanel])

  useEffect(() => {
    if (!backendRuntime.isReady || keyphraseWordPairs.length > 0) return

    let cancelled = false
    api.getKeyphraseRomanMap()
      .then((result) => {
        if (!cancelled && result.success) {
          setKeyphraseWordPairs(result.words)
        }
      })
      .catch(() => {
        if (!cancelled) toast.error('Keyphrase typing helper unavailable')
      })

    return () => {
      cancelled = true
    }
  }, [backendRuntime.isReady, keyphraseWordPairs.length])

  useEffect(() => {
    if (!archivePath) {
      setArchiveHints(null)
      return
    }

    let cancelled = false
    setInspectLoading(true)
    api.inspectArchive({ input_file: archivePath })
      .then((response) => {
        if (!cancelled) {
          setArchiveHints(response.archive || null)
        }
      })
      .catch((error) => {
        if (!cancelled) {
          setArchiveHints(null)
          toast.error(getErrorMessage(error, 'Failed to inspect archive'))
        }
      })
      .finally(() => {
        if (!cancelled) setInspectLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [archivePath])

  const handleBrowseArchive = async () => {
    try {
      const selected = await window.electron?.openFile({
        properties: ['openFile'],
        filters: [{ name: 'RookDuel Avikal File', extensions: ['avk'] }],
      })
      if (selected && selected.length > 0) {
        const nextPath = selected[0]
        setArchivePath(nextPath)
        setOutputFilePath(deriveDefaultRekeyPath(nextPath))
        setRekeyResult(null)
        setArchiveHints(null)
        setLoading(false)
        setOldPassword('')
        setOldKeyphrase('')
      }
    } catch (error) {
      console.error('Archive browse failed:', error)
      toast.error('Failed to choose archive')
    }
  }

  const handleChooseOutput = async () => {
    try {
      const selected = await window.electron?.saveFile({
        defaultPath: outputFilePath || deriveDefaultRekeyPath(archivePath),
        filters: [{ name: 'RookDuel Avikal File', extensions: ['avk'] }],
      })
      if (selected) {
        setOutputFilePath(selected)
      }
    } catch (error) {
      console.error('Output file selection failed:', error)
      toast.error('Failed to choose output path')
    }
  }

  const handleGenerateKeyphrase = async () => {
    try {
      const result = await api.generateKeyphrase(21)
      if (result.success) {
        setNewKeyphrase(result.keyphrase)
        toast.success('New keyphrase generated')
      }
    } catch {
      toast.error('Failed to generate keyphrase')
    }
  }

  const handleCopyKeyphrase = async () => {
    if (!newKeyphrase) return
    const copied = await copyKeyphraseToClipboard(newKeyphrase)
    if (copied) {
      setIsCopied(true)
      toast.success('Keyphrase copied')
      setTimeout(() => setIsCopied(false), 2000)
    } else {
      toast.error('Clipboard copy failed. Use Download instead.')
    }
  }

  const handleDownloadKeyphrase = async () => {
    if (!newKeyphrase) return
    const saved = await downloadStructuredKeyphrase(newKeyphrase, 'Rekey replacement keyphrase')
    if (saved) toast.success('Keyphrase document saved')
  }

  const unsupportedReason = useMemo(() => {
    if (!archiveHints) return null
    if (archiveHints.provider === 'drand' || archiveHints.provider === 'aavrit') {
      return 'Time-capsule rekey is not available yet. Decrypt and create a new archive instead.'
    }
    if (archiveHints.pqc_required) {
      return 'PQC rekey is not available yet. Decrypt and create a new archive instead.'
    }
    if (archiveHints.password_hint === false && archiveHints.keyphrase_hint === false) {
      return 'This archive does not appear to use password or keyphrase protection, so it does not need rekey.'
    }
    return null
  }, [archiveHints])

  const currentNeedsBoth = Boolean(archiveHints?.password_hint && archiveHints?.keyphrase_hint)
  const newKeyphraseWordCount = splitKeyphraseWords(newKeyphrase).length
  const hasMinLen = newPassword.length >= 12
  const hasUpper = /[A-Z]/.test(newPassword)
  const hasLower = /[a-z]/.test(newPassword)
  const hasNumber = /[0-9]/.test(newPassword)
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword)
  const isValidNewPassword = hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial

  const hasCurrentSecret = oldPassword.trim().length > 0 || splitKeyphraseWords(oldKeyphrase).length > 0
  const hasNewSecret = (newPasswordEnabled && newPassword.trim().length > 0) || (newKeyphraseEnabled && newKeyphraseWordCount > 0)
  const currentPasswordEnabled = Boolean(archiveHints?.password_hint)
  const currentKeyphraseEnabled = Boolean(archiveHints?.keyphrase_hint)
  const currentProtectionSet = useMemo(
    () => formatProtectionSet(currentPasswordEnabled, currentKeyphraseEnabled),
    [currentKeyphraseEnabled, currentPasswordEnabled],
  )
  const resultingProtectionSet = useMemo(
    () => formatProtectionSet(newPasswordEnabled, newKeyphraseEnabled),
    [newKeyphraseEnabled, newPasswordEnabled],
  )
  const isReducingProtection = useMemo(() => {
    const currentCount = Number(currentPasswordEnabled) + Number(currentKeyphraseEnabled)
    const nextCount = Number(newPasswordEnabled) + Number(newKeyphraseEnabled)
    return currentCount > 0 && nextCount < currentCount
  }, [currentKeyphraseEnabled, currentPasswordEnabled, newKeyphraseEnabled, newPasswordEnabled])
  const resultingProtectionNotice = useMemo(() => {
    if (!archiveHints) return 'Choose the protections that should remain on the rekeyed archive.'
    if (isReducingProtection) {
      return 'Any protection left disabled here will be removed from the rekeyed archive.'
    }
    if (currentProtectionSet === resultingProtectionSet) {
      return 'You are keeping the same protection shape and rotating its secrets.'
    }
    return 'The rekeyed archive will require exactly this new protection set during decryption.'
  }, [archiveHints, currentProtectionSet, isReducingProtection, resultingProtectionSet])
  const currentCredentialSummary = useMemo(() => {
    const parts: string[] = []
    if (archiveHints) parts.push(currentProtectionSet)
    if (oldPassword.trim().length > 0) parts.push('Password entered')
    if (splitKeyphraseWords(oldKeyphrase).length > 0) parts.push('Keyphrase entered')
    return parts.length > 0 ? parts.join(' - ') : 'No current secret entered yet'
  }, [archiveHints, currentProtectionSet, oldKeyphrase, oldPassword])
  const newCredentialSummary = useMemo(() => {
    const parts: string[] = []
    parts.push(resultingProtectionSet)
    if (newPasswordEnabled) parts.push(newPassword.trim().length > 0 ? 'Password ready' : 'Password on')
    if (newKeyphraseEnabled) parts.push(newKeyphraseWordCount > 0 ? `Keyphrase ${newKeyphraseWordCount}/21` : 'Keyphrase on')
    return parts.length > 0 ? parts.join(' - ') : 'No new protection selected yet'
  }, [newKeyphraseWordCount, newPassword, newPasswordEnabled, newKeyphraseEnabled, resultingProtectionSet])

  const canRekey = backendRuntime.isReady
    && !!archivePath
    && !!outputFilePath
    && !loading
    && !inspectLoading
    && !unsupportedReason
    && hasCurrentSecret
    && hasNewSecret
    && (!newPasswordEnabled || isValidNewPassword)
    && (!newKeyphraseEnabled || newKeyphraseWordCount === 21)
    && (newPasswordEnabled || newKeyphraseEnabled)

  const handleRekey = async () => {
    if (!canRekey) return

    try {
      setLoading(true)
      setRekeyResult(null)

      const result = await api.rekeyArchive({
        input_file: archivePath,
        output_file: outputFilePath,
        old_password: oldPassword || undefined,
        old_keyphrase: splitKeyphraseWords(oldKeyphrase).length > 0 ? splitKeyphraseWords(oldKeyphrase) : undefined,
        new_password: newPasswordEnabled ? newPassword || undefined : undefined,
        new_keyphrase: newKeyphraseEnabled ? splitKeyphraseWords(newKeyphrase) : undefined,
      })

      setRekeyResult(result)
      resetRightPanel()
      toast.success('Archive credentials rotated successfully')
    } catch (error) {
      toast.error(getErrorMessage(error, 'Rekey failed'))
    } finally {
      setOldPassword('')
      setOldKeyphrase('')
      setNewPassword('')
      setNewKeyphrase('')
      setLoading(false)
    }
  }

  return (
    <div className="av-page-shell">
      <div className="av-work-grid">
        <div className="av-primary-panel lg:col-span-3 flex flex-col overflow-hidden relative">
          <div className="av-panel-header z-10 shrink-0">
            <h2 className="text-[26px] font-medium tracking-tight text-av-main mb-1 flex items-center gap-3">
              Rekey Archive <span className="font-light text-av-muted">Rotate Access</span>
            </h2>
            <p className="text-av-muted text-sm font-light">Change password/keyphrase access without rewriting the payload.</p>
          </div>

          <div className="av-left-workspace flex-1 flex flex-col relative overflow-hidden">
            {loading && (
              <ProcessingOverlay
                title="Rekeying Archive"
                description="Rewrapping the archive access layer while keeping payload bytes unchanged."
                icon={<RotateCw className="h-5 w-5 text-av-accent" strokeWidth={1.7} />}
                percentage={null}
                sourceLabel="Access layer"
                statusLabel="Working"
                indeterminateText="Rotating credential envelope"
              />
            )}

            {rekeyResult ? (
              <div className="flex-1 p-8 flex items-center justify-center">
                <div className="av-result-card w-full max-w-lg p-10 rounded-[24px] flex flex-col items-center text-center">
                  <div className="relative mb-8">
                    <div className="absolute inset-0 bg-emerald-500/20 rounded-full blur-2xl" />
                    <div className="w-20 h-20 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/30 relative z-10 shadow-inner">
                      <CheckCircle2 className="w-10 h-10 text-emerald-500" strokeWidth={1.5} />
                    </div>
                  </div>
                  <h3 className="text-[22px] font-medium text-av-main mb-3 tracking-tight">Rekey Complete</h3>
                  <p className="text-sm text-av-muted font-light mb-8">The archive payload stayed unchanged. Only the credential layer was rotated.</p>

                  <div className="w-full p-4 rounded-xl bg-av-border/10 dark:bg-white/5 border border-av-border/40 flex items-center gap-4 transition-all shadow-inner">
                    <div className="w-10 h-10 rounded-lg bg-av-surface shadow-sm border border-av-border/50 flex items-center justify-center shrink-0">
                      <Archive className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
                    </div>
                    <div className="text-left truncate flex-1">
                      <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-1">New Archive Path</p>
                      <p className="text-sm font-medium text-av-main truncate">{rekeyResult.output_file}</p>
                    </div>
                  </div>

                  <button
                    onClick={resetAll}
                    className="mt-10 w-full py-4 rounded-xl bg-av-main text-av-surface font-medium hover:opacity-90 shadow-lg transition-all"
                  >
                    Rekey Another Archive
                  </button>
                </div>
              </div>
            ) : (
              <div className="flex-1 p-5 flex flex-col">
                <div className="av-drop-zone rounded-[20px] flex-1 min-h-[360px] p-6 transition-colors">
                  {!archivePath ? (
                    <div className="flex h-full min-h-[310px] flex-col items-center justify-center text-center">
                      <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-2xl border border-av-border/40 bg-av-surface/70 shadow-sm">
                        <FileKey2 className="h-8 w-8 text-av-main" strokeWidth={1.5} />
                      </div>
                      <h3 className="text-xl font-medium tracking-tight text-av-main">Select archive</h3>
                      <p className="mt-2 max-w-sm text-sm text-av-muted">Choose a normal password/keyphrase `.avk` archive.</p>
                      <button
                        onClick={handleBrowseArchive}
                        className="mt-6 flex items-center gap-2 rounded-xl bg-av-main px-5 py-2.5 text-xs font-semibold text-av-surface shadow-[0_2px_12px_rgba(0,0,0,0.15)] transition-all hover:-translate-y-0.5 hover:opacity-90 active:scale-95"
                      >
                        <File className="h-3.5 w-3.5" /> Browse .avk
                      </button>
                    </div>
                  ) : (
                    <div className="flex h-full min-h-[310px] flex-col justify-between gap-5">
                      <div className="rounded-[22px] border border-av-border/45 bg-av-surface/60 p-5 shadow-sm">
                        <div className="mb-4 flex items-start justify-between gap-4">
                          <div className="flex min-w-0 items-start gap-3">
                            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-av-border/40 bg-av-border/10">
                              <Archive className="h-6 w-6 text-av-main" strokeWidth={1.5} />
                            </div>
                            <div className="min-w-0">
                              <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-av-muted">Selected Archive</p>
                              <p className="mt-1 line-clamp-2 break-all text-sm font-medium text-av-main">{archivePath}</p>
                            </div>
                          </div>
                          {inspectLoading && <span className="shrink-0 rounded-full border border-av-border/40 bg-av-border/10 px-2.5 py-1 text-[10px] text-av-muted">Inspecting</span>}
                        </div>

                        {archiveHints && (
                          <div className={`rounded-2xl border p-3 ${
                            unsupportedReason
                              ? 'border-amber-500/25 bg-amber-500/5'
                              : 'border-emerald-500/20 bg-emerald-500/5'
                          }`}>
                            <div className="flex items-start gap-2.5">
                              <div className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-xl ${
                                unsupportedReason ? 'bg-amber-500/10 text-amber-500' : 'bg-emerald-500/10 text-emerald-500'
                              }`}>
                                {unsupportedReason ? <ShieldAlert className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
                              </div>
                              <div className="min-w-0">
                                <p className="text-sm font-semibold text-av-main">
                                  {unsupportedReason ? 'Rekey unavailable' : 'Ready for rekey'}
                                </p>
                                <p className="mt-1 text-[12px] leading-relaxed text-av-muted">
                                  {unsupportedReason || 'Rotate password/keyphrase access.'}
                                </p>
                                <div className="mt-2 flex flex-wrap gap-1.5">
                                  {archiveHints.password_hint && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">Password</span>}
                                  {archiveHints.keyphrase_hint && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">Keyphrase</span>}
                                  {archiveHints.provider && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">TimeCapsule</span>}
                                  {archiveHints.pqc_required && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">PQC</span>}
                                </div>
                              </div>
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleBrowseArchive}
                          className="flex items-center gap-2 rounded-xl bg-av-main px-5 py-2.5 text-xs font-semibold text-av-surface shadow-[0_2px_12px_rgba(0,0,0,0.15)] transition-all hover:-translate-y-0.5 hover:opacity-90 active:scale-95"
                        >
                          <File className="h-3.5 w-3.5" /> Change Archive
                        </button>
                        <button
                          onClick={resetAll}
                          className="flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-500/10 px-4 py-2.5 text-xs font-semibold text-red-400 shadow-sm transition-all hover:bg-red-500/20 active:scale-95"
                        >
                          <X className="h-3.5 w-3.5" /> Remove
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>

        <div className={`av-side-stack av-natural-side-stack lg:col-span-2 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>
          <div className="px-2 mb-1">
            <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Rekey Settings</h3>
          </div>

          <div className={`rounded-[20px] border shadow-sm overflow-hidden backdrop-blur-xl ${
            isReducingProtection
              ? 'bg-amber-500/8 border-amber-500/30'
              : 'bg-av-surface/40 border-av-border/30'
          }`}>
            <div className="p-4">
              <div className="flex items-start gap-3">
                <div className={`w-10 h-10 rounded-xl flex items-center justify-center border shadow-[0_2px_8px_rgba(0,0,0,0.04)] shrink-0 ${
                  isReducingProtection
                    ? 'bg-amber-500/10 border-amber-500/25 text-amber-500'
                    : 'bg-av-surface border-av-border/20 text-av-accent'
                }`}>
                  {isReducingProtection ? <ShieldAlert className="w-[18px] h-[18px]" strokeWidth={1.5} /> : <Archive className="w-[18px] h-[18px]" strokeWidth={1.5} />}
                </div>
                <div className="min-w-0 flex-1">
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Rekey Output</h3>
                  <p className="text-av-muted text-[12px] font-light leading-relaxed">{resultingProtectionNotice}</p>
                </div>
              </div>

              <div className="mt-3 grid grid-cols-2 gap-2">
                <div className="rounded-2xl border border-av-border/35 bg-av-border/10 p-3">
                  <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.18em] mb-1">Current</p>
                  <p className="text-sm font-medium text-av-main">{currentProtectionSet}</p>
                </div>
                <div className="rounded-2xl border border-av-border/35 bg-av-border/10 p-3">
                  <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.18em] mb-1">After</p>
                  <p className="text-sm font-medium text-av-main">{resultingProtectionSet}</p>
                </div>
              </div>

              <div className="mt-3 rounded-xl border border-av-border/40 bg-av-border/10 p-3">
                <div className="mb-2 flex items-center justify-between gap-3">
                  <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.18em]">Destination</p>
                  <button
                    onClick={handleChooseOutput}
                    disabled={!archivePath}
                    className={`rounded-lg px-3 py-1.5 text-[11px] font-semibold transition-colors ${
                      archivePath
                        ? 'bg-av-main text-av-surface hover:opacity-90'
                        : 'bg-av-border/20 text-av-muted cursor-not-allowed'
                    }`}
                  >
                    {outputFilePath ? 'Change' : 'Choose'}
                  </button>
                </div>
                <p className="line-clamp-2 break-all text-sm text-av-main">{outputFilePath || 'No output selected.'}</p>
              </div>
            </div>
          </div>

          <CollapsibleSettingsCard
            icon={<Fingerprint className="w-[18px] h-[18px] text-emerald-500" strokeWidth={1.5} />}
            title="Current Credentials"
            description={currentNeedsBoth
              ? 'Current password and keyphrase are required.'
              : 'Enter the current secret.'}
            summary={currentCredentialSummary}
            open={showCurrentCredentialsPanel}
            onToggle={() => setShowCurrentCredentialsPanel((value) => !value)}
          >
            <div className="space-y-4">
              <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)]">
                <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                  <Fingerprint className="w-4 h-4 text-emerald-400" />
                </div>
                <input
                  type={showOldPassword ? 'text' : 'password'}
                  placeholder="Current archive password"
                  value={oldPassword}
                  onChange={(event) => setOldPassword(event.target.value)}
                  className="w-full pl-10 pr-11 py-3.5 rounded-xl bg-transparent text-av-main text-sm focus:outline-none focus:ring-1 transition-all font-medium placeholder:font-light focus:ring-emerald-500/50"
                />
                <button onClick={() => setShowOldPassword((value) => !value)} className="absolute right-3 top-1/2 -translate-y-1/2 text-av-muted hover:text-av-main transition-colors p-1.5 rounded-lg hover:bg-av-border/10">
                  {showOldPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>

              <KeyphraseAssistInput
                value={oldKeyphrase}
                onChange={setOldKeyphrase}
                pairs={keyphraseWordPairs}
                disabled={!backendRuntime.isReady || loading}
                onIssue={(message) => toast.error(message)}
                showClearButton
                onClearAll={() => setOldKeyphrase('')}
                placeholder="Current 21-word keyphrase"
              />
            </div>
          </CollapsibleSettingsCard>

          <CollapsibleSettingsCard
            icon={<Key className="w-[18px] h-[18px] text-purple-500" strokeWidth={1.5} />}
            title="New Credentials"
            description="Choose the new required secret."
            summary={newCredentialSummary}
            open={showNewCredentialsPanel}
            onToggle={() => setShowNewCredentialsPanel((value) => !value)}
          >
            <div className="space-y-4">
                <div className={`rounded-[18px] border transition-all duration-300 overflow-hidden backdrop-blur-xl ${newPasswordEnabled ? 'bg-av-surface/80 border-emerald-500/35 ring-1 ring-emerald-500/15' : 'bg-av-surface/40 border-av-border/30'}`}>
                  <div className="p-3.5 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <LockBadge />
                      <div>
                        <h4 className="text-sm font-medium text-av-main">New Password</h4>
                        <p className="text-[12px] text-av-muted">Password access</p>
                      </div>
                    </div>
                    <Toggle checked={newPasswordEnabled} onClick={() => setNewPasswordEnabled((value) => !value)} />
                  </div>

                  {newPasswordEnabled && (
                    <div className="px-3.5 pb-3.5 space-y-3">
                      <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)]">
                        <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                          <Fingerprint className="w-4 h-4 text-emerald-400" />
                        </div>
                        <input
                          type={showNewPassword ? 'text' : 'password'}
                          placeholder="New archive password"
                          value={newPassword}
                          onChange={(event) => setNewPassword(event.target.value)}
                          className="w-full pl-10 pr-11 py-3.5 rounded-xl bg-transparent text-av-main text-sm focus:outline-none focus:ring-1 transition-all font-medium placeholder:font-light focus:ring-emerald-500/50"
                        />
                        <button onClick={() => setShowNewPassword((value) => !value)} className="absolute right-3 top-1/2 -translate-y-1/2 text-av-muted hover:text-av-main transition-colors p-1.5 rounded-lg hover:bg-av-border/10">
                          {showNewPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>

                      <PasswordStrengthMeter password={newPassword} compact />
                    </div>
                  )}
                </div>

                <div className={`rounded-[18px] border transition-all duration-300 overflow-hidden backdrop-blur-xl ${newKeyphraseEnabled ? 'bg-av-surface/80 border-purple-500/35 ring-1 ring-purple-500/15' : 'bg-av-surface/40 border-av-border/30'}`}>
                  <div className="p-3.5 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <KeyBadge />
                      <div>
                        <h4 className="text-sm font-medium text-av-main">New Keyphrase</h4>
                        <p className="text-[12px] text-av-muted">21-word access</p>
                      </div>
                    </div>
                    <Toggle checked={newKeyphraseEnabled} onClick={() => setNewKeyphraseEnabled((value) => !value)} />
                  </div>

                  {newKeyphraseEnabled && (
                    <div className="px-3.5 pb-3.5 space-y-3">
                      <div className="flex items-center gap-2">
                        <button onClick={handleGenerateKeyphrase} className="keyphrase-generate-button flex-1 rounded-xl border py-2.5 text-[13px] font-semibold transition-colors">
                          {newKeyphrase ? 'Regenerate Keyphrase' : 'Generate New Keyphrase'}
                        </button>
                        {newKeyphrase && (
                          <button onClick={handleCopyKeyphrase} className="rounded-xl border border-av-border/40 bg-av-border/10 px-4 py-2.5 text-xs font-semibold text-av-muted transition-colors hover:bg-av-border/20 hover:text-av-main">
                            {isCopied ? 'Copied' : 'Copy'}
                          </button>
                        )}
                        {newKeyphrase && (
                          <button onClick={handleDownloadKeyphrase} className="flex items-center gap-1.5 rounded-xl border border-av-border/40 bg-av-border/10 px-4 py-2.5 text-xs font-semibold text-av-muted transition-colors hover:bg-av-border/20 hover:text-av-main">
                            <Download className="h-3.5 w-3.5" /> Download
                          </button>
                        )}
                      </div>

                      <KeyphraseAssistInput
                        value={newKeyphrase}
                        onChange={setNewKeyphrase}
                        pairs={keyphraseWordPairs}
                        disabled={!backendRuntime.isReady || loading}
                        onIssue={(message) => toast.error(message)}
                        showClearButton
                        onClearAll={() => setNewKeyphrase('')}
                        placeholder="New 21-word keyphrase"
                      />

                      {newKeyphrase.trim().length > 0 && (
                        <div className="flex items-center gap-2">
                          <div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${newKeyphraseWordCount === 21 ? 'bg-purple-500 shadow-[0_0_6px_rgba(168,85,247,0.8)]' : 'bg-av-border/50'}`} />
                          <span className="text-[11px] text-av-muted font-medium">{newKeyphraseWordCount} / 21 words</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
          </CollapsibleSettingsCard>

          {unsupportedReason && (
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-4 rounded-[16px] bg-amber-500/10 border border-amber-500/30 flex items-start gap-3 backdrop-blur-md shadow-inner">
              <ShieldAlert className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
              <div>
                <p className="text-[13px] font-bold text-amber-500 uppercase tracking-wide mb-1">Unsupported Rekey Scenario</p>
                <p className="text-xs text-amber-500/90 font-medium leading-relaxed">{unsupportedReason}</p>
              </div>
            </motion.div>
          )}

          <div className="shrink-0 flex flex-col gap-3 pt-2">
            <BackendStartupNotice backend={backendRuntime} compact />
            <button
              onClick={handleRekey}
              disabled={!canRekey}
              className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${
                !canRekey
                  ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner backdrop-blur-sm'
                  : 'bg-av-main hover:opacity-90 text-av-surface shadow-[0_10px_30px_rgba(0,0,0,0.15)] hover:shadow-[0_10px_40px_rgba(0,0,0,0.2)] hover:-translate-y-0.5'
              }`}
            >
              <RotateCw className="w-5 h-5" />
              {loading ? 'Rekeying Archive...' : !backendRuntime.isReady ? 'Starting Secure Engine...' : 'Rotate Credentials'}
            </button>
            <p className="text-center text-[11px] text-av-muted mt-1 font-light">
              {!backendRuntime.isReady
                ? backendRuntime.detail
                : unsupportedReason
                  ? unsupportedReason
                  : 'Rekey keeps payload.enc unchanged and rebuilds the archive around the exact new protection set shown above.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}

function Toggle({ checked, onClick }: { checked: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`relative w-11 h-6 rounded-full transition-all duration-300 border shadow-inner ${checked ? 'bg-purple-500 border-purple-500 shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]' : 'bg-av-border/20 border-av-border/30'}`}
    >
      <span className={`absolute top-[1px] left-[1px] w-5 h-5 rounded-full bg-white shadow-[0_2px_5px_rgba(0,0,0,0.2)] transition-transform duration-300 ${checked ? 'translate-x-[20px]' : ''}`} />
    </button>
  )
}

function CollapsibleSettingsCard({
  icon,
  title,
  description,
  summary,
  open,
  onToggle,
  children,
}: {
  icon: ReactNode
  title: string
  description: string
  summary: string
  open: boolean
  onToggle: () => void
  children: ReactNode
}) {
  return (
    <div className="rounded-[20px] border bg-av-surface/40 border-av-border/30 shadow-sm overflow-hidden backdrop-blur-xl">
      <div className="p-4 flex items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0 flex-1">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center border bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 shrink-0">
            {icon}
          </div>
          <div className="min-w-0">
            <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">{title}</h3>
            <p className="text-av-muted text-[12px] font-light leading-relaxed">{description}</p>
            <p className="mt-1 text-[11px] font-medium text-av-muted truncate">{summary}</p>
          </div>
        </div>
        <button
          type="button"
          onClick={onToggle}
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-av-border/25 bg-av-surface text-av-muted shadow-[0_2px_8px_rgba(0,0,0,0.04)] transition-colors hover:bg-av-border/10"
          aria-label={open ? `Collapse ${title}` : `Expand ${title}`}
          aria-expanded={open}
        >
          <ChevronDown className={`h-4 w-4 transition-transform duration-300 ${open ? 'rotate-180' : ''}`} />
        </button>
      </div>

      {open && (
        <div className="px-4 pb-4">
          {children}
        </div>
      )}
    </div>
  )
}

function LockBadge() {
  return (
    <div className="w-10 h-10 rounded-xl flex items-center justify-center border bg-emerald-500/10 border-emerald-500/30 shadow-inner">
      <Fingerprint className="w-4 h-4 text-emerald-500" strokeWidth={1.5} />
    </div>
  )
}

function KeyBadge() {
  return (
    <div className="w-10 h-10 rounded-xl flex items-center justify-center border bg-purple-500/10 border-purple-500/30 shadow-inner">
      <Key className="w-4 h-4 text-purple-500" strokeWidth={1.5} />
    </div>
  )
}
