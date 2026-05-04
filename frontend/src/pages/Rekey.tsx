import { useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { Archive, CheckCircle2, ChevronDown, Eye, EyeOff, File, FileKey2, Fingerprint, Key, RefreshCw, RotateCw, ShieldAlert, Upload, X } from 'lucide-react'
import { toast } from 'sonner'

import { api } from '../lib/api'
import type { KeyphraseWordPair } from '../lib/api'
import { getErrorMessage } from '../lib/errors'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'
import KeyphraseAssistInput, { splitKeyphraseWords } from '../components/KeyphraseAssistInput'

interface ArchiveInspectHints {
  provider?: 'aavrit' | 'drand' | null
  archive_type?: 'single_file' | 'multi_file' | null
  metadata_accessible?: boolean
  metadata_requires_secret?: boolean
  password_hint?: boolean | null
  keyphrase_hint?: boolean | null
  pqc_required?: boolean | null
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

function getStrength(password: string): number {
  if (!password) return 0
  let score = 0
  if (password.length > 8) score += 25
  if (password.length > 11) score += 25
  if (/[A-Z]/.test(password)) score += 15
  if (/[a-z]/.test(password)) score += 15
  if (/[0-9]/.test(password)) score += 10
  if (/[^A-Za-z0-9]/.test(password)) score += 10
  return Math.min(score, 100)
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
  const [showCurrentCredentialsPanel, setShowCurrentCredentialsPanel] = useState(true)
  const [showNewCredentialsPanel, setShowNewCredentialsPanel] = useState(true)
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

  const handleCopyKeyphrase = () => {
    if (!newKeyphrase) return
    navigator.clipboard.writeText(newKeyphrase)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 2000)
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
  const passwordStrength = getStrength(newPassword)
  const hasMinLen = newPassword.length >= 12
  const hasUpper = /[A-Z]/.test(newPassword)
  const hasLower = /[a-z]/.test(newPassword)
  const hasNumber = /[0-9]/.test(newPassword)
  const hasSpecial = /[^A-Za-z0-9]/.test(newPassword)
  const isValidNewPassword = hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial

  const hasCurrentSecret = oldPassword.trim().length > 0 || splitKeyphraseWords(oldKeyphrase).length > 0
  const hasNewSecret = (newPasswordEnabled && newPassword.trim().length > 0) || (newKeyphraseEnabled && newKeyphraseWordCount > 0)
  const currentCredentialSummary = useMemo(() => {
    const parts: string[] = []
    if (oldPassword.trim().length > 0) parts.push('Password entered')
    if (splitKeyphraseWords(oldKeyphrase).length > 0) parts.push('Keyphrase entered')
    return parts.length > 0 ? parts.join(' • ') : 'No current secret entered yet'
  }, [oldKeyphrase, oldPassword])
  const newCredentialSummary = useMemo(() => {
    const parts: string[] = []
    if (newPasswordEnabled) parts.push(newPassword.trim().length > 0 ? 'Password ready' : 'Password on')
    if (newKeyphraseEnabled) parts.push(newKeyphraseWordCount > 0 ? `Keyphrase ${newKeyphraseWordCount}/21` : 'Keyphrase on')
    return parts.length > 0 ? parts.join(' • ') : 'No new protection selected yet'
  }, [newKeyphraseWordCount, newPassword, newPasswordEnabled, newKeyphraseEnabled])

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
      setLoading(false)
    }
  }

  return (
    <div className="min-h-full w-full max-w-[1600px] mx-auto p-6 lg:p-10 box-border">
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">
        <div className="lg:col-span-3 min-h-[550px] bg-av-surface/60 backdrop-blur-3xl rounded-[24px] shadow-[0_8px_40px_rgba(0,0,0,0.06)] border border-av-border/30 flex flex-col overflow-hidden relative transition-colors duration-300">
          <div className="px-8 py-7 border-b border-av-border/30 bg-gradient-to-b from-av-surface/80 to-av-surface/40 z-10 shrink-0">
            <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
              Rekey Archive <span className="font-light text-av-muted">Rotate Credentials Safely</span>
            </h2>
            <p className="text-av-muted text-sm font-light">Change archive credentials without rewriting the encrypted payload.</p>
          </div>

          <div className="flex-1 flex flex-col relative overflow-hidden bg-av-border/10 dark:bg-white/[0.01]">
            {loading && (
              <div className="absolute inset-0 z-20 bg-av-surface/80 backdrop-blur-xl flex flex-col items-center justify-center p-8">
                <div className="w-full max-w-md rounded-3xl bg-av-surface/90 border border-av-border/40 p-8 shadow-[0_20px_60px_rgba(0,0,0,0.12)]">
                  <div className="flex items-center gap-3 mb-5">
                    <div className="p-3 rounded-2xl bg-av-accent/10 border border-av-accent/30">
                      <RefreshCw className="w-6 h-6 text-av-accent animate-spin" strokeWidth={1.5} />
                    </div>
                    <div>
                      <h3 className="text-xl font-medium tracking-tight text-av-main">Rekeying Archive</h3>
                      <p className="text-sm text-av-muted font-light">Rewrapping the archive access layer while keeping payload bytes unchanged.</p>
                    </div>
                  </div>
                  <div className="h-2.5 w-full bg-av-border/30 rounded-full overflow-hidden">
                    <motion.div
                      className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-av-accent to-transparent"
                      animate={{ x: ['0%', '300%'] }}
                      transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
                    />
                  </div>
                </div>
              </div>
            )}

            {rekeyResult ? (
              <div className="flex-1 p-8 flex items-center justify-center">
                <div className="w-full max-w-lg p-10 rounded-[24px] bg-av-surface/90 backdrop-blur-2xl border border-emerald-500/20 shadow-[0_20px_60px_rgba(16,185,129,0.1)] flex flex-col items-center text-center">
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
              <div className="flex-1 p-8 flex flex-col">
                <div className="rounded-[20px] border border-dashed border-av-border/50 bg-av-surface/40 flex-1 p-8 flex flex-col justify-between transition-colors">
                  <div>
                    <div className="flex items-center gap-3 mb-5">
                      <div className="w-14 h-14 rounded-2xl bg-av-main/10 border border-av-border/30 flex items-center justify-center">
                        <FileKey2 className="w-7 h-7 text-av-main" strokeWidth={1.5} />
                      </div>
                      <div>
                        <h3 className="text-xl font-medium text-av-main tracking-tight">Choose an existing `.avk` archive</h3>
                        <p className="text-sm text-av-muted font-light">Rekey works only for normal rekey-capable archives. TimeCapsule and PQC rekey stay blocked for now.</p>
                      </div>
                    </div>

                    <div className="rounded-2xl border border-av-border/40 bg-av-border/10 p-4">
                      <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-2">Selected Archive</p>
                      <p className="text-sm text-av-main break-all">{archivePath || 'No archive selected yet.'}</p>
                    </div>

                    {archiveHints && (
                      <div className={`mt-4 rounded-2xl border p-4 ${
                        unsupportedReason
                          ? 'border-amber-500/25 bg-amber-500/5'
                          : 'border-emerald-500/20 bg-emerald-500/5'
                      }`}>
                        <div className="flex items-start gap-3">
                          <div className={`mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-xl ${
                            unsupportedReason ? 'bg-amber-500/10 text-amber-500' : 'bg-emerald-500/10 text-emerald-500'
                          }`}>
                            {unsupportedReason ? <ShieldAlert className="h-4 w-4" /> : <CheckCircle2 className="h-4 w-4" />}
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-semibold text-av-main">
                              {unsupportedReason ? 'Rekey not available for this archive' : 'Archive looks rekey-eligible'}
                            </p>
                            <p className="mt-1 text-[13px] leading-relaxed text-av-muted">
                              {unsupportedReason || 'You can rotate its password and/or keyphrase without rewriting the payload file.'}
                            </p>
                            <div className="mt-3 flex flex-wrap gap-2">
                              {archiveHints.password_hint && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">Current password protected</span>}
                              {archiveHints.keyphrase_hint && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">Current keyphrase protected</span>}
                              {archiveHints.provider && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">TimeCapsule: {archiveHints.provider}</span>}
                              {archiveHints.pqc_required && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">PQC required</span>}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>

                  <div className="mt-6 flex items-center gap-3">
                    <button
                      onClick={handleBrowseArchive}
                      className="flex items-center gap-2 text-xs bg-av-main text-av-surface font-semibold px-5 py-2.5 rounded-xl transition-all shadow-[0_2px_12px_rgba(0,0,0,0.15)] hover:opacity-90 hover:-translate-y-0.5 active:scale-95"
                    >
                      <File className="w-3.5 h-3.5" /> Browse `.avk`
                    </button>
                    {archivePath && (
                      <button
                        onClick={resetAll}
                        className="flex items-center gap-2 text-xs bg-red-500/10 border border-red-500/20 text-red-400 font-semibold px-4 py-2.5 rounded-xl transition-all shadow-sm hover:bg-red-500/20 active:scale-95"
                      >
                        <X className="w-3.5 h-3.5" /> Remove
                      </button>
                    )}
                    {inspectLoading && <span className="text-xs text-av-muted">Inspecting archive...</span>}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className={`lg:col-span-2 flex flex-col gap-5 pb-6 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>
          <div className="px-2 mb-1">
            <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Rekey Settings</h3>
          </div>

          <div className="rounded-[20px] border bg-av-surface/40 border-av-border/30 shadow-sm overflow-hidden backdrop-blur-xl">
            <div className="p-5">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-4">
                  <div className="w-11 h-11 rounded-xl flex items-center justify-center border bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20">
                    <RotateCw className="w-[18px] h-[18px] text-av-muted" strokeWidth={1.5} />
                  </div>
                  <div>
                    <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Output Archive</h3>
                    <p className="text-av-muted text-[13px] font-light">Choose where the rekeyed `.avk` should be written</p>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-av-border/10 dark:bg-white/5 border border-av-border/40">
                <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-1">Destination</p>
                <p className="text-sm text-av-main break-all">{outputFilePath || 'Choose a destination for the new archive.'}</p>
              </div>

              <div className="mt-4 flex items-center gap-3">
                <button
                  onClick={handleChooseOutput}
                  disabled={!archivePath}
                  className={`flex-1 py-3 rounded-xl text-sm font-semibold transition-all shadow-sm ${
                    archivePath
                      ? 'bg-av-main text-av-surface border border-av-main hover:opacity-90'
                      : 'bg-av-border/10 border border-av-border/20 text-av-muted cursor-not-allowed'
                  }`}
                >
                  {outputFilePath ? 'Change Output Destination' : 'Choose Output Destination'}
                </button>
              </div>
            </div>
          </div>

          <CollapsibleSettingsCard
            icon={<Fingerprint className="w-[18px] h-[18px] text-emerald-500" strokeWidth={1.5} />}
            title="Current Credentials"
            description={currentNeedsBoth
              ? 'This archive appears to require both its current password and current 21-word keyphrase.'
              : 'Enter the current password, keyphrase, or both depending on how the archive was created.'}
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
            description="Choose the new password, keyphrase, or both for the rekeyed archive."
            summary={newCredentialSummary}
            open={showNewCredentialsPanel}
            onToggle={() => setShowNewCredentialsPanel((value) => !value)}
          >
            <div className="space-y-4">
                <div className={`rounded-[18px] border transition-all duration-300 overflow-hidden backdrop-blur-xl ${newPasswordEnabled ? 'bg-av-surface/80 border-emerald-500/35 ring-1 ring-emerald-500/15' : 'bg-av-surface/40 border-av-border/30'}`}>
                  <div className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <LockBadge />
                      <div>
                        <h4 className="text-sm font-medium text-av-main">New Password</h4>
                        <p className="text-[12px] text-av-muted">Rotate to a stronger password if needed.</p>
                      </div>
                    </div>
                    <Toggle checked={newPasswordEnabled} onClick={() => setNewPasswordEnabled((value) => !value)} />
                  </div>

                  {newPasswordEnabled && (
                    <div className="px-4 pb-4 space-y-4">
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

                      <div className="p-4 bg-container-bg border border-av-border/30 rounded-xl shadow-[inset_0_4px_15px_var(--container-bg)]">
                        <div className="flex items-center justify-between text-[10px] font-bold text-av-main opacity-80 mb-2.5 uppercase tracking-[0.15em]">
                          <span>Password Strength</span>
                          <span className={passwordStrength < 40 ? 'text-red-400' : passwordStrength < 80 ? 'text-amber-400' : 'text-emerald-400'}>
                            {passwordStrength < 40 ? 'WEAK' : passwordStrength < 80 ? 'MODERATE' : 'OPTIMAL'}
                          </span>
                        </div>
                        <div className="h-1.5 bg-av-border/40 rounded-full overflow-hidden mb-4">
                          <div
                            style={{ width: `${passwordStrength}%` }}
                            className={`h-full rounded-full transition-all duration-500 ${
                              passwordStrength < 40 ? 'bg-red-400' : passwordStrength < 80 ? 'bg-amber-400' : 'bg-emerald-400'
                            }`}
                          />
                        </div>
                        <div className="grid grid-cols-2 gap-y-2.5 text-[11px] font-medium text-av-main opacity-90 tracking-wide">
                          <RuleDot ok={hasMinLen} label="Length ≥ 12" />
                          <RuleDot ok={hasUpper} label="Uppercase" />
                          <RuleDot ok={hasLower} label="Lowercase" />
                          <RuleDot ok={hasNumber} label="Numeric" />
                          <RuleDot ok={hasSpecial} label="Symbolic Character" className="col-span-2" />
                        </div>
                      </div>
                    </div>
                  )}
                </div>

                <div className={`rounded-[18px] border transition-all duration-300 overflow-hidden backdrop-blur-xl ${newKeyphraseEnabled ? 'bg-av-surface/80 border-purple-500/35 ring-1 ring-purple-500/15' : 'bg-av-surface/40 border-av-border/30'}`}>
                  <div className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <KeyBadge />
                      <div>
                        <h4 className="text-sm font-medium text-av-main">New Keyphrase</h4>
                        <p className="text-[12px] text-av-muted">Rotate to a fresh 21-word Devanagari keyphrase.</p>
                      </div>
                    </div>
                    <Toggle checked={newKeyphraseEnabled} onClick={() => setNewKeyphraseEnabled((value) => !value)} />
                  </div>

                  {newKeyphraseEnabled && (
                    <div className="px-4 pb-4 space-y-4">
                      {!newKeyphrase ? (
                        <button onClick={handleGenerateKeyphrase} className="w-full py-3.5 rounded-xl border border-purple-500/20 bg-purple-500/10 shadow-sm hover:bg-purple-500/15 text-[13px] font-semibold transition-all duration-300 flex items-center justify-center gap-2.5 text-purple-700 dark:text-purple-300 hover:border-purple-500/40">
                          <RefreshCw className="w-4 h-4" /> Generate New Keyphrase
                        </button>
                      ) : (
                        <div className="security-keyphrase-card rounded-2xl p-4">
                          <div className="security-keyphrase-header mb-3 flex items-center justify-between pb-3 text-[10px] font-bold uppercase tracking-[0.16em]">
                            <span>New Keyphrase</span>
                            <span className="security-keyphrase-badge rounded-full px-2 py-0.5">21 Words</span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                            {newKeyphrase.split(' ').map((word, idx) => (
                              <div key={`${word}-${idx}`} className="security-keyphrase-chip flex min-w-0 overflow-hidden rounded-lg transition-colors">
                                <span className="security-keyphrase-index flex w-7 shrink-0 items-center justify-center py-1 text-[9px] font-bold tracking-wider tabular-nums">{(idx + 1).toString().padStart(2, '0')}</span>
                                <span className="min-w-0 flex-1 truncate px-2 py-1 text-[11px] font-semibold">{word}</span>
                              </div>
                            ))}
                          </div>
                          <div className="security-keyphrase-actions mt-4 flex items-center gap-3 pt-4">
                            <button onClick={handleCopyKeyphrase} className="security-keyphrase-copy flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-colors duration-300">
                              {isCopied ? <><CheckCircle2 className="w-4 h-4 text-emerald-500" /> Copied</> : <><Upload className="w-4 h-4" /> Copy</>}
                            </button>
                            <button onClick={handleGenerateKeyphrase} className="security-keyphrase-secondary rounded-lg px-4 py-2 text-xs font-semibold transition-colors duration-300">
                              Regenerate
                            </button>
                          </div>
                        </div>
                      )}

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

          <div className="shrink-0 flex flex-col gap-3 mt-auto pt-2">
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
                  : currentNeedsBoth
                    ? 'Provide both current protections, then choose the new protection set for the rotated archive.'
                    : 'Rekey keeps payload.enc unchanged and rotates only the credential-protection layer.'}
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
      <div className="p-5 flex items-start justify-between gap-4">
        <div className="flex items-start gap-4 min-w-0 flex-1">
          <div className="w-11 h-11 rounded-xl flex items-center justify-center border bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 shrink-0">
            {icon}
          </div>
          <div className="min-w-0">
            <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">{title}</h3>
            <p className="text-av-muted text-[13px] font-light leading-relaxed">{description}</p>
            <p className="mt-2 text-[11px] font-medium text-av-muted truncate">{summary}</p>
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
        <div className="px-5 pb-5">
          {children}
        </div>
      )}
    </div>
  )
}

function RuleDot({ ok, label, className = '' }: { ok: boolean; label: string; className?: string }) {
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      <div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${ok ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50'}`} />
      {label}
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
