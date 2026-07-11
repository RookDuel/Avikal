import React, { useState, useCallback, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import {
  Lock, Key, Shield, Eye, EyeOff,
  Upload, Search, Copy, RefreshCw, CheckCircle2,
  Fingerprint, ShieldAlert, File, Folder, Download, MessageSquare, BarChart3
} from 'lucide-react'
import { api } from '../lib/api'
import { parseBackendProgressChunk } from '../lib/backendProgress'
import { getErrorMessage } from '../lib/errors'
import { getDroppedPaths } from '../lib/electron'
import { toast } from 'sonner'
import { useProgress } from '../hooks/useProgress'
import FileTree, { pruneTreeByPaths, type FileNode } from '../components/FileTree'
import type { PendingExternalLaunchAction } from '../lib/externalLaunch'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'
import { getDefaultPqcStorageMode, USER_PREFERENCES_UPDATED_EVENT, type UserPreferences } from '../lib/preferences'
import ProcessingOverlay from '../components/ProcessingOverlay'
import ArchiveReportModal from '../components/ArchiveReportModal'
import { copyKeyphraseToClipboard, downloadStructuredKeyphrase } from '../lib/keyphraseExport'
import PasswordStrengthMeter from '../components/PasswordStrengthMeter'
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

type PqcStorageMode = 'embedded' | 'external'

function deriveSiblingKeyfilePath(archivePath: string): string {
  return archivePath.replace(/(\.avk)?$/i, '.avkkey')
}

interface EncryptProps {
  externalLaunchAction?: PendingExternalLaunchAction | null
}

export default function Encrypt({ externalLaunchAction }: EncryptProps) {
  const [files, setFiles] = useState<string[]>([])
  const [treeNodes, setTreeNodes] = useState<FileNode[]>([])
  const [selectedTreePaths, setSelectedTreePaths] = useState<Set<string>>(() => new Set())
  const [excludedInputPaths, setExcludedInputPaths] = useState<string[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const [passwordEnabled, setPasswordEnabled] = useState(true)
  const [keyphraseEnabled, setKeyphraseEnabled] = useState(false)

  const [password, setPassword] = useState('')
  const [keyphrase, setKeyphrase] = useState('')
  const [loading, setLoading] = useState(false)
  const [isEncrypted, setIsEncrypted] = useState(false)
  const [outputFilePath, setOutputFilePath] = useState('')
  const [createdPqcKeyfilePath, setCreatedPqcKeyfilePath] = useState('')
  const [createdPqcStorageMode, setCreatedPqcStorageMode] = useState<PqcStorageMode>(() => getDefaultPqcStorageMode())
  const [searchQuery, setSearchQuery] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [pqcEnabled, setPqcEnabled] = useState(false)
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
  const [isCopied, setIsCopied] = useState(false)
  const filesRef = useRef<string[]>([])
  const backendRuntime = useBackendRuntime()

  const normalizeUiPath = (value: string) => value.replace(/\\/g, '/').replace(/\/+$/, '').toLowerCase()
  const isSameOrChildPath = (candidate: string, parent: string) => {
    const candidatePath = normalizeUiPath(candidate)
    const parentPath = normalizeUiPath(parent)
    return candidatePath === parentPath || candidatePath.startsWith(`${parentPath}/`)
  }

  const resetProtectionPanel = useCallback(() => {
    setPassword('')
    setKeyphrase('')
    setShowPassword(false)
    setIsCopied(false)
    setPasswordEnabled(true)
    setKeyphraseEnabled(false)
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
      setCreatorIdentities((result.identities || []).map(item => ({
        identity_id: String(item.identity_id || ''),
        label: String(item.label || 'Creator identity'),
      })).filter(item => /^[0-9a-f]{64}$/.test(item.identity_id)))
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
    const applyDefault = (mode: PqcStorageMode) => {
      setPqcStorageMode(current => pqcModeOverridden ? current : mode)
    }

    const onPreferencesUpdated = (event: Event) => {
      const detail = (event as CustomEvent<UserPreferences>).detail
      const mode = detail?.archive_defaults?.pqc_storage_mode
      if (mode === 'embedded' || mode === 'external') applyDefault(mode)
    }

    const onFocus = () => applyDefault(getDefaultPqcStorageMode())

    window.addEventListener(USER_PREFERENCES_UPDATED_EVENT, onPreferencesUpdated)
    window.addEventListener('focus', onFocus)
    return () => {
      window.removeEventListener(USER_PREFERENCES_UPDATED_EVENT, onPreferencesUpdated)
      window.removeEventListener('focus', onFocus)
    }
  }, [pqcModeOverridden])

  useEffect(() => {
    const unsubscribe = window.electron?.onBackendLog?.((message) => {
      if (!loading && progress.status !== 'running') return
      for (const event of parseBackendProgressChunk(message)) {
        if (event.operation !== 'encrypt') continue
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

  const isBoth = passwordEnabled && keyphraseEnabled
  const isTrioProtection = isBoth && pqcEnabled
  const usePass = passwordEnabled
  const useKeyp = keyphraseEnabled
  const hasSecretLock = usePass || useKeyp

  // Validation
  const hasMinLen = password.length >= 12
  const hasUpper = /[A-Z]/.test(password)
  const hasLower = /[a-z]/.test(password)
  const hasNumber = /[0-9]/.test(password)
  const hasSpecial = /[^A-Za-z0-9]/.test(password)
  const isValidPassword = hasMinLen && hasUpper && hasLower && hasNumber && hasSpecial
  const needsPqcKeyfilePassword = pqcEnabled && pqcStorageMode === 'external' && pqcKeyfilePasswordEnabled
  const isValidPqcKeyfilePassword =
    !needsPqcKeyfilePassword ||
    (
      pqcKeyfilePassword.length >= 12 &&
      /[A-Z]/.test(pqcKeyfilePassword) &&
      /[a-z]/.test(pqcKeyfilePassword) &&
      /[0-9]/.test(pqcKeyfilePassword) &&
      /[^A-Za-z0-9]/.test(pqcKeyfilePassword) &&
      (!usePass || pqcKeyfilePassword !== password)
    )

  const pqcKeyfilePasswordIssue =
    pqcKeyfilePassword && usePass && pqcKeyfilePassword === password
      ? 'Must be different from archive password.'
      : ''

  const handleDragOver = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(true) }, [])
  const handleDragLeave = useCallback((e: React.DragEvent) => { e.preventDefault(); setIsDragging(false) }, [])

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
      // Fallback: add as a simple file node
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
    if (externalLaunchAction?.target !== 'encrypt') {
      return
    }

    addPathsToSelection(externalLaunchAction.paths)
  }, [addPathsToSelection, externalLaunchAction])

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault(); setIsDragging(false)
    const dropped = getDroppedPaths(e.dataTransfer.files)
    const newPaths = dropped.filter(f => !files.includes(f))
    if (dropped.length - newPaths.length > 0) toast.error(`${dropped.length - newPaths.length} duplicate(s) skipped`)
    addPathsToSelection(newPaths)
  }, [addPathsToSelection, files])

  // Browse FILES only (Windows-safe: openFile shows files)
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

  // Browse FOLDERS only (Windows-safe: openDirectory shows folders)
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

  const handleGenerateKeyphrase = async () => {
    try {
      const result = await api.generateKeyphrase(21)
      if (result.success) {
        setKeyphrase(result.keyphrase)
        toast.success('Keyphrase generated!')
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
    const saved = await downloadStructuredKeyphrase(keyphrase, 'Encode archive recovery keyphrase')
    if (saved) toast.success('Keyphrase document saved')
  }

  const keyphraseWordCount = keyphrase.trim().split(/\s+/).filter(Boolean).length
  const senderMessageWordCount = senderMessage.trim().split(/\s+/).filter(Boolean).length
  const senderMessageByteCount = new TextEncoder().encode(senderMessage).length
  const isSenderMessageValid = !senderMessageEnabled || (
    hasSecretLock && senderMessageWordCount > 0 && senderMessageWordCount <= 100 && senderMessageByteCount <= 1024
  )
  const canEncrypt = backendRuntime.isReady && files.length > 0 && !loading &&
    (!pqcEnabled || hasSecretLock) &&
    (!usePass || isValidPassword) &&
    (!useKeyp || keyphraseWordCount === 21) &&
    isValidPqcKeyfilePassword && isSenderMessageValid

  const handleEncrypt = async () => {
    if (!canEncrypt) return
    const electron = window.electron
    const outputFile = await electron?.saveFile({
      defaultPath: `encrypted_archive_${new Date().toISOString().split('T')[0]}.avk`,
      filters: [{ name: 'RookDuel Avikal File', extensions: ['avk'] }]
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

    try {
      setLoading(true)
      setIsEncrypted(false)
      setOutputFilePath(outputFile)
      setCreatedPqcKeyfilePath('')
      setCreatedPqcStorageMode(pqcStorageMode)
      setCreationReport(null)
      progress.reset()
      progress.update({ status: 'running', currentOperation: 'Initializing Encryption Engine...', percentage: 0 })

      const result = await api.encrypt({
        input_files: files,
        excluded_input_paths: excludedInputPaths.length > 0 ? excludedInputPaths : undefined,
        output_file: outputFile,
        password: usePass ? password : undefined,
        keyphrase: useKeyp ? keyphrase.trim().split(/\s+/).filter(Boolean) : undefined,
        use_timecapsule: false,
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
      })

      setCreatedPqcKeyfilePath(result?.result?.pqc?.keyfile || nextPqcKeyfilePath || '')
      setIsEncrypted(true)
      setCreationReport((result?.result?.creation_report as Record<string, unknown> | undefined) || null)
      progress.update({ status: 'completed', currentOperation: 'Encryption complete', percentage: 100 })
      if (!hasSecretLock) {
        toast.success('Unencrypted archive created. Integrity signatures remain enabled.')
      } else {
        toast.success(
          pqcEnabled
            ? pqcStorageMode === 'embedded'
              ? 'Protected archive created with embedded quantum protection.'
              : 'Protected archive created and PQC keyfile saved.'
            : 'Protected archive created successfully.',
        )
      }
      resetProtectionPanel()
    } catch (error: unknown) {
      progress.update({ status: 'error', currentOperation: 'Encryption failed', percentage: progress.percentage || 0 })
      toast.error(getErrorMessage(error, 'Encryption failed'))
    } finally {
      setPassword('')
      setKeyphrase('')
      setPqcKeyfilePassword('')
      setLoading(false)
    }
  }

  return (
    <div className="av-page-shell">

      {/* 60/40 Split Architecture */}
      <div className="av-work-grid">

        {/* â”€â”€ Left Panel: File Staging (60%) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <div className="av-primary-panel lg:col-span-3 flex flex-col overflow-hidden relative">

          <div className="av-panel-header z-10 shrink-0">
            <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
              Create Archive <span className="font-light text-av-muted">Package Files</span>
            </h2>
            <p className="text-av-muted text-sm font-light">Package files with optional password, keyphrase, and PQC protection.</p>
          </div>

          <div
            className="av-left-workspace flex-1 flex flex-col relative overflow-hidden"
            onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
          >
            {loading && !isEncrypted && (
              <ProcessingOverlay
                title="Creating Archive"
                description={progress.currentOperation || 'Preparing archive...'}
                icon={<Shield className="h-5 w-5 text-av-accent" strokeWidth={1.7} />}
                percentage={progress.percentage}
                etaSeconds={progress.etaSeconds}
                elapsedSeconds={progress.elapsedSeconds}
                fileSize={progress.fileSize}
                indeterminateText="Building protected archive"
              />
            )}

            {isEncrypted && (
              <div className="av-processing-overlay absolute inset-0 z-20 flex flex-col items-center justify-center p-8">
                <div className="av-result-card w-full max-w-lg rounded-[24px] p-10 flex flex-col items-center text-center">
                  <div className="relative mb-8">
                    <div className="absolute inset-0 bg-emerald-500/20 rounded-full blur-2xl" />
                    <div className="w-20 h-20 rounded-full bg-emerald-500/10 flex items-center justify-center border border-emerald-500/30 relative z-10 shadow-inner">
                      <CheckCircle2 className="w-10 h-10 text-emerald-500" strokeWidth={1.5} />
                    </div>
                  </div>
                  <h3 className="text-[22px] font-medium text-av-main mb-3 tracking-tight">Archive Created</h3>
                  <p className="text-sm text-av-muted font-light mb-8">Your archive has been created and stored locally.</p>

                  <div className="w-full p-4 rounded-xl bg-av-border/10 dark:bg-white/5 border border-av-border/40 flex items-center gap-4 transition-all shadow-inner">
                    <div className="w-10 h-10 rounded-lg bg-av-surface shadow-sm border border-av-border/50 flex items-center justify-center shrink-0">
                      <Shield className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
                    </div>
                    <div className="text-left truncate flex-1">
                      <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-1">Local Destination</p>
                      <p className="text-sm font-medium text-av-main truncate">{outputFilePath}</p>
                    </div>
                  </div>

                  {createdPqcStorageMode === 'embedded' && pqcEnabled && !createdPqcKeyfilePath && (
                    <div className="w-full mt-4 p-4 rounded-xl bg-emerald-500/5 border border-emerald-500/20 flex items-center gap-4 transition-all shadow-inner">
                      <div className="w-10 h-10 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
                        <Fingerprint className="w-5 h-5 text-emerald-500" strokeWidth={1.5} />
                      </div>
                      <div className="text-left truncate flex-1">
                        <p className="text-[10px] font-semibold text-emerald-500 uppercase tracking-[0.2em] mb-1">Embedded Quantum Protection</p>
                        <p className="text-sm font-medium text-av-main truncate">Stored inside the .avk archive</p>
                        <p className="text-[11px] text-av-muted mt-1">The archive still requires the correct password or keyphrase before quantum unlock can continue.</p>
                      </div>
                    </div>
                  )}

                  {createdPqcKeyfilePath && (
                    <div className="w-full mt-4 p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 flex items-center gap-4 transition-all shadow-inner">
                      <div className="w-10 h-10 rounded-lg bg-amber-500/10 border border-amber-500/20 flex items-center justify-center shrink-0">
                        <Fingerprint className="w-5 h-5 text-amber-500" strokeWidth={1.5} />
                      </div>
                      <div className="text-left truncate flex-1">
                        <p className="text-[10px] font-semibold text-amber-500 uppercase tracking-[0.2em] mb-1">Quantum Keyfile</p>
                        <p className="text-sm font-medium text-av-main truncate">{createdPqcKeyfilePath}</p>
                        <p className="text-[11px] text-av-muted mt-1">Store this `.avkkey` separately. Without it, decryption is impossible.</p>
                      </div>
                    </div>
                  )}

                  {creationReport && (
                    <button
                      type="button"
                      onClick={() => setShowCreationReport(true)}
                      className="mt-4 flex w-full items-center justify-center gap-2 rounded-xl border border-av-border/50 bg-av-surface/70 px-4 py-3 text-sm font-semibold text-av-main transition hover:border-av-accent/50"
                    >
                      <BarChart3 className="h-4 w-4" />
                      View detailed report
                    </button>
                  )}

                  <button onClick={() => {
                    setIsEncrypted(false)
                    setFiles([])
                    setTreeNodes([])
                    setSelectedTreePaths(new Set())
                    setExcludedInputPaths([])
                    setPqcEnabled(false)
                    setPqcStorageMode('embedded')
                    setPqcKeyfilePath('')
                    setCreatedPqcKeyfilePath('')
                    setPasswordEnabled(true)
                    setKeyphraseEnabled(false)
                    setCreationReport(null)
                    setShowCreationReport(false)
                  }} className="mt-10 w-full py-4 rounded-xl bg-av-main text-av-surface font-medium hover:opacity-90 shadow-lg transition-all">
                    Acknowledge & Close
                  </button>
                </div>
              </div>
            )}

            {!loading && !isEncrypted && (
              files.length === 0 ? (
                <div className="flex-1 p-8 flex flex-col relative">
                  <div
                    className={`av-drop-zone flex-1 rounded-[20px] flex flex-col items-center justify-center transition-all duration-300 relative overflow-hidden group ${isDragging ? 'av-drop-zone-active' : 'text-av-muted'
                      }`}
                  >
                    <div className="pointer-events-none absolute inset-0 opacity-0" />

                    <div className={`z-10 flex flex-col items-center transition-transform duration-300 ease-out ${isDragging ? '-translate-y-2 scale-105' : ''}`}>
                      <div className="relative mb-6">
                        <div className="absolute inset-0 rounded-2xl bg-av-border/10" />
                        <div className="w-20 h-20 rounded-2xl bg-av-surface/80 flex items-center justify-center border border-av-border/30 shadow-[0_4px_20px_rgba(0,0,0,0.05)] text-av-main relative z-10 transition-transform duration-300">
                          <Upload className="w-8 h-8 text-av-muted" strokeWidth={1.25} />
                        </div>
                      </div>
                      <h3 className="text-xl font-medium text-av-main mb-2 tracking-tight">
                        {isDragging ? 'Drop targets to ingest' : 'Select files to protect'}
                      </h3>
                      <p className="text-sm font-light text-av-muted mb-6">Drag & drop, or use the buttons below</p>
                      <div className="flex items-center gap-3">
                        <button
                          onClick={handleBrowseFiles}
                          className="flex items-center gap-2 text-xs bg-av-main text-av-surface font-semibold px-5 py-2.5 rounded-xl transition-all shadow-[0_2px_12px_rgba(0,0,0,0.15)] hover:opacity-90 hover:-translate-y-0.5 active:scale-95"
                        >
                          <File className="w-3.5 h-3.5" /> Add Files
                        </button>
                        <button
                          onClick={handleBrowseFolders}
                          className="flex items-center gap-2 text-xs bg-av-surface/80 border border-av-border/60 text-av-main font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:border-av-border hover:-translate-y-0.5 active:scale-95"
                        >
                          <Folder className="w-3.5 h-3.5 text-av-muted" /> Add Folders
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col relative overflow-hidden">

                  {/* Toolbar */}
                  <div className="av-explorer-toolbar px-6 py-4 flex items-center justify-between shrink-0">
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-sm font-medium text-av-main tracking-tight">Explorer</span>
                      <span className="bg-av-border/15 border border-av-main/20 text-av-main text-[11px] font-semibold px-2.5 py-0.5 rounded-md">{files.length}</span>
                    </div>
                    <div className="flex-1 max-w-[200px] mx-4">
                      <div className="relative group">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-av-muted group-focus-within:text-av-main transition-colors" />
                        <input type="text" placeholder="Filter..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="w-full pl-8 pr-3 py-1.5 bg-av-surface/50 border border-av-border/50 rounded-lg text-xs focus:outline-none focus:border-av-border focus:ring-1 focus:ring-av-border/20 transition-all text-av-main shadow-inner placeholder:font-light" />
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={handleBrowseFiles} className="flex items-center gap-1.5 text-[11px] bg-av-surface/60 border border-av-border/50 text-av-muted hover:text-av-main hover:border-av-border font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                        <File className="w-3 h-3" /> Files
                      </button>
                      <button onClick={handleBrowseFolders} className="flex items-center gap-1.5 text-[11px] bg-av-surface/60 border border-av-border/50 text-av-muted hover:text-av-main hover:border-av-border font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
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

        {/* â”€â”€ Right Panel: Security Architecture (40%) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€ */}
        <div className={`av-side-stack av-natural-side-stack lg:col-span-2 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>

          <div className="px-2 mb-1">
            <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Encryption Settings</h3>
          </div>

          {/* Module: Standard Container */}
          <div
            onClick={() => { setPasswordEnabled(false); setKeyphraseEnabled(false) }}
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${!hasSecretLock ? 'bg-av-surface/80 border-blue-500 shadow-[0_8px_30px_rgba(0,0,0,0.08)] ring-1 ring-blue-500/20' : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
              }`}
          >
            {!hasSecretLock && <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent pointer-events-none" />}
            <div className="p-5 flex items-center justify-between relative z-10">
              <div className="flex items-center gap-4">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-all duration-300 ${!hasSecretLock ? 'bg-blue-500/10 border-blue-500/30 shadow-inner' : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'}`}>
                  <Shield className={`w-[18px] h-[18px] ${!hasSecretLock ? 'text-blue-500' : 'text-av-muted'}`} strokeWidth={1.5} />
                </div>
                <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Unencrypted Archive</h3>
                  <p className="text-av-muted text-[13px] font-light">No confidentiality; integrity signatures only</p>
                </div>
              </div>
              <div className="flex items-center gap-2 pr-1">
                <button
                  onClick={(e) => { e.stopPropagation(); setPasswordEnabled(false); setKeyphraseEnabled(false) }}
                  className={`relative w-11 h-6 rounded-full transition-all duration-300 border shadow-inner ${!hasSecretLock ? 'bg-blue-500 border-blue-500 shadow-[inset_0_2px_4px_rgba(0,0,0,0.2)]' : 'bg-av-border/20 dark:bg-white/10 border-av-border/30 dark:border-white/10'}`}
                >
                  <span className={`absolute top-[1px] left-[1px] w-5 h-5 rounded-full bg-white shadow-[0_2px_5px_rgba(0,0,0,0.2)] transition-transform duration-300 ${!hasSecretLock ? 'translate-x-[20px]' : ''}`} />
                </button>
              </div>
            </div>
          </div>

          {/* Module: Password */}
          <div
            onClick={() => setPasswordEnabled(value => !value)}
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${passwordEnabled
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
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Access Password</h3>
                  <p className="text-av-muted text-[13px] font-light">Require a strong password to unlock the archive</p>
                </div>
              </div>
              <div className="flex items-center gap-2 pr-1">
                <button
                  onClick={(e) => { e.stopPropagation(); setPasswordEnabled(value => !value) }}
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
                    placeholder="Enter your access password"
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

          {/* Module: Keyphrase */}
          <div
            onClick={() => setKeyphraseEnabled(value => !value)}
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden relative group ${keyphraseEnabled
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
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Security Keyphrase</h3>
                  <p className="text-av-muted text-[13px] font-light">Add a generated 21-word recovery keyphrase</p>
                </div>
              </div>
              <div className="flex items-center gap-2 pr-1">
                <button
                  onClick={(e) => { e.stopPropagation(); setKeyphraseEnabled(value => !value) }}
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
                    <RefreshCw className="w-4 h-4" /> Generate Security Keyphrase
                  </button>
                ) : (
                  <div className="security-keyphrase-card rounded-2xl p-4">
                    <div className="security-keyphrase-header mb-3 flex items-center justify-between pb-3 text-[10px] font-bold uppercase tracking-[0.16em]">
                      <span>Keyphrase Generation</span>
                      <span className="security-keyphrase-badge rounded-full px-2 py-0.5">21 Words</span>
                    </div>
                    <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                      {keyphrase.split(' ').map((word, idx) => (
                        <div key={idx} className="security-keyphrase-chip flex min-w-0 overflow-hidden rounded-lg transition-colors">
                          <span className="security-keyphrase-index flex w-7 shrink-0 items-center justify-center py-1 text-[9px] font-bold tracking-wider tabular-nums">{(idx + 1).toString().padStart(2, '0')}</span>
                          <span className="min-w-0 flex-1 truncate px-2 py-1 text-[11px] font-semibold">{word}</span>
                        </div>
                      ))}
                    </div>
                    <div className="security-keyphrase-actions mt-4 flex flex-col gap-2 pt-4 sm:flex-row sm:items-center sm:gap-3">
                      <button onClick={handleCopyKeyphrase} className="security-keyphrase-copy flex flex-1 items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-colors duration-300">
                        {isCopied ? <><CheckCircle2 className="w-4 h-4 text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]" /> Copied</> : <><Copy className="w-4 h-4" /> Copy</>}
                      </button>
                      <button onClick={handleDownloadKeyphrase} className="security-keyphrase-secondary flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2 text-xs font-semibold transition-colors duration-300">
                        <Download className="w-4 h-4" /> Download
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

          <div
            onClick={() => setPqcEnabled(value => !value)}
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
              <div className="flex items-center gap-2 pr-1">
                <button
                  onClick={(e) => { e.stopPropagation(); setPqcEnabled(value => !value) }}
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
                        <p className="mt-1 text-[11px] text-av-muted">Single archive file</p>
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

            {showCreationReport && creationReport && <ArchiveReportModal report={creationReport} title="Archive creation report" onClose={() => { setShowCreationReport(false); setCreationReport(null) }} />}
          </div>

          <div className="rounded-2xl border border-av-border/40 bg-av-surface/65 p-4">
            <div className="flex items-center justify-between gap-4">
              <div className="flex items-center gap-3"><MessageSquare className="h-4 w-4 text-av-muted" /><div><p className="text-sm font-semibold text-av-main">Sender message</p><p className="text-[11px] text-av-muted">Encrypted inside the Chess-PGN keychain</p></div></div>
              <button type="button" onClick={() => { setSenderMessageEnabled(value => !value); if (senderMessageEnabled) setSenderMessage('') }} disabled={!hasSecretLock} className={`relative h-6 w-11 rounded-full border transition ${senderMessageEnabled ? 'border-av-accent bg-av-accent' : 'border-av-border/50 bg-av-border/20'} disabled:opacity-40`}><span className={`absolute left-[1px] top-[1px] h-5 w-5 rounded-full bg-white shadow transition-transform ${senderMessageEnabled ? 'translate-x-5' : ''}`} /></button>
            </div>
            {senderMessageEnabled && (
              <div className="mt-3">
                <textarea value={senderMessage} onChange={event => setSenderMessage(event.target.value)} rows={3} maxLength={1024} className="w-full resize-none rounded-xl border border-av-border/40 bg-av-border/10 px-3 py-2 text-sm text-av-main outline-none focus:border-av-accent" placeholder="Add recovery context for the recipient..." />
                <div className="mt-1 flex justify-between text-[10px] text-av-muted"><span>{senderMessageWordCount}/100 words</span><span>{senderMessageByteCount}/1024 bytes</span></div>
              </div>
            )}
            {creatorIdentities.length > 0 && (
              <label className="mt-3 block text-[11px] font-medium text-av-muted">Creator signature identity<select value={creatorIdentityId} onChange={event => setCreatorIdentityId(event.target.value)} className="mt-1 w-full rounded-xl border border-av-border/40 bg-av-surface px-3 py-2 text-sm text-av-main"><option value="">Per-archive identity</option>{creatorIdentities.map(identity => <option key={identity.identity_id} value={identity.identity_id}>{identity.label}</option>)}</select></label>
            )}
          </div>

          {/* Execution Block */}
          <div className="shrink-0 flex flex-col gap-3 pt-2">

            {/* Multi-layer High-Protect Warning */}
            {isBoth && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-4 rounded-[16px] bg-red-500/10 border border-red-500/30 flex items-start gap-3 shadow-inner mb-2">
                <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                <div>
                  <p className="text-[13px] font-bold text-red-500 uppercase tracking-wide mb-1 drop-shadow-[0_0_8px_rgba(239,68,68,0.3)]">
                    {isTrioProtection ? 'Trio High Protection Enabled' : 'Dual High Protection Enabled'}
                  </p>
                  <p className="text-xs text-red-400/90 font-medium leading-relaxed">
                    {isTrioProtection
                      ? 'This archive will require password, 21-word keyphrase, and PQC material during unlock. Store every required secret carefully before you continue.'
                      : 'This archive will require both the access password and the 21-word keyphrase during unlock. Keep both stored safely before you continue.'}
                  </p>
                </div>
              </motion.div>
            )}

            <BackendStartupNotice backend={backendRuntime} compact />

            <button
              onClick={handleEncrypt}
              disabled={!canEncrypt}
              className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${!canEncrypt ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner' : 'bg-av-main hover:opacity-90 text-av-surface shadow-[0_10px_30px_rgba(0,0,0,0.15)] hover:shadow-[0_10px_40px_rgba(0,0,0,0.2)] hover:-translate-y-0.5'
                }`}
            >
              <Shield className="w-5 h-5" />
              {loading
                ? 'Creating Archive...'
                : !backendRuntime.isReady
                  ? 'Starting Secure Engine...'
                  : !hasSecretLock
                    ? 'Create Archive'
                    : 'Create Protected Archive'}
            </button>

            <p className="text-center text-[11px] text-av-muted mt-1 font-light">
              {!backendRuntime.isReady
                ? backendRuntime.detail
                : !hasSecretLock
                ? 'This archive is not encrypted. Signatures detect modification but do not hide its contents.'
                : isBoth
                ? 'Both the password and the 21-word keyphrase will be required during unlock.'
                : usePass
                ? 'A strong password will be required during unlock.'
                : useKeyp
                ? 'The 21-word keyphrase will be required during unlock.'
                : hasSecretLock
                ? 'Protected archive mode enabled.'
                : 'Choose how you want this archive to unlock.'}
            </p>
          </div>
        </div>
      </div>
    </div>
  )
}


