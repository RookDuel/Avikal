import React, { useState, useCallback, useEffect, useRef } from 'react'
import { motion } from 'framer-motion'
import {
  Lock, Key, Shield, Eye, EyeOff,
  Upload, Search, Copy, RefreshCw, CheckCircle2, Download,
  Fingerprint, ShieldAlert, File, Folder
} from 'lucide-react'
import { api } from '../lib/api'
import { formatEta, parseBackendProgressChunk } from '../lib/backendProgress'
import { getErrorMessage } from '../lib/errors'
import { getDroppedPaths } from '../lib/electron'
import { toast } from 'sonner'
import { useProgress } from '../hooks/useProgress'
import FileTree, { type FileNode } from '../components/FileTree'
import type { PendingExternalLaunchAction } from '../lib/externalLaunch'

function deriveSiblingKeyfilePath(archivePath: string): string {
  return archivePath.replace(/(\.avk)?$/i, '.avkkey')
}

function deriveDefaultKeyfileName(files: string[]): string {
  const first = files[0]?.split(/[/\\]/).pop() || 'avikal-archive'
  const base = first.replace(/\.[^.]+$/, '')
  return `${base || 'avikal-archive'}.avkkey`
}

interface EncryptProps {
  externalLaunchAction?: PendingExternalLaunchAction | null
}

export default function Encrypt({ externalLaunchAction }: EncryptProps) {
  const [files, setFiles] = useState<string[]>([])
  const [treeNodes, setTreeNodes] = useState<FileNode[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const [passwordEnabled, setPasswordEnabled] = useState(true)
  const [keyphraseEnabled, setKeyphraseEnabled] = useState(false)

  const [password, setPassword] = useState('')
  const [keyphrase, setKeyphrase] = useState('')
  const [loading, setLoading] = useState(false)
  const [isEncrypted, setIsEncrypted] = useState(false)
  const [outputFilePath, setOutputFilePath] = useState('')
  const [createdPqcKeyfilePath, setCreatedPqcKeyfilePath] = useState('')
  const [searchQuery, setSearchQuery] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [pqcEnabled, setPqcEnabled] = useState(false)
  const [pqcKeyfilePath, setPqcKeyfilePath] = useState('')
  const progress = useProgress()
  const [isCopied, setIsCopied] = useState(false)
  const filesRef = useRef<string[]>([])

  useEffect(() => {
    filesRef.current = files
  }, [files])

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
        })
      }
    })
    return () => {
      unsubscribe?.()
    }
  }, [loading, progress.status, progress.update])

  const isBoth = passwordEnabled && keyphraseEnabled
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

  const getStrength = (pass: string) => {
    if (!pass) return 0
    let s = 0
    if (pass.length > 8) s += 25
    if (pass.length > 11) s += 25
    if (/[A-Z]/.test(pass)) s += 15
    if (/[0-9]/.test(pass)) s += 15
    if (/[^A-Za-z0-9]/.test(pass)) s += 20
    return Math.min(100, s)
  }
  const strength = getStrength(password)
  const strengthColor = strength < 40 ? 'bg-red-400' : strength < 80 ? 'bg-amber-400' : 'bg-emerald-400'
  const strengthLabel = strength < 40 ? 'WEAK' : strength < 80 ? 'MODERATE' : 'OPTIMAL'
  const strengthLabelColor = strength < 40 ? 'text-red-400' : strength < 80 ? 'text-amber-400' : 'text-emerald-400'

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
    if (newPaths.length > 0) {
      setFiles(prev => [...prev, ...newPaths])
      newPaths.forEach(p => {
        void scanAndAddPath(p)
      })
    }
  }, [files])

  // Browse FILES only (Windows-safe: openFile shows files)
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

  // Browse FOLDERS only (Windows-safe: openDirectory shows folders)
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

  const handleGenerateKeyphrase = async () => {
    try {
      const result = await api.generateKeyphrase(21)
      if (result.success) {
        setKeyphrase(result.keyphrase)
        toast.success('Keyphrase generated!')
      }
    } catch { toast.error('Failed to generate keyphrase') }
  }

  const handleCopyKeyphrase = () => {
    if (!keyphrase) return
    navigator.clipboard.writeText(keyphrase)
    setIsCopied(true)
    setTimeout(() => setIsCopied(false), 2000)
  }

  const handleDownloadKeyphrase = async () => {
    if (!keyphrase) return

    try {
      const electron = window.electron

      if (electron?.saveFile && electron.writeFile) {
        const selected = await electron.saveFile({
          defaultPath: 'avikal-keyphrase.txt',
          filters: [{ name: 'Text Files', extensions: ['txt'] }]
        })

        if (!selected) return

        const saved = await electron.writeFile(selected, `${keyphrase.trim()}\n`)
        if (!saved) throw new Error('Failed to save keyphrase file')

        toast.success('Keyphrase saved as .txt')
        return
      }

      const blob = new Blob([`${keyphrase.trim()}\n`], { type: 'text/plain;charset=utf-8' })
      const url = URL.createObjectURL(blob)
      const anchor = document.createElement('a')
      anchor.href = url
      anchor.download = 'avikal-keyphrase.txt'
      anchor.click()
      URL.revokeObjectURL(url)
      toast.success('Keyphrase download started')
    } catch {
      toast.error('Failed to download keyphrase')
    }
  }

  const handleChoosePqcKeyfile = async () => {
    const electron = window.electron
    const selected = await electron?.saveFile({
      defaultPath: pqcKeyfilePath || deriveDefaultKeyfileName(files),
      filters: [{ name: 'RookDuel Avikal PQC Keyfile', extensions: ['avkkey'] }]
    })
    if (selected) setPqcKeyfilePath(selected)
  }

  const keyphraseWordCount = keyphrase.trim().split(/\s+/).filter(Boolean).length
  const canEncrypt = files.length > 0 && !loading &&
    (!pqcEnabled || hasSecretLock) &&
    (!usePass || isValidPassword) &&
    (!useKeyp || keyphraseWordCount === 21)

  const handleEncrypt = async () => {
    if (!canEncrypt) return
    const electron = window.electron
    const outputFile = await electron?.saveFile({
      defaultPath: `encrypted_archive_${new Date().toISOString().split('T')[0]}.avk`,
      filters: [{ name: 'RookDuel Avikal File', extensions: ['avk'] }]
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

    try {
      setLoading(true)
      setIsEncrypted(false)
      setOutputFilePath(outputFile)
      setCreatedPqcKeyfilePath('')
      progress.reset()
      progress.update({ status: 'running', currentOperation: 'Initializing Encryption Engine...', percentage: 0 })

      const result = await api.encrypt({
        input_files: files,
        output_file: outputFile,
        password: usePass ? password : undefined,
        keyphrase: useKeyp ? keyphrase.trim().split(/\s+/).filter(Boolean) : undefined,
        use_timecapsule: false,
        pqc_enabled: pqcEnabled,
        pqc_keyfile_output: pqcEnabled ? nextPqcKeyfilePath : undefined,
      })

      setCreatedPqcKeyfilePath(result?.result?.pqc?.keyfile || nextPqcKeyfilePath || '')
      setIsEncrypted(true)
      progress.update({ status: 'completed', currentOperation: 'Encryption complete', percentage: 100 })
      if (!hasSecretLock) {
        toast.success('Archive created without password or keyphrase protection.')
      } else {
        toast.success(pqcEnabled ? 'Protected archive created and PQC keyfile saved.' : 'Protected archive created successfully.')
      }
      setPassword('')
      setKeyphrase('')
      setPasswordEnabled(true)
      setKeyphraseEnabled(false)
    } catch (error: unknown) {
      progress.update({ status: 'error', currentOperation: 'Encryption failed', percentage: progress.percentage || 0 })
      toast.error(getErrorMessage(error, 'Encryption failed'))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-full w-full max-w-[1600px] mx-auto p-6 lg:p-10 box-border">

      {/* 60/40 Split Architecture */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-8">

        {/* ── Left Panel: File Staging (60%) ─────────────────────────────────────── */}
        <div className="lg:col-span-3 min-h-[550px] bg-av-surface/60 backdrop-blur-3xl rounded-[24px] shadow-[0_8px_40px_rgba(0,0,0,0.06)] border border-av-border/30 flex flex-col overflow-hidden relative transition-colors duration-300">

          <div className="px-8 py-7 border-b border-av-border/30 bg-gradient-to-b from-av-surface/80 to-av-surface/40 z-10 shrink-0">
            <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
              Create Archive <span className="font-light text-av-muted">Package Files</span>
            </h2>
            <p className="text-av-muted text-sm font-light">Package files with optional password, keyphrase, and PQC protection.</p>
          </div>

          <div
            className="flex-1 flex flex-col relative overflow-hidden bg-av-border/10 dark:bg-white/[0.01]"
            onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}
          >
            {loading && !isEncrypted && (
              <div className="absolute inset-0 z-20 bg-av-surface/80 backdrop-blur-xl flex flex-col items-center justify-center p-8">
                <div className="w-full max-w-md rounded-3xl bg-av-surface/90 border border-av-border/40 p-8 shadow-[0_20px_60px_rgba(0,0,0,0.12)]">
                  <div className="flex items-center gap-3 mb-5">
                    <div className="p-3 rounded-2xl bg-av-accent/10 border border-av-accent/30">
                      <RefreshCw className="w-6 h-6 text-av-accent" strokeWidth={1.5} />
                    </div>
                    <div>
                      <h3 className="text-xl font-medium tracking-tight text-av-main">Creating Archive</h3>
                      <p className="text-sm text-av-muted font-light">{progress.currentOperation || 'Preparing archive...'}</p>
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
                      />
                    ) : (
                      <motion.div
                        className="h-full w-1/3 rounded-full bg-gradient-to-r from-transparent via-av-accent to-transparent"
                        animate={{ x: ['0%', '300%'] }}
                        transition={{ duration: 1.4, repeat: Infinity, ease: 'easeInOut' }}
                      />
                    )}
                  </div>
                  <div className="mt-4 flex items-center justify-between text-xs text-av-muted">
                    <span>Elapsed {progress.elapsedSeconds}s</span>
                    {progress.fileSize !== null && <span>{Math.round(progress.fileSize / (1024 * 1024))} MB source</span>}
                  </div>
                </div>
              </div>
            )}

            {isEncrypted && (
              <div className="absolute inset-0 z-20 bg-av-surface/80 backdrop-blur-xl flex flex-col items-center justify-center p-8">
                <div className="w-full max-w-lg p-10 rounded-[24px] bg-av-surface/90 backdrop-blur-2xl border border-emerald-500/20 shadow-[0_20px_60px_rgba(16,185,129,0.1)] flex flex-col items-center text-center">
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

                  <button onClick={() => {
                    setIsEncrypted(false)
                    setFiles([])
                    setTreeNodes([])
                    setPqcEnabled(false)
                    setPqcKeyfilePath('')
                    setCreatedPqcKeyfilePath('')
                    setPasswordEnabled(true)
                    setKeyphraseEnabled(false)
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
                    className={`flex-1 rounded-[20px] border-[1.5px] border-dashed flex flex-col items-center justify-center transition-all duration-300 relative overflow-hidden group ${isDragging ? 'border-av-accent bg-av-accent/5' : 'border-av-border/60 bg-av-surface/20 hover:border-av-accent/40 hover:bg-av-surface/40 text-av-muted'
                      }`}
                  >
                    <div className="absolute inset-0 bg-gradient-to-b from-transparent to-av-border/15 dark:to-white/5 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-500" />

                    <div className={`z-10 flex flex-col items-center transition-transform duration-300 ease-out ${isDragging ? '-translate-y-2 scale-105' : ''}`}>
                      <div className="relative mb-6">
                        <div className="absolute inset-0 bg-av-accent/10 rounded-2xl blur-xl transition-all duration-500 group-hover:bg-av-accent/20" />
                        <div className="w-20 h-20 rounded-2xl bg-av-surface/80 backdrop-blur-sm flex items-center justify-center border border-av-border/30 shadow-[0_4px_20px_rgba(0,0,0,0.05)] text-av-main relative z-10 transition-transform duration-300">
                          <Upload className="w-8 h-8 text-av-accent" strokeWidth={1.25} />
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
                          className="flex items-center gap-2 text-xs bg-av-surface/80 border border-av-border/60 text-av-main font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:border-av-accent/40 hover:-translate-y-0.5 active:scale-95"
                        >
                          <Folder className="w-3.5 h-3.5 text-amber-400" /> Add Folders
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="flex-1 flex flex-col relative overflow-hidden backdrop-blur-sm">

                  {/* Toolbar */}
                  <div className="px-6 py-4 flex items-center justify-between border-b border-av-border/30 bg-av-surface/30 backdrop-blur-md shrink-0">
                    <div className="flex items-center gap-3 shrink-0">
                      <span className="text-sm font-medium text-av-main tracking-tight">Explorer</span>
                      <span className="bg-av-border/15 border border-av-main/20 text-av-main text-[11px] font-semibold px-2.5 py-0.5 rounded-md">{files.length}</span>
                    </div>
                    <div className="flex-1 max-w-[200px] mx-4">
                      <div className="relative group">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-av-muted group-focus-within:text-av-accent transition-colors" />
                        <input type="text" placeholder="Filter..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="w-full pl-8 pr-3 py-1.5 bg-av-surface/50 border border-av-border/50 rounded-lg text-xs focus:outline-none focus:border-av-accent/50 focus:ring-1 focus:ring-av-accent/10 transition-all text-av-main shadow-inner placeholder:font-light" />
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <button onClick={handleBrowseFiles} className="flex items-center gap-1.5 text-[11px] bg-av-surface/60 border border-av-border/50 text-av-muted hover:text-av-main hover:border-av-accent/40 font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
                        <File className="w-3 h-3" /> Files
                      </button>
                      <button onClick={handleBrowseFolders} className="flex items-center gap-1.5 text-[11px] bg-av-surface/60 border border-av-border/50 text-av-muted hover:text-av-main hover:border-av-accent/40 font-medium px-3 py-1.5 rounded-lg transition-all shadow-sm">
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

        {/* ── Right Panel: Security Architecture (40%) ──────────────────────────────── */}
        <div className="lg:col-span-2 flex flex-col gap-5 pb-6">

          <div className="px-2 mb-1">
            <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Encryption Settings</h3>
          </div>

          {/* Module: Standard Container */}
          <div
            onClick={() => { setPasswordEnabled(false); setKeyphraseEnabled(false) }}
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${!hasSecretLock ? 'bg-av-surface/80 border-blue-500 shadow-[0_8px_30px_rgba(0,0,0,0.08)] ring-1 ring-blue-500/20' : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
              }`}
          >
            {!hasSecretLock && <div className="absolute inset-0 bg-gradient-to-br from-blue-500/5 to-transparent pointer-events-none" />}
            <div className="p-5 flex items-center justify-between relative z-10">
              <div className="flex items-center gap-4">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-all duration-300 ${!hasSecretLock ? 'bg-blue-500/10 border-blue-500/30 shadow-inner' : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'}`}>
                  <Shield className={`w-[18px] h-[18px] ${!hasSecretLock ? 'text-blue-500' : 'text-av-muted'}`} strokeWidth={1.5} />
                </div>
                <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Standard Archive</h3>
                  <p className="text-av-muted text-[13px] font-light">Archive without password or keyphrase protection</p>
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
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${passwordEnabled
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
                <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md group/input">
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

                <div className="p-4 bg-container-bg border border-av-border/30 rounded-xl shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md group/matrix">
                  <div className="flex items-center justify-between text-[10px] font-bold text-av-main opacity-80 mb-2.5 uppercase tracking-[0.15em]">
                    <span>Password Strength</span>
                    <span className={`${strengthLabelColor} transition-colors duration-300`}>{strengthLabel}</span>
                  </div>
                  <div className="h-1.5 bg-av-border/40 dark:bg-black/40 rounded-full overflow-hidden mb-4 shadow-[inset_0_2px_4px_rgba(0,0,0,0.5)]">
                    <div style={{ width: `${strength}%` }} className={`h-full rounded-full transition-all duration-500 ease-out ${strengthColor}`} />
                  </div>
                  <div className="grid grid-cols-2 gap-y-2.5 text-[11px] font-medium text-av-main opacity-90 tracking-wide">
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasMinLen ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`} /> Length &ge; 12</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasUpper ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`} /> Uppercase</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasLower ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`} /> Lowercase</div>
                    <div className="flex items-center gap-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasNumber ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`} /> Numeric</div>
                    <div className="flex items-center gap-2 col-span-2"><div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${hasSpecial ? 'bg-emerald-500 shadow-[0_0_6px_rgba(16,185,129,0.8)]' : 'bg-av-border/50 dark:bg-white/10'}`} /> Symbolic Character</div>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Module: Keyphrase */}
          <div
            onClick={() => setKeyphraseEnabled(value => !value)}
            className={`rounded-[20px] border transition-all duration-300 cursor-pointer overflow-hidden backdrop-blur-xl relative group ${keyphraseEnabled
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
                  <button onClick={handleGenerateKeyphrase} className="w-full py-3.5 rounded-xl border border-av-border/30 bg-container-bg shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 text-[13px] font-medium transition-all duration-300 flex items-center justify-center gap-2.5 backdrop-blur-md text-purple-600 dark:text-purple-400 hover:border-purple-500/40">
                    <RefreshCw className="w-4 h-4" /> Generate Security Keyphrase
                  </button>
                ) : (
                  <div className="bg-container-bg border border-av-border/30 rounded-xl p-4 shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md">
                    <div className="flex items-center justify-between uppercase tracking-[0.15em] text-[10px] font-bold text-av-main opacity-80 mb-3 pb-3 border-b border-av-border/30">
                      <span>Keyphrase Generation</span>
                      <span className="text-purple-400 drop-shadow-[0_0_8px_rgba(168,85,247,0.4)]">21-WORDS</span>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      {keyphrase.split(' ').map((word, idx) => (
                        <div key={idx} className="flex bg-av-border/10 dark:bg-white/5 border border-av-border/30 rounded-lg overflow-hidden shadow-sm hover:bg-av-border/20 dark:hover:bg-white/10 transition-colors">
                          <span className="w-6 py-1 bg-av-border/15 dark:bg-black/40 text-av-main opacity-80 text-[9px] font-bold flex items-center justify-center border-r border-av-border/30 tracking-wider">{(idx + 1).toString().padStart(2, '0')}</span>
                          <span className="flex-1 py-1 px-2 text-[11px] font-medium text-av-main truncate overflow-hidden">{word}</span>
                        </div>
                      ))}
                    </div>
                    <div className="flex items-center gap-3 mt-4 pt-4 border-t border-av-border/30">
                      <button onClick={handleCopyKeyphrase} className="flex-1 py-2 rounded-lg bg-av-border/10 dark:bg-white/5 border border-av-border/30 dark:border-white/10 text-xs font-semibold text-av-main transition-all duration-300 flex items-center justify-center gap-2 shadow-sm hover:border-purple-500/50 hover:bg-purple-500/20 hover:text-purple-700 dark:hover:text-white">
                        {isCopied ? <><CheckCircle2 className="w-4 h-4 text-emerald-500 drop-shadow-[0_0_8px_rgba(16,185,129,0.5)]" /> Copied</> : <><Copy className="w-4 h-4" /> Copy</>}
                      </button>
                      <button onClick={handleDownloadKeyphrase} className="flex-1 py-2 rounded-lg bg-av-border/10 dark:bg-white/5 border border-av-border/30 dark:border-white/10 text-xs font-semibold text-av-main transition-all duration-300 flex items-center justify-center gap-2 shadow-sm hover:border-purple-500/50 hover:bg-purple-500/20 hover:text-purple-700 dark:hover:text-white">
                        <Download className="w-4 h-4" /> Download .txt
                      </button>
                      <button onClick={handleGenerateKeyphrase} className={`py-2 px-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-500 text-xs font-semibold hover:bg-red-500/20 dark:hover:bg-red-500 hover:text-red-700 dark:hover:text-white transition-colors duration-300 shadow-sm`}>
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
                  <p className="text-av-muted text-[13px] font-light">Create a separate `.avkkey` file that must travel with the archive</p>
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
              <div className="px-5 pb-5 space-y-4 pt-1 relative z-10" onClick={e => e.stopPropagation()}>
                <div className="p-4 rounded-xl bg-amber-500/5 border border-amber-500/20 text-[12px] text-av-muted leading-relaxed">
                  RookDuel Avikal will generate an encrypted `.avkkey` file and keep PQC private material out of the `.avk` archive itself.
                </div>
                <div className="flex items-center gap-3">
                  <button
                    onClick={handleChoosePqcKeyfile}
                    className="flex-1 py-3 rounded-xl bg-av-surface/80 border border-av-border/50 text-sm font-medium text-av-main hover:border-amber-500/30 hover:bg-amber-500/5 transition-all"
                  >
                    {pqcKeyfilePath ? 'Change .avkkey Destination' : 'Choose .avkkey Destination'}
                  </button>
                  {pqcKeyfilePath && (
                    <button
                      onClick={() => setPqcKeyfilePath('')}
                      className="py-3 px-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm font-medium hover:bg-red-500/20 transition-all"
                    >
                      Clear
                    </button>
                  )}
                </div>
                <div className="p-3 rounded-xl bg-av-border/10 dark:bg-white/5 border border-av-border/40">
                  <p className="text-[10px] font-semibold text-av-muted uppercase tracking-[0.2em] mb-1">Keyfile Destination</p>
                  <p className="text-sm text-av-main break-all">{pqcKeyfilePath || 'You will be prompted before encryption starts.'}</p>
                </div>
                <p className="text-[11px] text-amber-500 leading-relaxed">
                  Losing the `.avkkey` means permanent loss of the archive, even with the correct password or keyphrase.
                </p>
              </div>
            )}
          </div>

          {/* Execution Block */}
          <div className="shrink-0 flex flex-col gap-3 mt-auto pt-2">

            {/* Dual Layer High-Protect Warning */}
            {isBoth && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-4 rounded-[16px] bg-red-500/10 border border-red-500/30 flex items-start gap-3 backdrop-blur-md shadow-inner mb-2">
                <ShieldAlert className="w-5 h-5 text-red-500 shrink-0 mt-0.5 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]" />
                <div>
                  <p className="text-[13px] font-bold text-red-500 uppercase tracking-wide mb-1 drop-shadow-[0_0_8px_rgba(239,68,68,0.3)]">Dual High Protection Enabled</p>
                  <p className="text-xs text-red-400/90 font-medium leading-relaxed">
                    This archive will require both the access password and the 21-word keyphrase during unlock.
                    Keep both stored safely before you continue.
                  </p>
                </div>
              </motion.div>
            )}

            {pqcEnabled && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="p-4 rounded-[16px] bg-amber-500/10 border border-amber-500/30 flex items-start gap-3 backdrop-blur-md shadow-inner mb-2">
                <Fingerprint className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
                <div>
                  <p className="text-[13px] font-bold text-amber-500 uppercase tracking-wide mb-1">External Keyfile Required</p>
                  <p className="text-xs text-amber-700 dark:text-amber-200/90 font-medium leading-relaxed">
                    This archive will require a separate `.avkkey` file during decryption. Keep that file stored away from the `.avk`.
                  </p>
                </div>
              </motion.div>
            )}

            <button
              onClick={handleEncrypt}
              disabled={!canEncrypt}
              className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${!canEncrypt ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner backdrop-blur-sm' : 'bg-av-main hover:opacity-90 text-av-surface shadow-[0_10px_30px_rgba(0,0,0,0.15)] hover:shadow-[0_10px_40px_rgba(0,0,0,0.2)] hover:-translate-y-0.5'
                }`}
            >
              <Shield className="w-5 h-5" />
              {loading ? 'Creating Archive...' : !hasSecretLock ? 'Create Archive' : 'Create Protected Archive'}
            </button>

            <p className="text-center text-[11px] text-av-muted mt-1 font-light">
              {!hasSecretLock
                ? 'This archive will be packaged without password or keyphrase protection.'
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


