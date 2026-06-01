import { useState, useCallback, useMemo, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  Unlock, FolderOpen, FileText, Key, Shield, X, Eye, EyeOff, Download,
  Archive, Upload, Search, CheckCircle2, File, Folder,
  ChevronLeft, ChevronRight, ChevronDown, Fingerprint, Lock, StopCircle
} from 'lucide-react'
import { api, cancelDecrypt } from '../lib/api'
import type { KeyphraseWordPair } from '../lib/api'
import { callCoreResponse } from '../lib/backend'
import { waitForBackendReady } from '../lib/backendStatus'
import { parseBackendProgressChunk } from '../lib/backendProgress'
import { getErrorMessage } from '../lib/errors'
import { getDroppedPaths } from '../lib/electron'
import { toast } from 'sonner'
import { useAuth } from '../contexts/AuthContext'
import { useProgress } from '../hooks/useProgress'
import SecuritySettings from '../components/SecuritySettings'
import { useBackendRuntime } from '../hooks/useBackendRuntime'
import BackendStartupNotice from '../components/BackendStartupNotice'
import KeyphraseAssistInput, { splitKeyphraseWords } from '../components/KeyphraseAssistInput'
import ProcessingOverlay from '../components/ProcessingOverlay'

// ── Result Tree Types ─────────────────────────────────────────────
interface ExtractedFile {
  filename: string
  path: string
  size: number
}

interface ResultTreeNode {
  name: string
  fullPath: string      // relative path inside archive
  isDir: boolean
  size: number
  file?: ExtractedFile  // set for leaf files
  children: ResultTreeNode[]
}

interface DecryptResultPayload {
  file_count?: number
  files?: ExtractedFile[]
}

interface DecryptResponseEnvelope {
  success: boolean
  message?: string
  preview_session_id?: string
  result?: DecryptResultPayload
}

interface PreviewTab {
  id: string
  title: string
  archivePath: string
  result: DecryptResponseEnvelope
}

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

function formatSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), units.length - 1)
  return `${(bytes / Math.pow(k, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function buildResultTree(files: ExtractedFile[]): ResultTreeNode[] {
  const root: ResultTreeNode = { name: '', fullPath: '', isDir: true, size: 0, children: [] }

  for (const f of files) {
    const parts = f.filename.replace(/\\/g, '/').split('/').filter(Boolean)
    let cursor = root

    for (let i = 0; i < parts.length; i++) {
      const part = parts[i]
      const isLast = i === parts.length - 1
      const pathSoFar = parts.slice(0, i + 1).join('/')

      let child = cursor.children.find(c => c.name === part)
      if (!child) {
        child = {
          name: part,
          fullPath: pathSoFar,
          isDir: !isLast,
          size: isLast ? f.size : 0,
          file: isLast ? f : undefined,
          children: []
        }
        cursor.children.push(child)
      }
      if (!isLast) {
        child.isDir = true
      }
      cursor = child
    }
  }

  // Calculate folder sizes and sort (folders first, then alphabetical)
  function calcSize(node: ResultTreeNode): number {
    if (!node.isDir) return node.size
    node.size = node.children.reduce((sum, c) => sum + calcSize(c), 0)
    node.children.sort((a, b) => {
      if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
      return a.name.localeCompare(b.name)
    })
    return node.size
  }
  root.children.forEach(c => calcSize(c))
  root.children.sort((a, b) => {
    if (a.isDir !== b.isDir) return a.isDir ? -1 : 1
    return a.name.localeCompare(b.name)
  })

  return root.children
}

function getFileColor(ext: string): string {
  switch (ext) {
    case 'pdf': return 'text-red-400'
    case 'doc': case 'docx': return 'text-blue-400'
    case 'xls': case 'xlsx': return 'text-green-400'
    case 'ppt': case 'pptx': return 'text-orange-400'
    case 'jpg': case 'jpeg': case 'png': case 'gif': case 'bmp': case 'svg': case 'webp': return 'text-purple-400'
    case 'mp4': case 'avi': case 'mov': case 'mkv': case 'webm': return 'text-pink-400'
    case 'mp3': case 'wav': case 'flac': case 'aac': return 'text-yellow-400'
    case 'zip': case 'rar': case '7z': case 'tar': case 'gz': return 'text-av-muted'
    case 'py': case 'js': case 'ts': case 'tsx': case 'jsx': case 'html': case 'css': return 'text-cyan-400'
    case 'json': case 'xml': case 'yaml': case 'yml': return 'text-lime-400'
    default: return 'text-av-muted/70'
  }
}

// ── Result Tree Node Component ──────────────────────────────────────
function ResultNode({
  node,
  depth,
  searchQuery,
  onPreview,
  onDownload
}: {
  node: ResultTreeNode
  depth: number
  searchQuery: string
  onPreview: (f: ExtractedFile) => void
  onDownload: (f: ExtractedFile) => void
}) {
  const [expanded, setExpanded] = useState(depth < 2)
  const ext = node.name.split('.').pop()?.toLowerCase() || ''

  const matchesSearch = !searchQuery || node.name.toLowerCase().includes(searchQuery.toLowerCase())
  const childrenMatch = searchQuery && node.isDir && node.children.some(c =>
    c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    (c.isDir && c.children.some(gc => gc.name.toLowerCase().includes(searchQuery.toLowerCase())))
  )

  if (searchQuery && !matchesSearch && !childrenMatch) return null
  const isExpandedOrForced = expanded || (!!searchQuery && !!childrenMatch)

  return (
    <div>
      <div
        className={`flex items-center gap-2 py-1.5 pr-3 rounded-xl transition-colors duration-150 group cursor-default
          ${node.isDir ? 'hover:bg-av-border/12' : 'hover:bg-av-border/8'}
          ${matchesSearch && searchQuery ? 'bg-av-accent/10 ring-1 ring-av-accent/15' : ''}`}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => node.isDir && setExpanded(e => !e)}
      >
        {/* Toggle */}
        {node.isDir ? (
          <button className="w-4 h-4 flex items-center justify-center shrink-0 text-av-muted/60 hover:text-av-main transition-colors">
            {isExpandedOrForced ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
          </button>
        ) : <span className="w-4 h-4 shrink-0" />}

        {/* Icon */}
        <div className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border ${node.isDir ? 'border-amber-500/20 bg-amber-500/10' : 'border-av-border/45 bg-av-surface/45'}`}>
          {node.isDir ? (
            isExpandedOrForced
              ? <FolderOpen className="w-4 h-4 text-amber-400" strokeWidth={1.5} />
              : <Folder className="w-4 h-4 text-amber-400/70" strokeWidth={1.5} />
          ) : (
            <FileText className={`w-4 h-4 ${getFileColor(ext)}`} strokeWidth={1.5} />
          )}
        </div>

        {/* Name */}
        <span className={`text-[12.5px] truncate ${node.isDir ? 'text-av-main font-medium' : 'text-av-muted font-normal'}`}>
          {node.name}
        </span>

        {/* Size */}
        <span className="text-[10px] text-av-muted/55 font-mono shrink-0 ml-auto mr-1 rounded-md border border-av-border/30 bg-av-border/8 px-2 py-0.5">
          {formatSize(node.size)}
        </span>

        {/* File actions */}
        {!node.isDir && node.file && (
          <div className="flex items-center gap-0.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
            <button
              onClick={e => { e.stopPropagation(); onPreview(node.file!) }}
              className="w-6 h-6 rounded flex items-center justify-center text-av-muted/50 hover:text-av-main hover:bg-av-border/10 dark:hover:bg-white/[0.06] transition-all"
              title="Preview"
            >
              <Eye className="w-3 h-3" />
            </button>
            <button
              onClick={e => { e.stopPropagation(); onDownload(node.file!) }}
              className="w-6 h-6 rounded flex items-center justify-center text-av-muted/50 hover:text-av-main hover:bg-av-border/10 dark:hover:bg-white/[0.06] transition-all"
              title="Save As..."
            >
              <Download className="w-3 h-3" />
            </button>
          </div>
        )}
      </div>

      {/* Children */}
      {node.isDir && isExpandedOrForced && node.children.length > 0 && (
        <div className="relative">
          {depth < 8 && (
            <div
              className="absolute top-0 bottom-0 border-l border-av-border/25 dark:border-white/[0.06]"
              style={{ left: `${depth * 16 + 16}px` }}
            />
          )}
          {node.children.map(child => (
            <ResultNode
              key={child.fullPath}
              node={child}
              depth={depth + 1}
              searchQuery={searchQuery}
              onPreview={onPreview}
              onDownload={onDownload}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Main Decrypt Component ──────────────────────────────────────────
export default function Decrypt() {
  const { sessionToken } = useAuth()
  const [file, setFile] = useState<string[]>([])
  const [isDragging, setIsDragging] = useState(false)
  const [password, setPassword] = useState('')
  const [keyphrase, setKeyphrase] = useState('')
  const [keyphraseWordPairs, setKeyphraseWordPairs] = useState<KeyphraseWordPair[]>([])
  const [pqcKeyfile, setPqcKeyfile] = useState('')
  const [pqcKeyfileRequiresPassword, setPqcKeyfileRequiresPassword] = useState(false)
  const [pqcKeyfileInspecting, setPqcKeyfileInspecting] = useState(false)
  const [pqcKeyfilePassword, setPqcKeyfilePassword] = useState('')
  const [showPqcKeyfilePassword, setShowPqcKeyfilePassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [isCancelling, setIsCancelling] = useState(false)
  const [previewTabs, setPreviewTabs] = useState<PreviewTab[]>([])
  const [activePreviewId, setActivePreviewId] = useState<string | null>(null)
  const [previewFile, setPreviewFile] = useState<ExtractedFile | null>(null)
  const [showSecuritySettings, setShowSecuritySettings] = useState(false)
  const [settingsInitialTab, setSettingsInitialTab] = useState<'appearance' | 'aavrit' | 'privacy' | 'defaults' | 'runtime' | 'diagnostics'>('appearance')
  const [searchQuery, setSearchQuery] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [archiveHints, setArchiveHints] = useState<ArchiveInspectHints | null>(null)
  // Ref holds the preview session ID that may be created server-side during a decrypt
  const activeSessionIdRef = useRef<string | null>(null)
  const previewTabsRef = useRef<PreviewTab[]>([])
  const previewTabStripRef = useRef<HTMLDivElement | null>(null)
  const progress = useProgress()
  const backendRuntime = useBackendRuntime()
  const activePreview = useMemo(() => previewTabs.find(tab => tab.id === activePreviewId) ?? null, [previewTabs, activePreviewId])
  const decryptionResult = activePreview?.result ?? null
  const canDecrypt = backendRuntime.isReady && file.length > 0 && !loading && !pqcKeyfileInspecting && (!pqcKeyfileRequiresPassword || pqcKeyfilePassword.trim().length > 0)
  const expectsEmbeddedPqc = Boolean(archiveHints?.pqc_required && archiveHints?.pqc_storage_mode === 'embedded')
  const expectsExternalPqc = Boolean(archiveHints?.pqc_required && archiveHints?.pqc_storage_mode !== 'embedded')

  const resetUnlockInputs = useCallback(() => {
    setPassword('')
    setKeyphrase('')
    setPqcKeyfile('')
    setPqcKeyfileRequiresPassword(false)
    setPqcKeyfileInspecting(false)
    setPqcKeyfilePassword('')
    setShowPqcKeyfilePassword(false)
    setShowPassword(false)
  }, [])

  useEffect(() => {
    if (!backendRuntime.isReady || keyphraseWordPairs.length > 0) return

    let cancelled = false
    api.getKeyphraseRomanMap()
      .then(result => {
        if (!cancelled && result.success) setKeyphraseWordPairs(result.words)
      })
      .catch(() => {
        if (!cancelled) toast.error('Keyphrase typing helper unavailable')
      })

    return () => {
      cancelled = true
    }
  }, [backendRuntime.isReady, keyphraseWordPairs.length])

  useEffect(() => {
    const unsubscribe = window.electron?.onBackendLog?.((message) => {
      if (!loading && progress.status !== 'running') return
      for (const event of parseBackendProgressChunk(message)) {
        if (event.operation !== 'decrypt') continue
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

  const cleanupPreviewSession = useCallback(async (sessionId?: string | null) => {
    if (!sessionId) return
    try {
      await api.cleanupDecryptSession({ session_id: sessionId })
    } catch (error) {
      console.error('Preview cleanup error:', error)
    }
  }, [])

  useEffect(() => {
    previewTabsRef.current = previewTabs
  }, [previewTabs])

  const previewFileContent = async (fileObj: ExtractedFile) => {
    const ext = fileObj.filename.split('.').pop()?.toLowerCase()
    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'txt', 'md', 'json', 'xml', 'csv'].includes(ext || '')) {
      setPreviewFile(fileObj)
    } else {
      if (fileObj.path) window.electron?.openPath?.(fileObj.path)
    }
  }

  const handleSaveFile = async (fileObj: ExtractedFile) => {
    try {
      if (!fileObj.path || !window.electron?.exportFileCopy) {
        throw new Error('Desktop file export is unavailable')
      }
      const savePath = await window.electron.exportFileCopy({
        sourcePath: fileObj.path,
        defaultPath: fileObj.filename.split(/[/\\]/).pop(),
        filters: [{ name: 'All Files', extensions: ['*'] }]
      })
      if (savePath) {
        toast.success('File saved successfully')
      }
    } catch {
      toast.error('Failed to save file')
    }
  }

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }, [])

  const handleFileSelected = (paths: string[]) => {
    if (paths?.length > 0) {
      setFile([paths[0]])
      setActivePreviewId(null)
      resetUnlockInputs()
      setPreviewFile(null)
      setSearchQuery('')
      setArchiveHints(null)
    }
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const droppedFiles = getDroppedPaths(e.dataTransfer.files)
    const avkFiles = droppedFiles.filter(f => f.endsWith('.avk') || f.endsWith('.AVK'))
    if (avkFiles.length > 0) {
      handleFileSelected(avkFiles)
    } else {
      toast.error('Please select a valid .avk file')
    }
  }, [])

  const handleBrowse = async () => {
    try {
      const selected = await window.electron?.openFile({
        properties: ['openFile'],
        filters: [{ name: 'RookDuel Avikal File', extensions: ['avk'] }]
      })
      if (selected && selected.length > 0) handleFileSelected(selected)
    } catch (error) {
      console.error('Error selecting files:', error)
    }
  }

  const handleBrowsePqcKeyfile = async () => {
    try {
      const selected = await window.electron?.openFile({
        properties: ['openFile'],
        filters: [{ name: 'RookDuel Avikal PQC Keyfile', extensions: ['avkkey'] }]
      })
      if (selected && selected.length > 0) {
        const keyfilePath = selected[0]
        setPqcKeyfile(keyfilePath)
        setPqcKeyfileRequiresPassword(false)
        setPqcKeyfileInspecting(true)
        setPqcKeyfilePassword('')
        setShowPqcKeyfilePassword(false)
        try {
          const info = await api.inspectPqcKeyfile({ keyfile_path: keyfilePath })
          setPqcKeyfileRequiresPassword(Boolean(info?.requires_keyfile_password))
        } catch (error) {
          setPqcKeyfile('')
          toast.error(getErrorMessage(error, 'Invalid PQC keyfile'))
        } finally {
          setPqcKeyfileInspecting(false)
        }
      }
    } catch (error) {
      console.error('Error selecting PQC keyfile:', error)
      toast.error('Failed to select PQC keyfile')
    }
  }

  const handleCancelDecrypt = useCallback(async () => {
    if (!loading || isCancelling) return
    setIsCancelling(true)
    // 1. Abort the in-flight HTTP request immediately
    cancelDecrypt()
    // 2. Tell the backend to clean up any partial preview session dir
    try {
      await waitForBackendReady()
      await callCoreResponse('preview.cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: activeSessionIdRef.current }),
      }, 10_000)
    } catch {
      // Backend cleanup is best-effort — the abort already fired
    }
    activeSessionIdRef.current = null
    progress.reset()
    setLoading(false)
    setIsCancelling(false)
    toast.info('Decryption stopped')
  }, [loading, isCancelling, progress])

  const handleDecrypt = async () => {
    if (!backendRuntime.isReady) {
      toast.info(backendRuntime.detail)
      return
    }
    if (loading) {
      toast.info('Another archive is already being decoded. Wait for it to finish before starting the next one.')
      return
    }
    if (file.length === 0) {
      toast.error('Please select an encrypted file')
      return
    }
    let keyfileRequiresPassword = pqcKeyfileRequiresPassword
    if (pqcKeyfile) {
      try {
        setPqcKeyfileInspecting(true)
        const info = await api.inspectPqcKeyfile({ keyfile_path: pqcKeyfile })
        keyfileRequiresPassword = Boolean(info?.requires_keyfile_password)
        setPqcKeyfileRequiresPassword(keyfileRequiresPassword)
      } catch (error) {
        toast.error(getErrorMessage(error, 'Invalid PQC keyfile'))
        setPqcKeyfileInspecting(false)
        return
      } finally {
        setPqcKeyfileInspecting(false)
      }
    }
    if (keyfileRequiresPassword && !pqcKeyfilePassword.trim()) {
      toast.error('Enter the .avkkey password before unlocking.')
      return
    }
    try {
      setLoading(true)
      setIsCancelling(false)
      activeSessionIdRef.current = null
      progress.reset()
      let initialOperation = 'Contacting secure engine...'
      if (archiveHints?.provider === 'drand') {
        initialOperation = expectsExternalPqc
          ? 'Checking release time and required keys...'
          : expectsEmbeddedPqc
          ? 'Checking release time and embedded quantum lock...'
          : 'Checking release time and required protections...'
      } else if (archiveHints?.provider === 'aavrit') {
        initialOperation = 'Checking capsule access requirements...'
      } else if (archiveHints?.pqc_required || archiveHints?.password_hint || archiveHints?.keyphrase_hint) {
        initialOperation = expectsEmbeddedPqc ? 'Checking embedded quantum protection...' : 'Checking required protections...'
      }
      progress.update({ status: 'running', currentOperation: initialOperation, percentage: null })

      const result = await api.decrypt(
        {
          input_file: file[0],
          password: password || undefined,
          keyphrase: keyphrase ? splitKeyphraseWords(keyphrase) : undefined,
          pqc_keyfile: pqcKeyfile || undefined,
          pqc_keyfile_password: keyfileRequiresPassword ? pqcKeyfilePassword.trim() : undefined,
        },
        sessionToken || undefined,
      )

      if (result.success) {
        // Store the session ID so cancel can clean it up if needed
        if (result.preview_session_id) {
          activeSessionIdRef.current = result.preview_session_id
        }
        const fileCount = result.result?.file_count || 1
        toast.success(fileCount > 1 ? `${fileCount} files ready for preview` : 'File ready for preview')
        const tabId = result.preview_session_id || `${Date.now()}-${Math.random().toString(16).slice(2)}`
        const tabTitle = file[0].split('\\').pop()?.split('/').pop() || 'Decoded archive'
        const nextTab: PreviewTab = {
          id: tabId,
          title: tabTitle,
          archivePath: file[0],
          result,
        }
        setPreviewTabs(current => {
          const withoutDuplicate = current.filter(tab => tab.id !== tabId)
          return [...withoutDuplicate, nextTab]
        })
        setActivePreviewId(tabId)
        setFile([])
        setArchiveHints(null)
        setSearchQuery('')
        resetUnlockInputs()
        progress.update({ status: 'completed', currentOperation: 'Preview ready', percentage: 100 })
      }
    } catch (error: unknown) {
      // Cancelled by user — silent, no error toast
      if ((error as Error & { cancelled?: boolean })?.cancelled) return
      const message = getErrorMessage(error, 'Decryption failed')
      const normalizedLockMessage = message.replace(/^Failed to open \.avk file:\s*/i, '').trim()
      if (
        message.includes('Time-capsule locked')
        || normalizedLockMessage.toLowerCase().includes('locked until')
        || normalizedLockMessage.toLowerCase().includes('still locked')
      ) {
        toast.error(normalizedLockMessage)
      } else if (message.includes('Not authenticated') || message.includes('Please login first')) {
        toast.error('Private Aavrit mode requires a valid session before reveal can continue.')
        setSettingsInitialTab('aavrit')
        setShowSecuritySettings(true)
      } else if (message.includes('Authentication failed')) toast.error('Authentication failed. Please try again.')
      else if (message.includes('Session expired')) toast.error('Session expired. Please login again.')
      else if (message.includes('requires the matching .avkkey file')) toast.error('This archive requires its matching .avkkey file before decryption can continue.')
      else if (message.includes('.avkkey requires its keyfile password')) toast.error('This .avkkey requires its keyfile password.')
      else if (message.includes('Incorrect .avkkey password')) toast.error('Incorrect .avkkey password or corrupted keyfile.')
      else if (message.includes('embedded PQC') || message.includes('embedded quantum')) toast.error('The embedded quantum protection could not be unlocked. Check the password or keyphrase, or verify that the archive is not corrupted.')
      else if (message.includes('requires both its password and 21-word keyphrase')) toast.error('This archive requires both its password and 21-word keyphrase before decryption can continue.')
      else if (message.includes('requires its password before decryption can continue')) toast.error('This archive requires its password before decryption can continue.')
      else if (message.includes('requires its 21-word keyphrase before decryption can continue')) toast.error('This archive requires its 21-word keyphrase before decryption can continue.')
      else if (message.includes('requires a password or keyphrase')) toast.error('This protected archive requires a password or keyphrase.')
      else if (message.includes('Incorrect password or keyphrase')) toast.error('Wrong password or keyphrase')
      else if (message.includes('Incorrect password')) toast.error('Wrong password or keyphrase')
      else if (message.includes('File integrity check failed')) toast.error('File integrity check failed. File may be corrupted.')
      else if (message.includes('Capsule verification failed')) toast.error('Capsule verification failed. File may be corrupted.')
      else if (message.includes('service unavailable')) toast.error('Time-capsule service unavailable. Try again later.')
      else toast.error(message)
    } finally {
      setPassword('')
      setKeyphrase('')
      setShowPassword(false)
      setLoading(false)
    }
  }

  // Build tree from extracted files
  const extractedFiles = useMemo<ExtractedFile[]>(() => decryptionResult?.result?.files ?? [], [decryptionResult])
  const resultTree = useMemo(() => buildResultTree(extractedFiles), [extractedFiles])
  const totalSize = useMemo(() => extractedFiles.reduce((s, f) => s + (f.size || 0), 0), [extractedFiles])

  const handleExtractAll = async () => {
    try {
      if (!window.electron?.exportFilesToDirectory) {
        throw new Error('Bulk extraction is unavailable')
      }
      const exportableFiles = extractedFiles
        .filter((fileObj) => fileObj.path)
        .map((fileObj) => ({
          sourcePath: fileObj.path,
          relativePath: fileObj.filename.replace(/\\/g, '/'),
        }))
      if (exportableFiles.length === 0) {
        throw new Error('No extracted files are available to export')
      }

      const result = await window.electron.exportFilesToDirectory({
        title: 'Choose extraction folder',
        files: exportableFiles,
      })
      if (result) {
        toast.success(`${result.copiedCount} files extracted to ${result.destinationPath}`)
      }
    } catch {
      toast.error('Failed to extract files')
    }
  }

  const closePreviewTab = useCallback((tabId: string) => {
    const tab = previewTabsRef.current.find(item => item.id === tabId)
    void cleanupPreviewSession(tab?.result.preview_session_id)
    setPreviewTabs(current => current.filter(item => item.id !== tabId))
    setActivePreviewId(current => {
      if (current !== tabId) return current
      const remaining = previewTabsRef.current.filter(item => item.id !== tabId)
      return remaining.length > 0 ? remaining[remaining.length - 1].id : null
    })
    setPreviewFile(null)
    setSearchQuery('')
  }, [cleanupPreviewSession])

  const handleNewDecode = useCallback(() => {
    setFile([])
    setSearchQuery('')
    resetUnlockInputs()
    setArchiveHints(null)
    setActivePreviewId(null)
    setPreviewFile(null)
  }, [resetUnlockInputs])

  const scrollPreviewTabs = useCallback((direction: -1 | 1) => {
    const strip = previewTabStripRef.current
    if (!strip) return
    strip.scrollBy({ left: direction * Math.max(180, strip.clientWidth * 0.55), behavior: 'smooth' })
  }, [])

  useEffect(() => {
    let cancelled = false

    async function inspectSelectedArchive() {
      if (file.length === 0) {
        setArchiveHints(null)
        return
      }

      try {
        const response = await api.inspectArchive({ input_file: file[0] })
        if (!cancelled) {
          setArchiveHints(response.archive ?? null)
        }
      } catch {
        if (!cancelled) {
          setArchiveHints(null)
        }
      }
    }

    void inspectSelectedArchive()

    return () => {
      cancelled = true
    }
  }, [file])

  useEffect(() => {
    return () => {
      for (const tab of previewTabsRef.current) {
        void cleanupPreviewSession(tab.result.preview_session_id)
      }
    }
  }, [cleanupPreviewSession])

  const selectedFileName = file.length > 0 ? (file[0].split('\\').pop()?.split('/').pop() || file[0]) : null

  return (
    <div className="av-page-shell">

      {/* 60/40 Split Architecture */}
      <div className="av-work-grid">

      {/* ── Left Panel: File / Result Tree (60%) ──────────────────────── */}
      <div
        className="av-primary-panel lg:col-span-3 flex flex-col overflow-hidden relative"
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
      >
        {/* Header */}
        <div className="av-panel-header z-10 shrink-0">
          <h2 className="text-[28px] font-medium tracking-tight text-av-main mb-1.5 flex items-center gap-3">
            Unlock Archive <span className="font-light text-av-muted">Open Secure Contents</span>
          </h2>
          <p className="text-av-muted text-sm font-light">Load an `.avk` archive, verify it, then preview or extract the unlocked contents.</p>
        </div>

        {/* Loading Overlay */}
        {loading && (
          <ProcessingOverlay
            title="Unlocking Archive"
            description={progress.currentOperation || 'Preparing secure preview...'}
            icon={<Unlock className="h-5 w-5 text-av-accent" strokeWidth={1.7} />}
            percentage={progress.percentage}
            etaSeconds={progress.etaSeconds}
            elapsedSeconds={progress.elapsedSeconds}
            fileSize={progress.fileSize}
            indeterminateText="Working in secure preview session"
          >
            <button
              id="decrypt-stop-btn"
              onClick={handleCancelDecrypt}
              disabled={isCancelling}
              className="w-full flex items-center justify-center gap-2.5 py-2.5 px-4 rounded-xl bg-red-500/10 border border-red-500/25 text-red-400 text-sm font-medium transition-all hover:bg-red-500/20 hover:border-red-500/50 hover:text-red-300 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isCancelling ? (
                <>
                  <motion.div
                    animate={{ rotate: 360 }}
                    transition={{ duration: 0.8, repeat: Infinity, ease: 'linear' }}
                    className="w-4 h-4 border-2 border-red-400/30 border-t-red-400 rounded-full"
                  />
                  Stopping...
                </>
              ) : (
                <>
                  <StopCircle className="w-4 h-4" strokeWidth={1.5} />
                  Stop Decryption
                </>
              )}
            </button>
            <p className="text-[10px] text-av-muted/50 text-center mt-2 font-light">
              Stopping will discard any partially decrypted data
            </p>
          </ProcessingOverlay>
        )}

        {/* State 1: Before Decryption — Drop Zone */}
        {previewTabs.length > 0 && (
          <div className="av-explorer-toolbar flex items-center gap-2 px-3 py-2.5">
            <button
              onClick={() => scrollPreviewTabs(-1)}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-av-border/40 bg-av-surface/65 text-av-muted transition-all hover:border-av-border/70 hover:text-av-main"
              title="Scroll preview tabs left"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>

            <div
              ref={previewTabStripRef}
              onWheel={(event) => {
                if (Math.abs(event.deltaY) <= Math.abs(event.deltaX)) return
                event.currentTarget.scrollLeft += event.deltaY
              }}
              className="flex min-w-0 flex-1 items-end gap-1.5 overflow-x-auto overflow-y-hidden px-1 pb-1 custom-scrollbar"
            >
              {previewTabs.map(tab => {
                const isActive = tab.id === activePreviewId
                const fileCount = tab.result.result?.file_count ?? tab.result.result?.files?.length ?? 1
                return (
                  <div
                    key={tab.id}
                    className={`group flex h-11 min-w-[92px] flex-[1_1_150px] max-w-[210px] items-center rounded-t-2xl rounded-b-xl border transition-all ${
                      isActive
                        ? 'border-av-accent/45 bg-av-accent/10 text-av-main shadow-[0_8px_24px_rgba(59,130,246,0.08)]'
                        : 'border-av-border/35 bg-av-surface/45 text-av-muted hover:border-av-border/70 hover:bg-av-surface/70 hover:text-av-main'
                    }`}
                    title={tab.archivePath}
                  >
                    <button
                      onClick={() => {
                        setActivePreviewId(tab.id)
                        setFile([])
                        setSearchQuery('')
                        setArchiveHints(null)
                        setPreviewFile(null)
                      }}
                      className="flex min-w-0 flex-1 items-center gap-2 px-2.5 py-2 text-left"
                    >
                      <CheckCircle2 className={`h-3.5 w-3.5 shrink-0 ${isActive ? 'text-green-500' : 'text-av-muted/80'}`} />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-[11.5px] font-semibold leading-tight">{tab.title}</span>
                        <span className="block truncate text-[9.5px] leading-tight text-av-muted">{fileCount} file{fileCount !== 1 ? 's' : ''}</span>
                      </span>
                    </button>
                    <button
                      onClick={(event) => {
                        event.stopPropagation()
                        closePreviewTab(tab.id)
                      }}
                      className="mr-1.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-lg text-av-muted opacity-70 transition-all hover:bg-red-500/10 hover:text-red-400 group-hover:opacity-100"
                      title="Close and wipe preview files"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                )
              })}
            </div>

            <button
              onClick={() => scrollPreviewTabs(1)}
              className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl border border-av-border/40 bg-av-surface/65 text-av-muted transition-all hover:border-av-border/70 hover:text-av-main"
              title="Scroll preview tabs right"
            >
              <ChevronRight className="h-4 w-4" />
            </button>

            <button
              onClick={handleNewDecode}
              disabled={loading}
              className="shrink-0 rounded-xl border border-av-border/50 bg-av-surface/60 px-3.5 py-2 text-xs font-semibold text-av-main transition-all hover:border-av-accent/40 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Decode Another
            </button>
          </div>
        )}

        {!decryptionResult && (
          <div className="av-left-workspace flex-1 flex flex-col relative overflow-hidden">
            <div className="flex-1 p-8 flex flex-col relative">
              <div
                  className={`av-drop-zone flex-1 rounded-2xl flex flex-col items-center justify-center transition-all duration-300 relative overflow-hidden cursor-pointer ${
                  isDragging
                    ? 'av-drop-zone-active'
                    : file.length > 0
                      ? 'border-av-accent/50'
                      : 'text-av-muted'
                }`}
                onClick={!file.length ? handleBrowse : undefined}
              >
                <div className="pointer-events-none absolute inset-0 opacity-0" />
                <motion.div animate={{ y: isDragging ? -10 : 0 }} className="z-10 flex flex-col items-center">
                  <div className="relative mb-6">
                    <div className="absolute inset-0 rounded-2xl bg-av-border/10" />
                    <div className="w-20 h-20 rounded-2xl bg-av-surface/80 backdrop-blur-sm flex items-center justify-center border border-av-border/30 shadow-[0_4px_20px_rgba(0,0,0,0.05)] text-av-main relative z-10">
                      {file.length > 0
                        ? <Shield className="w-8 h-8 text-av-accent" strokeWidth={1.25} />
                        : <Upload className="w-8 h-8" strokeWidth={1.25} />
                      }
                    </div>
                  </div>

                  <h3 className="text-xl font-medium text-av-main mb-2 tracking-tight">
                    {file.length > 0
                      ? selectedFileName
                      : isDragging
                        ? 'Drop .avk archive to unlock'
                        : 'Select or drop .avk archive'}
                  </h3>
                  <p className="text-sm text-av-muted font-light mb-6">
                    {file.length > 0 ? 'Archive loaded. Provide only the protections this archive actually uses.' : 'Supports only RookDuel Avikal archives'}
                  </p>

                  {file.length > 0 && archiveHints && (
                    <div className="w-full max-w-xl mb-6 rounded-2xl border border-av-border/40 bg-av-surface/70 px-4 py-3 text-left shadow-sm">
                      <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-av-muted mb-2">Archive Summary</p>
                      <div className="flex flex-wrap gap-2">
                        <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">
                          {archiveHints.archive_type === 'multi_file' ? 'Multi-file archive' : 'Single-file archive'}
                        </span>
                        {archiveHints.provider === 'aavrit' && <span className="rounded-full border border-av-accent/30 bg-av-accent/10 px-3 py-1 text-[11px] text-av-main">Aavrit time-capsule</span>}
                        {archiveHints.provider === 'drand' && <span className="rounded-full border border-cyan-500/30 bg-cyan-500/10 px-3 py-1 text-[11px] text-av-main">drand time-capsule</span>}
                        {archiveHints.password_hint && <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-[11px] text-av-main">Password</span>}
                        {archiveHints.keyphrase_hint && <span className="rounded-full border border-purple-500/30 bg-purple-500/10 px-3 py-1 text-[11px] text-av-main">21-word keyphrase</span>}
                        {archiveHints.pqc_required && (
                          <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1 text-[11px] text-av-main">
                            {archiveHints.pqc_storage_mode === 'embedded' ? 'Embedded PQC' : 'External PQC Keyfile'}
                          </span>
                        )}
                        {archiveHints.metadata_requires_secret && <span className="rounded-full border border-av-border/40 bg-av-border/10 px-3 py-1 text-[11px] text-av-main">More details unlock after password or keyphrase</span>}
                      </div>
                    </div>
                  )}

                  {file.length > 0 ? (
                    <div className="flex items-center gap-3">
                      <button
                        onClick={(e) => { e.stopPropagation(); handleBrowse() }}
                        className="flex items-center gap-2 text-xs bg-av-surface/80 border border-av-border/60 text-av-main font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm hover:border-av-accent/40 active:scale-95"
                      >
                        <File className="w-3.5 h-3.5" /> Change File
                      </button>
                      <button
                        onClick={(e) => { e.stopPropagation(); setFile([]); setPqcKeyfile(''); setArchiveHints(null) }}
                        className="flex items-center gap-2 text-xs bg-red-500/10 border border-red-500/20 text-red-400 font-semibold px-4 py-2.5 rounded-xl transition-all shadow-sm hover:bg-red-500/20 active:scale-95"
                      >
                        <X className="w-3.5 h-3.5" /> Remove
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleBrowse() }}
                      className="flex items-center gap-2 text-xs bg-av-main text-av-surface font-semibold px-5 py-2.5 rounded-xl transition-all shadow-[0_2px_12px_rgba(0,0,0,0.15)] hover:opacity-90 hover:-translate-y-0.5 active:scale-95"
                    >
                      <File className="w-3.5 h-3.5" /> Browse .avk Files
                    </button>
                  )}
                </motion.div>
              </div>
            </div>
          </div>
        )}

        {/* State 2: After Decryption — Result Tree */}
        {decryptionResult && extractedFiles.length > 0 && (
          <div className="flex-1 flex flex-col relative overflow-hidden">
            {/* Success Header */}
            <div className="av-explorer-toolbar px-6 py-4 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-3 shrink-0">
                <div className="w-8 h-8 rounded-lg bg-green-500/10 border border-green-500/20 flex items-center justify-center">
                  <CheckCircle2 className="w-4 h-4 text-green-500" />
                </div>
                <div>
                  <span className="text-sm font-medium text-av-main block leading-tight">Unlocked Preview Ready</span>
                  <span className="text-[10px] text-av-muted font-light">{extractedFiles.length} file{extractedFiles.length !== 1 ? 's' : ''} - {formatSize(totalSize)}</span>
                </div>
              </div>

              <div className="flex-1 max-w-[200px] mx-4">
                <div className="relative group">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-av-muted group-focus-within:text-av-accent transition-colors" />
                  <input
                    type="text"
                    placeholder="Filter..."
                    value={searchQuery}
                    onChange={e => setSearchQuery(e.target.value)}
                    className="w-full pl-8 pr-3 py-1.5 bg-av-surface border border-av-border rounded-lg text-xs focus:outline-none focus:border-av-accent/50 focus:ring-1 focus:ring-av-accent/10 transition-all text-av-main shadow-inner placeholder:font-light"
                  />
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <button
                  onClick={handleExtractAll}
                  className="flex items-center gap-1.5 text-[11px] bg-av-main text-av-surface font-medium px-3.5 py-1.5 rounded-lg transition-all shadow-sm hover:opacity-90"
                >
                  <Archive className="w-3 h-3" /> Extract All
                </button>
                <button
                  onClick={() => activePreviewId && closePreviewTab(activePreviewId)}
                  className="w-8 h-8 rounded-lg flex items-center justify-center bg-av-border/10 hover:bg-av-border/20 transition-colors text-av-main"
                  title="Close and wipe this preview"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            {/* Tree View */}
            <div className="av-tree-surface flex-1 overflow-y-auto custom-scrollbar px-3 py-3">
              {resultTree.length > 0 ? (
                resultTree.map(node => (
                  <ResultNode
                    key={node.fullPath}
                    node={node}
                    depth={0}
                    searchQuery={searchQuery}
                    onPreview={previewFileContent}
                    onDownload={handleSaveFile}
                  />
                ))
              ) : searchQuery ? (
                <div className="flex flex-col items-center justify-center py-20 text-av-muted">
                  <Search className="w-12 h-12 mb-4 opacity-20" />
                  <p className="text-sm font-medium">No files matching "{searchQuery}"</p>
                </div>
              ) : null}
            </div>
          </div>
        )}
      </div>

      {/* ── Right Panel: Security Protocol (40%) ─────────────────────── */}
      <div className={`av-side-stack av-natural-side-stack lg:col-span-2 transition-opacity ${loading ? 'pointer-events-none opacity-70' : ''}`}>

        <div className="px-2 mb-1">
          <h3 className="text-sm font-semibold text-av-muted uppercase tracking-[0.15em]">Unlocking Settings</h3>
        </div>

        {/* Module: Symmetric Key (Password) */}
        <div className={`rounded-[20px] border transition-all duration-300 overflow-hidden backdrop-blur-xl relative group ${
          password.length > 0
            ? 'bg-av-surface/80 border-emerald-500 shadow-[0_8px_30px_rgba(16,185,129,0.08)] ring-1 ring-emerald-500/20'
            : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
        }`}>
          {password.length > 0 && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-emerald-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 relative z-10">
            <div className="flex items-start justify-between gap-4">
              <div className="flex min-w-0 items-start gap-4">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-all duration-300 ${
                  password.length > 0
                    ? 'bg-emerald-500/10 border-emerald-500/30 shadow-inner'
                    : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'
                }`}>
                  <Lock className={`w-[18px] h-[18px] ${password.length > 0 ? 'text-emerald-500' : 'text-av-muted'}`} strokeWidth={1.5} />
                </div>
                <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Access Password</h3>
                  <p className="text-av-muted text-[13px] font-light">Enter only if this archive was created with a password</p>
                </div>
              </div>
            </div>

            <div className="relative rounded-xl bg-container-bg border border-av-border/30 shadow-[inset_0_4px_15px_var(--container-bg)] hover:bg-container-bg/80 transition-all duration-300 backdrop-blur-md group/input">
              <div className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                <Fingerprint className={`w-4 h-4 transition-colors duration-300 ${password.length > 0 ? 'text-emerald-400 opacity-100' : 'text-av-muted opacity-50 group-hover/input:opacity-100 group-hover/input:text-emerald-400'}`} />
              </div>
              <input
                type={showPassword ? 'text' : 'password'}
                placeholder="Enter your access password"
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="w-full pl-10 pr-11 py-3.5 rounded-xl bg-transparent text-av-main text-sm focus:outline-none focus:ring-1 focus:ring-emerald-500/50 transition-all font-medium placeholder:font-light"
              />
              <button onClick={() => setShowPassword(!showPassword)} className="absolute right-3 top-1/2 -translate-y-1/2 text-av-muted hover:text-av-main dark:hover:text-white transition-colors p-1.5 rounded-lg hover:bg-av-border/10 dark:hover:bg-white/10">
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>
        </div>

        {/* Module: Seed Vector (Keyphrase) */}
        <div className={`rounded-[20px] border transition-all duration-300 overflow-hidden backdrop-blur-xl relative group ${
          keyphrase.trim().length > 0
            ? 'bg-av-surface/80 border-purple-500 shadow-[0_8px_30px_rgba(168,85,247,0.08)] ring-1 ring-purple-500/20'
            : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
        }`}>
          {keyphrase.trim().length > 0 && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-purple-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 relative z-10">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-all duration-300 ${
                  keyphrase.trim().length > 0
                    ? 'bg-purple-500/10 border-purple-500/30 shadow-inner'
                    : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'
                }`}>
                  <Key className={`w-[18px] h-[18px] ${keyphrase.trim().length > 0 ? 'text-purple-500' : 'text-av-muted'}`} strokeWidth={1.5} />
                </div>
              <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">Security Keyphrase</h3>
                  <p className="text-av-muted text-[13px] font-light">Enter only if this archive was created with a 21-word keyphrase</p>
                </div>
              </div>
            </div>

            <KeyphraseAssistInput
              value={keyphrase}
              onChange={setKeyphrase}
              pairs={keyphraseWordPairs}
              disabled={!backendRuntime.isReady || loading}
              onIssue={message => toast.error(message)}
              showClearButton
              onClearAll={() => setKeyphrase('')}
            />

            {/* Word count indicator */}
            {keyphrase.trim().length > 0 && (
              <div className="mt-3 flex items-center gap-2">
                <div className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${
                  splitKeyphraseWords(keyphrase).length === 21
                    ? 'bg-purple-500 shadow-[0_0_6px_rgba(168,85,247,0.8)]'
                    : 'bg-av-border/50 dark:bg-white/10'
                }`} />
                <span className="text-[11px] text-av-muted font-medium">
                  {splitKeyphraseWords(keyphrase).length} / 21 words
                </span>
              </div>
            )}
          </div>
        </div>

        <div className={`rounded-[20px] border transition-all duration-300 overflow-hidden backdrop-blur-xl relative group ${
          pqcKeyfile.trim().length > 0
            ? 'bg-av-surface/80 border-amber-500 shadow-[0_8px_30px_rgba(245,158,11,0.12)] ring-1 ring-amber-500/20'
            : 'bg-av-surface/40 border-av-border/30 shadow-sm hover:border-av-border/60 hover:bg-av-surface/60'
        }`}>
          {pqcKeyfile.trim().length > 0 && <div className="absolute top-0 left-0 right-0 h-32 bg-gradient-to-b from-amber-500/5 to-transparent pointer-events-none" />}
          <div className="p-5 relative z-10">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-4">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center border transition-all duration-300 ${
                  pqcKeyfile.trim().length > 0
                    ? 'bg-amber-500/10 border-amber-500/30 shadow-inner'
                    : 'bg-av-surface shadow-[0_2px_8px_rgba(0,0,0,0.04)] border-av-border/20 group-hover:scale-105'
                }`}>
                  <Fingerprint className={`w-[18px] h-[18px] ${pqcKeyfile.trim().length > 0 ? 'text-amber-500' : 'text-av-muted'}`} strokeWidth={1.5} />
                </div>
                <div>
                  <h3 className="font-medium text-av-main tracking-tight text-sm mb-0.5">
                    {expectsEmbeddedPqc ? 'Embedded Quantum Protection' : 'Quantum Keyfile'}
                  </h3>
                  <p className="text-av-muted text-[13px] font-light leading-relaxed">
                    {expectsEmbeddedPqc
                      ? 'No external keyfile needed.'
                      : pqcKeyfileInspecting
                      ? 'Checking keyfile...'
                      : pqcKeyfile
                      ? pqcKeyfile.split(/[\\/]/).pop()
                      : 'Optional external PQC key.'}
                  </p>
                </div>
              </div>
              {!expectsEmbeddedPqc && (
                <div className="flex shrink-0 items-center gap-2">
                  <button
                    onClick={handleBrowsePqcKeyfile}
                    className="flex items-center gap-1.5 rounded-xl border border-amber-500/20 bg-amber-500/10 px-3 py-2 text-[11px] font-semibold text-amber-600 shadow-sm transition-all hover:border-amber-500/35 hover:bg-amber-500/15 dark:text-amber-300"
                  >
                    <Upload className="w-3.5 h-3.5" />
                    {pqcKeyfile ? 'Change' : 'Browse'}
                  </button>
                  {pqcKeyfile && (
                    <button
                      onClick={() => {
                        setPqcKeyfile('')
                        setPqcKeyfileRequiresPassword(false)
                        setPqcKeyfileInspecting(false)
                        setPqcKeyfilePassword('')
                        setShowPqcKeyfilePassword(false)
                      }}
                      className="w-8 h-8 rounded-lg flex items-center justify-center bg-red-500/10 border border-red-500/20 text-red-400 hover:bg-red-500/20 transition-all"
                      title="Clear keyfile"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  )}
                </div>
              )}
            </div>

            {expectsEmbeddedPqc ? (
              <div className="mt-4 flex items-center gap-2 rounded-xl border border-emerald-500/20 bg-emerald-500/5 px-3 py-2">
                <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                <p className="text-xs font-medium text-av-main">Embedded PQC will unlock from the `.avk` file.</p>
              </div>
            ) : (
              <div className="mt-4 rounded-xl border border-av-border/35 bg-av-border/10 px-3 py-2.5">
                <div className="flex items-center gap-2">
                  <File className="h-4 w-4 shrink-0 text-av-muted" />
                  <p className={`min-w-0 flex-1 truncate text-xs font-medium ${pqcKeyfile ? 'text-av-main' : 'text-av-muted'}`}>
                    {pqcKeyfile || 'No .avkkey selected'}
                  </p>
                </div>
                {pqcKeyfileRequiresPassword && (
                  <div className="mt-3 space-y-2 border-t border-av-border/25 pt-3">
                    <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-amber-500">Keyfile password required</p>
                    <div className="flex items-center gap-2 rounded-xl border border-av-border/35 bg-av-surface/70 px-3 py-2">
                      <Lock className="h-4 w-4 text-av-muted" />
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
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Execution Block */}
        <div className="shrink-0 flex flex-col gap-3 pt-2">
          <BackendStartupNotice backend={backendRuntime} compact />
          <button
            onClick={handleDecrypt}
            disabled={!canDecrypt}
            className={`w-full py-4 rounded-2xl text-[15px] font-semibold tracking-wide transition-all duration-300 flex items-center justify-center gap-2 ${
              !canDecrypt
                ? 'bg-av-border/10 dark:bg-white/5 border border-av-border/20 dark:border-white/5 text-av-muted cursor-not-allowed shadow-inner backdrop-blur-sm'
                : 'bg-av-main hover:opacity-90 text-av-surface shadow-[0_10px_30px_rgba(0,0,0,0.15)] hover:shadow-[0_10px_40px_rgba(0,0,0,0.2)] hover:-translate-y-0.5'
            }`}
          >
            <Unlock className="w-5 h-5" />
            {loading ? 'Unlocking Archive...' : !backendRuntime.isReady ? 'Starting Secure Engine...' : 'Unlock & Preview'}
          </button>
          {!backendRuntime.isReady && (
            <p className="text-center text-[11px] text-av-muted font-light">{backendRuntime.detail}</p>
          )}
        </div>
      </div>
      </div>

      {/* ── File Preview Modal ───────────────────────────────────────── */}
      <AnimatePresence>
        {previewFile && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="av-modal-backdrop fixed inset-0 z-[100] flex items-center justify-center p-4 sm:p-6"
            onClick={() => setPreviewFile(null)}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0, y: 10 }}
              animate={{ scale: 1, opacity: 1, y: 0 }}
              exit={{ scale: 0.95, opacity: 0, y: 10 }}
              className="av-modal-surface flex max-h-[82vh] w-full max-w-4xl flex-col overflow-hidden rounded-[1.5rem]"
              onClick={e => e.stopPropagation()}
            >
              <div className="flex items-center justify-between p-5 border-b border-av-border bg-av-border/10">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-av-surface shadow-sm flex items-center justify-center">
                    <FileText className={`w-5 h-5 ${getFileColor(previewFile.filename.split('.').pop()?.toLowerCase() || '')}`} />
                  </div>
                  <div>
                    <h3 className="font-semibold text-av-main text-sm">{previewFile.filename}</h3>
                    <p className="text-xs text-av-muted">{formatSize(previewFile.size || 0)}</p>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={() => { if (previewFile.path) window.electron?.openPath?.(previewFile.path) }}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-av-main text-av-surface hover:opacity-90 transition-colors"
                  >
                    <FolderOpen className="w-4 h-4" />
                    Open in System Viewer
                  </button>
                  <button
                    onClick={() => setPreviewFile(null)}
                    className="w-8 h-8 rounded-lg flex items-center justify-center text-av-muted hover:text-av-main hover:bg-av-border/10 transition-all"
                  >
                    <X className="w-5 h-5" />
                  </button>
                </div>
              </div>

              <div className="flex min-h-[300px] flex-1 flex-col items-center justify-center overflow-y-auto bg-av-surface p-10 custom-scrollbar">
                <FileText className="w-20 h-20 text-av-border mb-6" />
                <h2 className="text-xl font-medium text-av-main mb-2">Open in System Viewer</h2>
                <p className="text-sm text-av-muted max-w-md text-center">
                  Avikal unlocked this file into a secure preview session. Use "Open in System Viewer" above to open it with your default desktop app.
                </p>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      <SecuritySettings isOpen={showSecuritySettings} onClose={() => setShowSecuritySettings(false)} initialTab={settingsInitialTab} />
    </div>
  )
}





