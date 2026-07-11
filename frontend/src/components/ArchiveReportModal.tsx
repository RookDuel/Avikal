import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'
import {
  Activity, Archive, CalendarClock, Check, CheckCircle2, Clock3,
  Copy, Cpu, Download, FileCheck2, FileJson, Fingerprint, Gauge, HardDrive,
  Info, KeyRound, Layers3, LockKeyhole, ShieldCheck, TriangleAlert, X,
} from 'lucide-react'
import { toast } from 'sonner'

type ReportRecord = Record<string, unknown>
type ReportTab = 'summary' | 'checks' | 'protection' | 'contents' | 'performance' | 'chess' | 'technical'
type CheckStatus = 'passed' | 'failed' | 'not_checked' | 'not_applicable'

interface ArchiveReportModalProps {
  report: ReportRecord
  title?: string
  onClose: () => void
}

function record(value: unknown): ReportRecord {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as ReportRecord : {}
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : []
}

function text(value: unknown, fallback = 'Not recorded'): string {
  if (value === null || value === undefined || value === '') return fallback
  if (typeof value === 'boolean') return value ? 'Yes' : 'No'
  return String(value)
}

function titleCase(value: unknown): string {
  const source = text(value)
  return source.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase())
}

function formatBytes(value: unknown): string {
  const bytes = Number(value)
  if (!Number.isFinite(bytes) || bytes < 0) return 'Not recorded'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let amount = bytes
  let unit = 0
  while (amount >= 1024 && unit < units.length - 1) { amount /= 1024; unit += 1 }
  return `${amount.toFixed(unit === 0 ? 0 : amount >= 10 ? 1 : 2)} ${units[unit]}`
}

function formatDuration(value: unknown): string {
  const ms = Number(value)
  if (!Number.isFinite(ms) || ms < 0) return 'Not recorded'
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(2)} s`
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`
}

function parseTimestamp(value: unknown): Date | null {
  if (value instanceof Date && Number.isFinite(value.getTime())) return value
  if (typeof value === 'number' || (typeof value === 'string' && /^\d+(\.\d+)?$/.test(value.trim()))) {
    const numeric = Number(value)
    const milliseconds = numeric < 10_000_000_000 ? numeric * 1000 : numeric
    const date = new Date(milliseconds)
    return Number.isFinite(date.getTime()) ? date : null
  }
  if (typeof value === 'string') {
    const date = new Date(value)
    return Number.isFinite(date.getTime()) ? date : null
  }
  return null
}

function dateDetails(value: unknown) {
  const date = parseTimestamp(value)
  if (!date) return null
  const local = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'long', timeStyle: 'medium',
  }).format(date)
  const utc = new Intl.DateTimeFormat('en-GB', {
    dateStyle: 'long', timeStyle: 'medium', timeZone: 'UTC',
  }).format(date)
  const zone = Intl.DateTimeFormat().resolvedOptions().timeZone || 'Local time'
  return { local, utc: `${utc} UTC`, zone, iso: date.toISOString() }
}

function shortHash(value: unknown): string {
  const hash = text(value)
  return hash.length > 34 ? `${hash.slice(0, 16)}...${hash.slice(-14)}` : hash
}

function decodeBase64(value: unknown): Uint8Array | null {
  if (typeof value !== 'string' || !value) return null
  try {
    const binary = atob(value)
    return Uint8Array.from(binary, character => character.charCodeAt(0))
  } catch { return null }
}

function parseSignedManifest(evidence: ReportRecord): ReportRecord {
  const bytes = decodeBase64(evidence.manifest)
  if (!bytes) return {}
  try { return record(JSON.parse(new TextDecoder().decode(bytes))) } catch { return {} }
}

async function sha256Hex(bytes: Uint8Array | null): Promise<string | null> {
  if (!bytes) return null
  const digest = await window.crypto.subtle.digest('SHA-256', bytes as BufferSource)
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')
}

function encryptionProfile(value: unknown): string {
  const method = text(value, '')
  if (method === 'aes256gcm_stream' || method === 'aes256gcm_stream_timekey') return 'AES-256-GCM / chunked AEAD'
  if (method === 'plaintext_archive') return 'Unencrypted payload'
  return method || 'Unknown payload profile'
}

function resolvedPqcAlgorithms(protection: ReportRecord): ReportRecord {
  const details = record(protection.pqc_suite_details)
  const algorithms = record(details.algorithms)
  if (Object.keys(algorithms).length) return algorithms
  if (protection.pqc_suite === 'avikal-pqc-std-v1') return { post_quantum_kem: 'ML-KEM-768', classical_kem: 'X25519', authentication_signature: 'ML-DSA-65', long_term_signature: 'SLH-DSA-SHA2-128s' }
  if (protection.pqc_suite === 'avikal-pqc-openssl-hybrid-kem-triple-stack-v1') return { post_quantum_kem: 'ML-KEM-1024', classical_kem: 'X25519', authentication_signature: 'ML-DSA-87', long_term_signature: 'SLH-DSA-SHA2-256s' }
  return {}
}

function statusStyle(status: CheckStatus) {
  if (status === 'passed') return { icon: CheckCircle2, label: 'Passed', classes: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200' }
  if (status === 'failed') return { icon: TriangleAlert, label: 'Failed', classes: 'border-red-500/30 bg-red-500/10 text-red-800 dark:text-red-200' }
  if (status === 'not_applicable') return { icon: Info, label: 'Not applicable', classes: 'border-av-border/60 bg-av-border/10 text-av-muted' }
  return { icon: Clock3, label: 'Not checked', classes: 'border-amber-500/25 bg-amber-500/10 text-amber-800 dark:text-amber-200' }
}

function Metric({ label, value, detail, mono = false }: { label: string; value: ReactNode; detail?: string; mono?: boolean }) {
  return <div className="min-w-0 rounded-2xl border border-av-border/55 bg-av-surface/75 p-4 shadow-sm">
    <p className="text-[10px] font-bold uppercase tracking-[0.14em] text-av-muted">{label}</p>
    <div className={`mt-2 break-words text-sm font-semibold text-av-main ${mono ? 'font-mono text-xs' : ''}`}>{value}</div>
    {detail && <p className="mt-1.5 text-[11px] leading-5 text-av-muted">{detail}</p>}
  </div>
}

function Section({ title, description, icon, children }: { title: string; description?: string; icon: ReactNode; children: ReactNode }) {
  return <section className="rounded-[22px] border border-av-border/55 bg-av-surface/55 p-4 sm:p-5">
    <div className="mb-4 flex items-start gap-3 text-av-main">
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-av-border/60 bg-av-border/15">{icon}</span>
      <div><h3 className="text-sm font-bold">{title}</h3>{description && <p className="mt-1 text-xs leading-5 text-av-muted">{description}</p>}</div>
    </div>
    {children}
  </section>
}

function StatusBadge({ status }: { status: CheckStatus }) {
  const style = statusStyle(status)
  const Icon = style.icon
  return <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-[0.1em] ${style.classes}`}><Icon className="h-3 w-3" />{style.label}</span>
}

function CopyHash({ value, label }: { value: unknown; label: string }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(text(value, '')); toast.success(`${label} copied`) } catch { toast.error('Clipboard access failed') }
  }
  return <button type="button" onClick={() => void copy()} className="flex w-full items-center justify-between gap-3 text-left"><span className="break-all">{shortHash(value)}</span><Copy className="h-3.5 w-3.5 shrink-0 text-av-muted" /></button>
}

function EvidenceValue({ label, value }: { label: string; value: unknown }) {
  const copy = async () => {
    try { await navigator.clipboard.writeText(text(value, '')); toast.success(`${label} copied`) } catch { toast.error('Clipboard access failed') }
  }
  return <div className="min-w-0 rounded-xl border border-av-border/45 bg-av-border/[0.06] px-3 py-2.5">
    <div className="flex items-center justify-between gap-3"><span className="text-[9px] font-bold uppercase tracking-[0.14em] text-av-muted">{label}</span><button type="button" onClick={() => void copy()} className="text-av-muted hover:text-av-main" aria-label={`Copy ${label}`}><Copy className="h-3 w-3" /></button></div>
    <p className="mt-1.5 break-all font-mono text-[10px] leading-4 text-av-main">{text(value)}</p>
  </div>
}

function EvidenceRow({ title, profile, status, reason, values }: { title: string; profile: string; status: CheckStatus; reason: string; values: Array<{ label: string; value: unknown }> }) {
  return <article className="rounded-2xl border border-av-border/55 bg-av-surface/70 p-4">
    <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
      <div><h4 className="text-sm font-bold text-av-main">{title}</h4><p className="mt-1 font-mono text-[10px] leading-4 text-av-muted">{profile}</p></div>
      <div className="flex items-center gap-2"><span className="font-mono text-[9px] text-av-muted">{reason}</span><StatusBadge status={status} /></div>
    </div>
    {values.length > 0 && <div className={`mt-3 grid gap-2 ${values.length > 1 ? 'lg:grid-cols-2' : ''}`}>{values.map(item => <EvidenceValue key={item.label} label={item.label} value={item.value} />)}</div>}
  </article>
}

export default function ArchiveReportModal({ report, title = 'Archive assurance report', onClose }: ArchiveReportModalProps) {
  const [activeTab, setActiveTab] = useState<ReportTab>('summary')
  const [exporting, setExporting] = useState(false)
  const archive = record(report.archive)
  const compatibility = record(report.compatibility)
  const assurance = record(report.assurance)
  const payload = record(report.payload)
  const protection = record(report.protection)
  const chess = record(report.chess)
  const timings = record(report.timings)
  const operation = record(report.operation)
  const runtime = record(report.runtime_attestation)
  const ledger = list(report.verification_ledger).map(record)
  const evidence = record(report.verification_evidence)
  const evidenceSignatures = record(evidence.signatures)
  const signedManifest = useMemo(() => parseSignedManifest(evidence), [evidence])
  const pqcAlgorithms = resolvedPqcAlgorithms(protection)
  const [evidenceDigests, setEvidenceDigests] = useState<Record<string, string>>({})
  const limitations = list(report.limitations).map(item => text(item)).filter(Boolean)
  const redaction = record(report.redaction_declaration)
  const isCreation = report.report_type === 'archive_creation'
  const wholeVerified = assurance.whole_payload_verified === true
  const selectedVerified = assurance.selected_content_verified === true
  const signatureValid = assurance.verified !== false && Boolean(report.verification_evidence)
  const createdAtRaw = archive.created_at_utc ?? assurance.created_at_utc
  const createdAt = dateDetails(archive.created_at_iso_utc ?? createdAtRaw)
  const reportGeneratedAt = dateDetails(report.generated_at_utc)
  const statisticsAvailable = chess.statistics_status !== 'unavailable' && Number(chess.mainline_plies) > 0
  const overallState = isCreation ? 'committed' : wholeVerified ? 'verified' : selectedVerified ? 'partial' : 'metadata'
  const mlSignatureBytes = decodeBase64(evidenceSignatures.ml_dsa)?.byteLength
  const slhSignatureBytes = decodeBase64(evidenceSignatures.slh_dsa)?.byteLength
  const manifestBytes = decodeBase64(evidence.manifest)?.byteLength
  const identityKind = text(assurance.identity_kind ?? protection.signing_identity_kind, 'archive')
  const identityTrust = assurance.identity_trust ?? (identityKind === 'creator' ? 'valid_untrusted' : 'archive_scoped')

  useEffect(() => {
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const handleKey = (event: KeyboardEvent) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', handleKey)
    return () => { document.body.style.overflow = previousOverflow; window.removeEventListener('keydown', handleKey) }
  }, [onClose])

  useEffect(() => {
    let active = true
    const sources: Array<[string, Uint8Array | null]> = [
      ['signed_manifest', decodeBase64(evidence.manifest)],
      ['ml_dsa_signature', decodeBase64(evidenceSignatures.ml_dsa)],
      ['slh_dsa_signature', decodeBase64(evidenceSignatures.slh_dsa)],
    ]
    void Promise.all(sources.map(async ([key, bytes]) => [key, await sha256Hex(bytes)] as const)).then(items => {
      if (!active) return
      setEvidenceDigests(Object.fromEntries(items.filter((item): item is readonly [string, string] => Boolean(item[1]))))
    })
    return () => { active = false }
  }, [evidence.manifest, evidenceSignatures.ml_dsa, evidenceSignatures.slh_dsa])

  const ledgerById = useMemo(() => new Map(ledger.map(entry => [text(entry.id, ''), entry])), [ledger])
  const ledgerStatus = (id: string): CheckStatus => text(ledgerById.get(id)?.status, 'not_checked') as CheckStatus
  const ledgerReason = (id: string): string => text(ledgerById.get(id)?.reason_code, 'NO_RESULT')

  const timingRows = useMemo(() => Object.entries(timings)
    .filter(([key, value]) => typeof value === 'number' && key.endsWith('_ms'))
    .map(([key, value]) => ({ key, label: titleCase(key.replace(/_ms$/, '')), numeric: Number(value), value: formatDuration(value) }))
    .sort((left, right) => right.numeric - left.numeric), [timings])

  const exportReport = async (format: 'json' | 'pdf') => {
    if (!window.electron?.exportAssuranceReport) { toast.error('Report export is unavailable'); return }
    try {
      setExporting(true)
      const archiveId = text(archive.archive_id, 'archive').slice(0, 12)
      const destination = await window.electron.exportAssuranceReport({ report, format, defaultPath: `avikal-${archiveId}-assurance.${format}` })
      if (destination) toast.success(`${format.toUpperCase()} report exported`)
    } catch (error) {
      toast.error(error instanceof Error ? error.message : 'Report export failed')
    } finally { setExporting(false) }
  }

  const tabs: Array<{ id: ReportTab; label: string; icon: typeof Archive }> = [
    { id: 'summary', label: 'Summary', icon: Archive },
    { id: 'checks', label: 'Verification', icon: ShieldCheck },
    { id: 'protection', label: 'Protection', icon: LockKeyhole },
    { id: 'contents', label: 'Contents', icon: FileCheck2 },
    { id: 'performance', label: 'Performance', icon: Gauge },
    { id: 'chess', label: 'Chess-PGN', icon: Activity },
    { id: 'technical', label: 'Technical', icon: Cpu },
  ]

  const modal = <div className="av-processing-overlay fixed inset-x-0 bottom-0 top-16 z-[210] flex items-center justify-center p-2 sm:p-5 lg:p-7">
    <div role="dialog" aria-modal="true" aria-label={title} className="av-result-card flex h-full max-h-[920px] w-full max-w-6xl flex-col overflow-hidden rounded-[24px] border border-av-border/70 bg-av-surface shadow-2xl sm:rounded-[30px]">
      <header className="shrink-0 border-b border-av-border/55 px-4 py-4 sm:px-6">
        <div className="flex items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-3">
            <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"><ShieldCheck className="h-5 w-5" /></span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2"><h2 className="text-lg font-bold text-av-main sm:text-xl">{title}</h2><StatusBadge status={signatureValid ? 'passed' : 'failed'} /></div>
              <p className="mt-1 text-xs leading-5 text-av-muted">{overallState === 'committed' ? 'Signed creation commitments recorded' : overallState === 'verified' ? 'Entire archive verified' : overallState === 'partial' ? 'Selected content verified' : 'Metadata and index authenticated'} · Schema {text(report.schema_version)}</p>
            </div>
          </div>
          <button type="button" onClick={onClose} className="rounded-xl border border-av-border/60 p-2.5 text-av-muted transition hover:bg-av-border/15 hover:text-av-main" aria-label="Close report"><X className="h-4 w-4" /></button>
        </div>
        <div className="mt-4 flex flex-col gap-3 xl:flex-row xl:items-center xl:justify-between">
          <nav className="custom-scrollbar flex gap-1 overflow-x-auto rounded-xl border border-av-border/35 bg-av-border/10 p-1" aria-label="Report sections">{tabs.map(tab => { const Icon = tab.icon; return <button key={tab.id} type="button" onClick={() => setActiveTab(tab.id)} className={`inline-flex whitespace-nowrap items-center gap-1.5 rounded-lg px-3 py-2 text-xs font-semibold transition ${activeTab === tab.id ? 'bg-av-main text-av-surface shadow-sm' : 'text-av-muted hover:bg-av-border/15 hover:text-av-main'}`}><Icon className="h-3.5 w-3.5" />{tab.label}</button> })}</nav>
          <div className="flex shrink-0 gap-2"><button disabled={exporting} onClick={() => void exportReport('json')} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl border border-av-border/60 px-3 py-2 text-xs font-semibold text-av-main hover:bg-av-border/15 disabled:opacity-50"><FileJson className="h-4 w-4" />Verifiable JSON</button><button disabled={exporting} onClick={() => void exportReport('pdf')} className="inline-flex flex-1 items-center justify-center gap-2 rounded-xl bg-av-main px-3 py-2 text-xs font-semibold text-av-surface disabled:opacity-50"><Download className="h-4 w-4" />Readable PDF</button></div>
        </div>
      </header>

      <main className="custom-scrollbar min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
        {activeTab === 'summary' && <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Payload format" value={text(payload.format, titleCase(archive.kind))} /><Metric label="Contents" value={`${text(archive.file_count, '0')} files · ${text(archive.folder_count, '0')} folders`} /><Metric label="Original size" value={formatBytes(archive.total_original_size)} /><Metric label="Final archive" value={formatBytes(archive.output_archive_size)} /></div>
          <Section title="Creation and compatibility" description="Human-readable times are derived from the signed raw timestamp." icon={<CalendarClock className="h-4 w-4" />}>
            <div className="grid gap-3 lg:grid-cols-2"><Metric label={`Created · ${createdAt?.zone || 'Local time'}`} value={createdAt?.local || 'Not recorded'} detail={createdAt ? `UTC: ${createdAt.utc}` : undefined} /><Metric label="Producer compatibility" value={`Avikal ${text(archive.created_with_version ?? compatibility.created_with_version)}`} detail={`Minimum reader: ${text(archive.minimum_reader_version ?? compatibility.minimum_reader_version)}`} /><Metric label="Archive ID" mono value={<CopyHash value={archive.archive_id ?? assurance.archive_id} label="Archive ID" />} /><Metric label="Verification scope" value={overallState === 'committed' ? 'Committed at creation' : overallState === 'verified' ? 'Entire archive' : overallState === 'partial' ? 'Selected content only' : 'Metadata and index only'} /></div>
          </Section>
          {archive.sender_message ? <Section title="Authenticated sender message" description="Stored inside protected metadata and shown only after archive authentication." icon={<KeyRound className="h-4 w-4" />}><p className="whitespace-pre-wrap text-sm leading-6 text-av-main">{text(archive.sender_message)}</p></Section> : null}
        </div>}

        {activeTab === 'checks' && <div className="space-y-3">
          <div className="grid gap-3 sm:grid-cols-3"><Metric label="Signature envelope" value={`${text(evidence.format)} / v${text(evidence.signature_version)}`} /><Metric label="Signed manifest" value={manifestBytes ? formatBytes(manifestBytes) : 'Unavailable'} /><Metric label="Verification scope" value={overallState === 'verified' ? 'FULL_PAYLOAD' : overallState === 'partial' ? 'SELECTED_ENTRIES' : overallState === 'committed' ? 'CREATION_COMMITMENT' : 'METADATA_INDEX'} /></div>
          <EvidenceRow title="Archive signature · ML-DSA" profile={`${text(record(assurance.algorithms).ml_dsa ?? record(protection.signature_algorithms).ml_dsa)} · ${mlSignatureBytes ? formatBytes(mlSignatureBytes) : 'size unavailable'}`} status={ledgerStatus('archive_signatures')} reason={ledgerReason('archive_signatures')} values={[{ label: 'Signature SHA-256', value: evidenceDigests.ml_dsa_signature ?? 'Computing SHA-256...' }]} />
          <EvidenceRow title="Archive signature · SLH-DSA" profile={`${text(record(assurance.algorithms).slh_dsa ?? record(protection.signature_algorithms).slh_dsa)} · ${slhSignatureBytes ? formatBytes(slhSignatureBytes) : 'size unavailable'}`} status={ledgerStatus('archive_signatures')} reason={ledgerReason('archive_signatures')} values={[{ label: 'Signature SHA-256', value: evidenceDigests.slh_dsa_signature ?? 'Computing SHA-256...' }]} />
          <EvidenceRow title="Signed archive manifest" profile={`${text(signedManifest.domain)} · canonical JSON · ${manifestBytes ? formatBytes(manifestBytes) : 'unknown size'}`} status={ledgerStatus('manifest')} reason={ledgerReason('manifest')} values={[{ label: 'Manifest SHA-256', value: evidenceDigests.signed_manifest ?? 'Computing SHA-256...' }, { label: 'Canonical metadata manifest', value: signedManifest.canonical_manifest_sha256 ?? payload.manifest_sha256 }]} />
          <EvidenceRow title="Chess-PGN keychain core" profile="SHA-256 binding · signature manifest scope" status={ledgerStatus('keychain_binding')} reason={ledgerReason('keychain_binding')} values={[{ label: 'Keychain core SHA-256', value: signedManifest.keychain_core_sha256 }]} />
          {Boolean(signedManifest.content_index_sha256 || payload.index_sha256) && <EvidenceRow title="Authenticated content index" profile={`${text(payload.format)} · encrypted canonical index`} status={ledgerStatus('content_index')} reason={ledgerReason('content_index')} values={[{ label: 'Index SHA-256', value: signedManifest.content_index_sha256 ?? payload.index_sha256 }]} />}
          <EvidenceRow title="Payload commitment" profile={`${text(payload.format)} · ${text(payload.chunk_count, 'n/a')} authenticated chunks`} status={ledgerStatus('payload')} reason={ledgerReason('payload')} values={[{ label: 'Payload SHA-256', value: signedManifest.payload_sha256 ?? payload.payload_sha256 ?? assurance.payload_sha256 }, { label: 'Payload Merkle root', value: signedManifest.payload_merkle_root ?? payload.merkle_root_sha256 ?? assurance.payload_merkle_root }]} />
          <EvidenceRow title="Signing identity" profile={`${titleCase(evidence.identity_kind)} identity · ${titleCase(identityTrust)}`} status={ledgerStatus('creator_identity')} reason={ledgerReason('creator_identity')} values={[{ label: 'Identity fingerprint', value: assurance.identity_fingerprint ?? protection.signing_identity_fingerprint ?? signedManifest.signing_identity_id }]} />
          {Boolean(assurance.timestamp_imprint_sha256 || protection.timestamp_imprint_sha256) && <EvidenceRow title="Creation-time statement" profile={`${titleCase(assurance.timestamp_status ?? protection.timestamp_status)} · SHA-256 imprint`} status={ledgerStatus('trusted_timestamp')} reason={ledgerReason('trusted_timestamp')} values={[{ label: 'Timestamp imprint SHA-256', value: assurance.timestamp_imprint_sha256 ?? protection.timestamp_imprint_sha256 }]} />}
          {Boolean(protection.pqc) && <EvidenceRow title="Hybrid PQC confidentiality" profile={`${text(pqcAlgorithms.post_quantum_kem)} + ${text(pqcAlgorithms.classical_kem, 'X25519')} · ${titleCase(protection.pqc_storage_mode)}`} status={ledgerStatus('pqc_confidentiality')} reason={ledgerReason('pqc_confidentiality')} values={[{ label: 'PQC suite ID', value: protection.pqc_suite }, { label: 'PQC key ID', value: signedManifest.pqc_key_id }]} />}
        </div>}

        {activeTab === 'protection' && <div className="space-y-4">
          <Section title="Cryptographic profile" description="Resolved primitives and parameters used by this archive." icon={<LockKeyhole className="h-4 w-4" />}><div className="overflow-hidden rounded-2xl border border-av-border/55">{
            [
              { layer: 'Payload AEAD', primitive: encryptionProfile(protection.encryption_method), parameters: protection.encryption_method === 'plaintext_archive' ? 'NONE' : 'KEY=256 · NONCE=96 · TAG=128 bits' },
              protection.password_protection_enabled === true ? { layer: 'Password KDF', primitive: 'Argon2id → HKDF-SHA256', parameters: 'm=262144 KiB · t=3 · p=4 · L=256 bits' } : null,
              protection.keyphrase_protection_enabled === true ? { layer: 'Recovery phrase', primitive: 'Avikal Devanagari-2048 v1', parameters: '21 words · checksummed mnemonic' } : null,
              protection.pqc ? { layer: 'Hybrid KEM', primitive: `${text(pqcAlgorithms.post_quantum_kem)} + ${text(pqcAlgorithms.classical_kem, 'X25519')}`, parameters: `HKDF-SHA3-256 · ${text(protection.pqc_suite)}` } : null,
              protection.pqc ? { layer: 'PQC bundle signatures', primitive: `${text(pqcAlgorithms.authentication_signature)} + ${text(pqcAlgorithms.long_term_signature)}`, parameters: `${titleCase(protection.pqc_storage_mode)} key material` } : null,
              { layer: 'Archive signatures', primitive: `${text(record(assurance.algorithms).ml_dsa ?? record(protection.signature_algorithms).ml_dsa)} + ${text(record(assurance.algorithms).slh_dsa ?? record(protection.signature_algorithms).slh_dsa)}`, parameters: 'Canonical manifest · dual verification required' },
              protection.timecapsule_provider ? { layer: 'Time release', primitive: titleCase(protection.timecapsule_provider), parameters: titleCase(assurance.timecapsule_result) } : null,
            ].filter((item): item is { layer: string; primitive: string; parameters: string } => Boolean(item)).map((item, index) => <div key={item.layer} className={`grid gap-1 px-4 py-3 sm:grid-cols-[150px_1fr_1.25fr] sm:items-center ${index ? 'border-t border-av-border/45' : ''}`}><span className="text-[10px] font-bold uppercase tracking-[0.12em] text-av-muted">{item.layer}</span><span className="font-mono text-xs font-semibold text-av-main">{item.primitive}</span><span className="font-mono text-[10px] text-av-muted">{item.parameters}</span></div>)
          }</div></Section>
          <Section title="Identity envelope" icon={<Fingerprint className="h-4 w-4" />}><div className="grid gap-3 lg:grid-cols-2"><EvidenceValue label="Signing fingerprint" value={assurance.identity_fingerprint ?? protection.signing_identity_fingerprint} />{Boolean(assurance.timestamp_imprint_sha256 ?? protection.timestamp_imprint_sha256) && <EvidenceValue label="Timestamp statement imprint" value={assurance.timestamp_imprint_sha256 ?? protection.timestamp_imprint_sha256} />}</div><div className="mt-3 grid gap-3 sm:grid-cols-3"><Metric label="Identity class" value={titleCase(identityKind)} /><Metric label="Identity scope" value={titleCase(identityTrust)} /><Metric label="Timestamp state" value={titleCase(assurance.timestamp_status ?? protection.timestamp_status)} /></div></Section>
        </div>}

        {activeTab === 'contents' && <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Payload format" value={text(payload.format)} /><Metric label="Authenticated chunks" value={text(payload.chunk_count)} /><Metric label="Index size" value={formatBytes(payload.index_bytes)} /><Metric label="Stored payload" value={formatBytes(payload.stored_payload_bytes)} /></div>
          <Section title="Signed commitments" description="These digests bind the keychain, index, manifest and payload into the dual-signature envelope." icon={<HardDrive className="h-4 w-4" />}><div className="grid gap-3"><Metric label="Payload SHA-256" mono value={<CopyHash value={payload.payload_sha256 ?? assurance.payload_sha256} label="Payload hash" />} /><Metric label="Index SHA-256" mono value={<CopyHash value={payload.index_sha256 ?? assurance.content_index_sha256} label="Index hash" />} /><Metric label="Manifest SHA-256" mono value={<CopyHash value={payload.manifest_sha256 ?? assurance.canonical_manifest_sha256} label="Manifest hash" />} /><Metric label="Merkle root" mono value={<CopyHash value={payload.merkle_root_sha256 ?? assurance.payload_merkle_root} label="Merkle root" />} /></div></Section>
          {list(report.verified_files).length > 0 && <Section title="Verified files" description="Only entries listed here were decrypted and individually authenticated during selective recovery." icon={<FileCheck2 className="h-4 w-4" />}><div className="space-y-2">{list(report.verified_files).slice(0, 250).map((item, index) => { const file = record(item); return <div key={`${text(file.entry_id)}-${index}`} className="flex items-center justify-between gap-4 rounded-xl border border-av-border/45 px-3 py-2.5"><div className="min-w-0"><p className="truncate text-xs font-semibold text-av-main">{text(file.relative_path)}</p><p className="mt-0.5 font-mono text-[9px] text-av-muted">{shortHash(file.sha256)}</p></div><div className="shrink-0 text-right"><p className="text-[10px] font-semibold text-av-main">{formatBytes(file.size)}</p><p className="text-[9px] text-av-muted">{text(file.chunks_verified, '0')} chunks</p></div></div> })}</div></Section>}
        </div>}

        {activeTab === 'performance' && <div className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Operation" value={titleCase(operation.mode,)} /><Metric label="Total elapsed" value={formatDuration(operation.elapsed_ms ?? timings.total_processing_ms ?? timings.session_open_ms)} /><Metric label="Throughput" value={operation.throughput_mib_s ? `${text(operation.throughput_mib_s)} MiB/s` : 'Not recorded'} /><Metric label="Bytes processed" value={formatBytes(operation.verified_bytes ?? timings.source_bytes_read)} /></div>
          <Section title="Processing stages" description="Sorted from the most expensive measured stage to the least expensive." icon={<Gauge className="h-4 w-4" />}><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{timingRows.length ? timingRows.map((row, index) => <Metric key={row.key} label={row.label} value={row.value} detail={index === 0 ? 'Largest measured stage' : undefined} />) : <p className="text-sm text-av-muted">No stage timings were recorded for this operation.</p>}</div></Section>
          <Section title="Storage efficiency" icon={<Layers3 className="h-4 w-4" />}><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Original bytes" value={formatBytes(payload.original_bytes ?? archive.total_original_size)} /><Metric label="Stored payload" value={formatBytes(payload.stored_payload_bytes)} /><Metric label="Bytes saved" value={formatBytes(payload.bytes_saved)} /><Metric label="Compression ratio" value={Number.isFinite(Number(payload.compression_ratio)) ? `${(Number(payload.compression_ratio) * 100).toFixed(1)}% of original` : 'Not recorded'} /></div></Section>
        </div>}

        {activeTab === 'chess' && <div className="space-y-4">
          {!statisticsAvailable && <div className="rounded-2xl border border-amber-500/30 bg-amber-500/10 p-4"><div className="flex gap-3"><TriangleAlert className="mt-0.5 h-5 w-5 shrink-0 text-amber-700 dark:text-amber-300" /><div><h3 className="text-sm font-bold text-amber-900 dark:text-amber-100">Chess statistics unavailable</h3><p className="mt-1 text-xs leading-5 text-amber-800 dark:text-amber-200">The codec did not return a consistent measured statistics set. Avikal does not substitute misleading zero values.</p></div></div></div>}
          {statisticsAvailable && <><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="Mainline plies" value={text(chess.mainline_plies)} detail="Moves on the primary game line." /><Metric label="Variation plies" value={text(chess.variation_plies)} detail="Moves encoded inside variation lines." /><Metric label="Total plies" value={text(chess.total_plies)} detail="Mainline and variation moves combined." /><Metric label="Variation branches" value={text(chess.branch_count ?? chess.total_variation_branches)} detail="Observable recursive PGN branches." /></div><Section title="Carrier structure" description="Chess-PGN is Avikal's reversible metadata carrier; encryption remains the confidentiality boundary." icon={<Activity className="h-4 w-4" />}><div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><Metric label="PGN document" value={formatBytes(chess.pgn_bytes)} /><Metric label="Metadata" value={formatBytes(chess.metadata_bytes)} /><Metric label="Encoded envelope" value={formatBytes(chess.encoded_envelope_bytes)} /><Metric label="Nesting depth" value={text(chess.max_nesting_depth)} /><Metric label="Positions with variations" value={chess.statistics_status === 'measured_from_pgn' ? 'Requires native measurement' : text(chess.positions_with_variations)} /><Metric label="Maximum branches at a position" value={chess.statistics_status === 'measured_from_pgn' ? 'Requires native measurement' : text(chess.max_variations_at_position)} /><Metric label="Statistics source" value={titleCase(chess.statistics_status)} /></div></Section></>}
        </div>}

        {activeTab === 'technical' && <div className="space-y-4">
          <Section title="Local runtime observation" description="These hashes identify the runtime that generated this report. They are observations, not archive-signed commitments." icon={<Cpu className="h-4 w-4" />}><div className="grid gap-3 md:grid-cols-2"><Metric label="Platform" value={`${text(runtime.platform)} · ${text(runtime.architecture)}`} /><Metric label="Avikal runtime" value={text(runtime.avikal_version)} /><Metric label="Native crypto module" mono value={<CopyHash value={runtime.native_module_sha256} label="Native module hash" />} /><Metric label="PQC runtime" mono value={<CopyHash value={runtime.pqc_runtime_sha256} label="PQC runtime hash" />} /><Metric label="OpenSSL" value={text(runtime.openssl_version)} /><Metric label="Runtime manifest" mono value={<CopyHash value={runtime.runtime_manifest_sha256} label="Runtime manifest hash" />} /></div></Section>
          <Section title="Report integrity" icon={<FileJson className="h-4 w-4" />}><div className="grid gap-3 md:grid-cols-2"><Metric label="Format" value={text(report.format)} /><Metric label="Generated" value={reportGeneratedAt?.local || text(report.generated_at_utc)} detail={reportGeneratedAt ? `UTC: ${reportGeneratedAt.utc}` : undefined} /><Metric label="Report digest SHA-256" mono value={<CopyHash value={report.report_digest_sha256} label="Report digest" />} /><Metric label="Evidence scope" value={titleCase(record(report.verification_scope).archive_commitments)} /></div><p className="mt-4 text-xs leading-5 text-av-muted">Verify the JSON export offline with <span className="font-mono text-av-main">avikal verify-report &lt;file.json&gt;</span>. PDF is a human-readable presentation copy.</p></Section>
          <Section title="Disclosure and limitations" icon={<Info className="h-4 w-4" />}><div className="grid gap-4 lg:grid-cols-2"><div><h4 className="text-xs font-bold uppercase tracking-[0.12em] text-av-muted">Intentionally excluded</h4><ul className="mt-2 space-y-2">{list(redaction.excluded_categories).map((item, index) => <li key={index} className="flex gap-2 text-xs leading-5 text-av-main"><Check className="mt-1 h-3 w-3 shrink-0 text-emerald-600" />{titleCase(item)}</li>)}</ul></div><div><h4 className="text-xs font-bold uppercase tracking-[0.12em] text-av-muted">Limitations</h4><ul className="mt-2 space-y-2">{limitations.map((item, index) => <li key={index} className="flex gap-2 text-xs leading-5 text-av-main"><TriangleAlert className="mt-1 h-3 w-3 shrink-0 text-amber-600" />{item}</li>)}</ul></div></div></Section>
        </div>}
      </main>
    </div>
  </div>

  return createPortal(modal, document.body)
}
