import {
  ML_DSA_OPTIONS,
  ML_KEM_OPTIONS,
  PQC_CUSTOM_SUITE_ID,
  PQC_MAXIMUM_SUITE_ID,
  PQC_STANDARD_SUITE_ID,
  SLH_DSA_OPTIONS,
  pqcSuiteLabel,
  pqcSuiteSummary,
  type MlDsaOption,
  type MlKemOption,
  type PqcSuiteId,
  type SlhDsaOption,
} from '../lib/pqcSuites'

interface PqcSuiteSelectorProps {
  suiteId: PqcSuiteId
  customKem: MlKemOption
  customSignature: MlDsaOption
  customSlhSignature: SlhDsaOption
  onSuiteChange: (suiteId: PqcSuiteId) => void
  onCustomKemChange: (value: MlKemOption) => void
  onCustomSignatureChange: (value: MlDsaOption) => void
  onCustomSlhSignatureChange: (value: SlhDsaOption) => void
}

export default function PqcSuiteSelector({
  suiteId,
  customKem,
  customSignature,
  customSlhSignature,
  onSuiteChange,
  onCustomKemChange,
  onCustomSignatureChange,
  onCustomSlhSignatureChange,
}: PqcSuiteSelectorProps) {
  const isStandard = suiteId === PQC_STANDARD_SUITE_ID
  const isMaximum = suiteId === PQC_MAXIMUM_SUITE_ID
  const isCustom = suiteId === PQC_CUSTOM_SUITE_ID

  return (
    <div className="rounded-2xl border border-av-border/35 bg-av-surface/60 p-3 shadow-sm dark:bg-av-surface/55 dark:shadow-none">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[10px] font-bold uppercase tracking-[0.18em] text-av-muted">
            PQC Suite
          </p>
          <p className="mt-1 text-xs font-semibold leading-relaxed text-av-main">
            {pqcSuiteSummary(suiteId, customKem, customSignature, customSlhSignature)}
          </p>
        </div>
        <span className="shrink-0 rounded-full border border-av-border/40 bg-av-border/15 px-2 py-0.5 text-[9px] font-bold uppercase tracking-[0.12em] text-av-main">
          {pqcSuiteLabel(suiteId).replace(' PQC', '')}
        </span>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
        <button
          type="button"
          onClick={() => onSuiteChange(PQC_STANDARD_SUITE_ID)}
          className={`rounded-2xl border px-3 py-2.5 text-left transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-blue-500/35 ${
            isStandard
              ? 'border-blue-500/35 bg-blue-500/10 shadow-sm'
              : 'border-av-border/40 bg-av-surface/60 hover:border-blue-500/25 hover:bg-blue-500/[0.055]'
          }`}
        >
          <span className="block text-xs font-semibold text-av-main tracking-tight">Standard</span>
          <span className="mt-0.5 block text-[9px] font-bold uppercase tracking-[0.12em] text-av-muted">
            Balanced
          </span>
        </button>

        <button
          type="button"
          onClick={() => onSuiteChange(PQC_MAXIMUM_SUITE_ID)}
          className={`rounded-2xl border px-3 py-2.5 text-left transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-slate-500/35 ${
            isMaximum
              ? 'border-av-border/70 bg-av-border/20 shadow-sm'
              : 'border-av-border/40 bg-av-surface/60 hover:border-av-border/70 hover:bg-av-border/12'
          }`}
        >
          <span className="block text-xs font-semibold text-av-main tracking-tight">Maximum</span>
          <span className="mt-0.5 block text-[9px] font-bold uppercase tracking-[0.12em] text-av-muted">
            Default
          </span>
        </button>

        <button
          type="button"
          onClick={() => onSuiteChange(PQC_CUSTOM_SUITE_ID)}
          className={`rounded-2xl border px-3 py-2.5 text-left transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-purple-500/35 ${
            isCustom
              ? 'border-purple-500/35 bg-purple-500/10 shadow-sm'
              : 'border-av-border/40 bg-av-surface/60 hover:border-purple-500/25 hover:bg-purple-500/[0.055]'
          }`}
        >
          <span className="block text-xs font-semibold text-av-main tracking-tight">Custom</span>
          <span className="mt-0.5 block text-[9px] font-bold uppercase tracking-[0.12em] text-av-muted">
            Expert
          </span>
        </button>
      </div>

      {isCustom && (
        <div className="mt-3 grid gap-2 rounded-xl border border-av-border/30 bg-container-bg p-2.5 shadow-[inset_0_4px_15px_var(--container-bg)] sm:grid-cols-3">
          <label className="space-y-1">
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-av-muted">KEM</span>
            <select
              value={customKem}
              onChange={(event) => onCustomKemChange(event.target.value as MlKemOption)}
              className="w-full rounded-xl border border-av-border/35 bg-av-surface px-3 py-2.5 text-xs font-semibold text-av-main outline-none transition-colors focus:border-av-border/70"
            >
              {ML_KEM_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <label className="space-y-1">
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-av-muted">ML-DSA</span>
            <select
              value={customSignature}
              onChange={(event) => onCustomSignatureChange(event.target.value as MlDsaOption)}
              className="w-full rounded-xl border border-av-border/35 bg-av-surface px-3 py-2.5 text-xs font-semibold text-av-main outline-none transition-colors focus:border-av-border/70"
            >
              {ML_DSA_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <label className="space-y-1">
            <span className="text-[10px] font-bold uppercase tracking-[0.16em] text-av-muted">SLH-DSA</span>
            <select
              value={customSlhSignature}
              onChange={(event) => onCustomSlhSignatureChange(event.target.value as SlhDsaOption)}
              className="w-full rounded-xl border border-av-border/35 bg-av-surface px-3 py-2.5 text-xs font-semibold text-av-main outline-none transition-colors focus:border-av-border/70"
            >
              {SLH_DSA_OPTIONS.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
        </div>
      )}
    </div>
  )
}
