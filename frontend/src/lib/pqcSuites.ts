export const PQC_MAXIMUM_SUITE_ID = 'avikal-pqc-openssl-hybrid-kem-triple-stack-v1' as const
export const PQC_STANDARD_SUITE_ID = 'avikal-pqc-std-v1' as const
export const PQC_CUSTOM_SUITE_ID = 'avikal-pqc-custom-v1' as const

export type PqcSuiteId =
  | typeof PQC_MAXIMUM_SUITE_ID
  | typeof PQC_STANDARD_SUITE_ID
  | typeof PQC_CUSTOM_SUITE_ID

export const ML_KEM_OPTIONS = ['ML-KEM-768', 'ML-KEM-1024'] as const
export const ML_DSA_OPTIONS = ['ML-DSA-65', 'ML-DSA-87'] as const
export const SLH_DSA_OPTIONS = [
  'SLH-DSA-SHA2-128s',
  'SLH-DSA-SHA2-192s',
  'SLH-DSA-SHA2-256s',
] as const

export type MlKemOption = typeof ML_KEM_OPTIONS[number]
export type MlDsaOption = typeof ML_DSA_OPTIONS[number]
export type SlhDsaOption = typeof SLH_DSA_OPTIONS[number]

export const DEFAULT_PQC_SUITE_ID: PqcSuiteId = PQC_MAXIMUM_SUITE_ID
export const DEFAULT_CUSTOM_KEM: MlKemOption = 'ML-KEM-1024'
export const DEFAULT_CUSTOM_SIGNATURE: MlDsaOption = 'ML-DSA-87'
export const DEFAULT_CUSTOM_SLH_SIGNATURE: SlhDsaOption = 'SLH-DSA-SHA2-256s'

export const PQC_SUITE_CHOICES = [
  {
    id: PQC_STANDARD_SUITE_ID,
    label: 'Standard',
    badge: 'Balanced',
    description: 'Fast NIST stack',
  },
  {
    id: PQC_MAXIMUM_SUITE_ID,
    label: 'Maximum',
    badge: 'Default',
    description: 'Highest archival stack',
  },
  {
    id: PQC_CUSTOM_SUITE_ID,
    label: 'Custom',
    badge: 'Expert',
    description: 'Guarded manual suite',
  },
] as const

export function pqcSuiteLabel(suiteId: PqcSuiteId): string {
  if (suiteId === PQC_STANDARD_SUITE_ID) return 'Standard PQC'
  if (suiteId === PQC_CUSTOM_SUITE_ID) return 'Custom PQC'
  return 'Maximum PQC'
}

export function pqcSuiteSummary(
  suiteId: PqcSuiteId,
  customKem = DEFAULT_CUSTOM_KEM,
  customSignature = DEFAULT_CUSTOM_SIGNATURE,
  customSlhSignature = DEFAULT_CUSTOM_SLH_SIGNATURE,
): string {
  if (suiteId === PQC_STANDARD_SUITE_ID) return 'ML-KEM-768 + X25519, ML-DSA-65, SLH-DSA-SHA2-128s'
  if (suiteId === PQC_CUSTOM_SUITE_ID) return `${customKem} + X25519, ${customSignature}, ${customSlhSignature}`
  return 'ML-KEM-1024 + X25519, ML-DSA-87, SLH-DSA-SHA2-256s'
}
