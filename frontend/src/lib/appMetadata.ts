export type AvikalReleaseChannel = 'beta' | 'production'

const configuredChannel = String(import.meta.env.VITE_AVIKAL_RELEASE_CHANNEL || 'production').toLowerCase()

export const AVIKAL_RELEASE_CHANNEL: AvikalReleaseChannel =
  configuredChannel === 'production' ? 'production' : 'beta'

export const AVIKAL_IS_BETA = AVIKAL_RELEASE_CHANNEL === 'beta'
