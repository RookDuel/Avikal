export type ActivityLogMode = 'off' | 'minimal' | 'detailed'
export type ActivityRetentionDays = 0 | 7 | 30 | 90 | 365
export type PqcStorageMode = 'embedded' | 'external'
export type TimecapsuleProvider = 'drand' | 'aavrit'
export type OverwritePolicy = 'never' | 'ask' | 'allow'
export type OutputFolderMode = 'ask' | 'remember'
export type PreviewCleanupPolicy = 'on_close_15m' | 'manual'
export type LargeFileMode = 'auto' | 'low_resource'
export type DecodeOutputLimit = 'standard' | 'high'
export type VisualEffectsMode = 'auto' | 'effects' | 'normal'

export interface UserPreferences {
  appearance: {
    visual_effects_mode: VisualEffectsMode
  }
  privacy: {
    activity_log_mode: ActivityLogMode
    activity_retention_days: ActivityRetentionDays
    redact_diagnostics: boolean
  }
  archive_defaults: {
    pqc_storage_mode: PqcStorageMode
    remember_keyfile_folder: boolean
    default_timecapsule_provider: TimecapsuleProvider
    overwrite_policy: OverwritePolicy
    output_folder_mode: OutputFolderMode
  }
  preview: {
    cleanup_policy: PreviewCleanupPolicy
  }
  advanced: {
    large_file_mode: LargeFileMode
    decode_output_limit: DecodeOutputLimit
  }
}

export const DEFAULT_USER_PREFERENCES: UserPreferences = {
  appearance: {
    visual_effects_mode: 'auto',
  },
  privacy: {
    activity_log_mode: 'minimal',
    activity_retention_days: 30,
    redact_diagnostics: true,
  },
  archive_defaults: {
    pqc_storage_mode: 'embedded',
    remember_keyfile_folder: false,
    default_timecapsule_provider: 'drand',
    overwrite_policy: 'never',
    output_folder_mode: 'ask',
  },
  preview: {
    cleanup_policy: 'on_close_15m',
  },
  advanced: {
    large_file_mode: 'auto',
    decode_output_limit: 'standard',
  },
}

const STORAGE_KEY = 'avikal-user-preferences'
export const USER_PREFERENCES_UPDATED_EVENT = 'avikal-user-preferences-updated'

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value))
}

function choice<T extends string>(value: unknown, allowed: readonly T[], fallback: T): T {
  return typeof value === 'string' && allowed.includes(value as T) ? value as T : fallback
}

function retention(value: unknown): ActivityRetentionDays {
  return [0, 7, 30, 90, 365].includes(Number(value)) ? Number(value) as ActivityRetentionDays : 30
}

export function sanitizeUserPreferences(raw: unknown): UserPreferences {
  const source = isRecord(raw) ? raw : {}
  const appearance = isRecord(source.appearance) ? source.appearance : {}
  const privacy = isRecord(source.privacy) ? source.privacy : {}
  const archive = isRecord(source.archive_defaults) ? source.archive_defaults : {}
  const preview = isRecord(source.preview) ? source.preview : {}
  const advanced = isRecord(source.advanced) ? source.advanced : {}

  return {
    appearance: {
      visual_effects_mode: choice(appearance.visual_effects_mode, ['auto', 'effects', 'normal'], DEFAULT_USER_PREFERENCES.appearance.visual_effects_mode),
    },
    privacy: {
      activity_log_mode: choice(privacy.activity_log_mode, ['off', 'minimal', 'detailed'], DEFAULT_USER_PREFERENCES.privacy.activity_log_mode),
      activity_retention_days: retention(privacy.activity_retention_days),
      redact_diagnostics: typeof privacy.redact_diagnostics === 'boolean' ? privacy.redact_diagnostics : DEFAULT_USER_PREFERENCES.privacy.redact_diagnostics,
    },
    archive_defaults: {
      pqc_storage_mode: choice(archive.pqc_storage_mode, ['embedded', 'external'], DEFAULT_USER_PREFERENCES.archive_defaults.pqc_storage_mode),
      remember_keyfile_folder: typeof archive.remember_keyfile_folder === 'boolean' ? archive.remember_keyfile_folder : DEFAULT_USER_PREFERENCES.archive_defaults.remember_keyfile_folder,
      default_timecapsule_provider: choice(archive.default_timecapsule_provider, ['drand', 'aavrit'], DEFAULT_USER_PREFERENCES.archive_defaults.default_timecapsule_provider),
      overwrite_policy: choice(archive.overwrite_policy, ['never', 'ask', 'allow'], DEFAULT_USER_PREFERENCES.archive_defaults.overwrite_policy),
      output_folder_mode: choice(archive.output_folder_mode, ['ask', 'remember'], DEFAULT_USER_PREFERENCES.archive_defaults.output_folder_mode),
    },
    preview: {
      cleanup_policy: choice(preview.cleanup_policy, ['on_close_15m', 'manual'], DEFAULT_USER_PREFERENCES.preview.cleanup_policy),
    },
    advanced: {
      large_file_mode: choice(advanced.large_file_mode, ['auto', 'low_resource'], DEFAULT_USER_PREFERENCES.advanced.large_file_mode),
      decode_output_limit: choice(advanced.decode_output_limit, ['standard', 'high'], DEFAULT_USER_PREFERENCES.advanced.decode_output_limit),
    },
  }
}

export function loadUserPreferences(): UserPreferences {
  if (typeof localStorage === 'undefined') return DEFAULT_USER_PREFERENCES
  try {
    return sanitizeUserPreferences(JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null'))
  } catch {
    return DEFAULT_USER_PREFERENCES
  }
}

export function saveUserPreferences(preferences: UserPreferences): void {
  if (typeof localStorage === 'undefined') return
  localStorage.setItem(STORAGE_KEY, JSON.stringify(sanitizeUserPreferences(preferences)))
  window.dispatchEvent(new CustomEvent(USER_PREFERENCES_UPDATED_EVENT, { detail: sanitizeUserPreferences(preferences) }))
}

export function getDefaultPqcStorageMode(): PqcStorageMode {
  return loadUserPreferences().archive_defaults.pqc_storage_mode
}

export function getDefaultTimecapsuleProvider(): TimecapsuleProvider {
  return loadUserPreferences().archive_defaults.default_timecapsule_provider
}
