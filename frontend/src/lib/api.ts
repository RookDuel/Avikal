/**
 * API client for the Avikal backend.
 *
 * All outbound fetch calls are wrapped with a 30-second timeout.
 * Safe-to-retry requests are wrapped with retry logic for transient failures.
 */

import { callCoreResponse, createBackendHeaders } from './backend'
import { waitForBackendReady } from './backendStatus'
import { withRetry } from './retry'

// Active decrypt abort controller — allows mid-flight cancellation
let _decryptAbortController: AbortController | null = null

/** Abort the currently running decrypt request, if any. */
export function cancelDecrypt(): void {
  if (_decryptAbortController) {
    _decryptAbortController.abort()
    _decryptAbortController = null
  }
}

async function readErrorResponse(response: Response, fallback: string): Promise<string> {
  const contentType = response.headers.get('content-type') || ''

  try {
    const toMessage = (value: unknown): string => {
      if (typeof value === 'string') return value.trim()
      if (Array.isArray(value)) {
        return value
          .map((entry) => toMessage(entry))
          .filter(Boolean)
          .join('; ')
      }
      if (value && typeof value === 'object') {
        const payload = value as Record<string, unknown>
        const location = Array.isArray(payload.loc)
          ? payload.loc
              .map((part) => String(part))
              .filter((part) => part !== 'body' && part !== 'query' && part !== 'path')
              .join('.')
          : ''
        const message =
          toMessage(payload.detail)
          || toMessage(payload.message)
          || toMessage(payload.error)
          || toMessage(payload.msg)
        if (location && message) return `${location}: ${message}`
        if (message) return message
      }
      return ''
    }

    if (contentType.includes('application/json')) {
      const payload = await response.json()
      return toMessage(payload?.detail) || toMessage(payload?.error) || toMessage(payload?.message) || fallback
    }

    const text = (await response.text()).trim()
    if (!text) return fallback

    try {
      const parsed = JSON.parse(text)
      return toMessage(parsed?.detail) || toMessage(parsed?.error) || toMessage(parsed?.message) || toMessage(parsed) || text
    } catch {
      return text
    }
  } catch {
    return fallback
  }
}

export async function fetchWithTimeout(
  path: string,
  options: RequestInit = {},
  timeoutMs = 30_000,
): Promise<Response> {
  return callCoreResponse(path, options, timeoutMs)
}

export interface EncryptRequest {
  input_files: string[]
  excluded_input_paths?: string[]
  output_file: string
  password?: string
  keyphrase?: string[]
  unlock_datetime?: string
  use_timecapsule: boolean
  timecapsule_provider?: 'aavrit' | 'drand'
  pqc_enabled?: boolean
  pqc_storage_mode?: 'embedded' | 'external'
  pqc_keyfile_output?: string
  pqc_keyfile_protection_mode?: 'archive_secret' | 'dual_password'
  pqc_keyfile_password?: string
}

export interface DecryptRequest {
  input_file: string
  output_dir?: string
  password?: string
  keyphrase?: string[]
  pqc_keyfile?: string
  pqc_keyfile_password?: string
}

export interface PreviewCleanupRequest {
  session_id: string
}

export interface ArchiveInspectRequest {
  input_file: string
}

export interface PqcKeyfileInspectRequest {
  keyfile_path: string
}

export interface RekeyRequest {
  input_file: string
  output_file: string
  old_password?: string
  old_keyphrase?: string[]
  new_password?: string
  new_keyphrase?: string[]
  force?: boolean
}

export interface KeyphraseWordPair {
  index: number
  hindi: string
  roman: string
}

export interface KeyphraseRomanMapResponse {
  success: boolean
  wordlist_id: string
  roman_wordlist_id: string
  words: KeyphraseWordPair[]
}

export interface VerifySessionRequest {
  session_token: string
  aavrit_url?: string
}

export const api = {
  async encrypt(data: EncryptRequest, token?: string) {
    const headers = await createBackendHeaders({ 'Content-Type': 'application/json' })
    if (data.use_timecapsule && data.timecapsule_provider === 'aavrit' && token) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    const response = await callCoreResponse('archive.encrypt', {
      method: 'POST',
      headers,
      body: JSON.stringify(data),
    }, 0)
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Encryption failed'))
    return response.json()
  },

  async decrypt(data: DecryptRequest, token?: string) {
    const headers = await createBackendHeaders({ 'Content-Type': 'application/json' })
    if (token) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    // Cancel any previous in-flight decrypt
    if (_decryptAbortController) {
      _decryptAbortController.abort()
    }
    _decryptAbortController = new AbortController()
    const signal = _decryptAbortController.signal

    try {
      const response = await callCoreResponse('archive.decrypt', {
        method: 'POST',
        headers,
        body: JSON.stringify(data),
        signal,
      }, 0)
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Decryption failed'))
      return response.json()
    } catch (err) {
      if (err instanceof Error && err.name === 'AbortError') {
        const cancelled = new Error('Decryption cancelled by user.')
        ;(cancelled as Error & { cancelled: boolean }).cancelled = true
        throw cancelled
      }
      throw err
    } finally {
      _decryptAbortController = null
    }
  },

  async inspectArchive(data: ArchiveInspectRequest) {
    const response = await fetchWithTimeout('archive.inspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Archive inspection failed'))
    return response.json()
  },

  async inspectPqcKeyfile(data: PqcKeyfileInspectRequest) {
    const response = await fetchWithTimeout('pqc.keyfileInspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    }, 10_000)
    if (!response.ok) throw new Error(await readErrorResponse(response, 'PQC keyfile inspection failed'))
    return response.json()
  },

  async rekeyArchive(data: RekeyRequest) {
    await waitForBackendReady()
    const response = await fetchWithTimeout('archive.rekey', {
      method: 'POST',
      headers: await createBackendHeaders({ 'Content-Type': 'application/json' }),
      body: JSON.stringify(data),
      }, 120_000)
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Rekey failed'))
    return response.json()
  },

  async cleanupDecryptSession(data: PreviewCleanupRequest) {
    const response = await fetchWithTimeout('preview.cleanupSession', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Preview cleanup failed'))
    return response.json()
  },

  async generateKeyphrase(wordCount = 21) {
    return withRetry(async () => {
      const response = await fetchWithTimeout('keyphrase.generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ word_count: wordCount, language: 'hindi' }),
      })
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Keyphrase generation failed'))
      return response.json()
    })
  },

  async getKeyphraseRomanMap(): Promise<KeyphraseRomanMapResponse> {
    return withRetry(async () => {
      const response = await fetchWithTimeout('keyphrase.romanMap')
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Keyphrase helper loading failed'))
      return response.json()
    })
  },

  async verifySession(sessionToken: string, aavritUrl?: string) {
    return withRetry(async () => {
      const response = await fetchWithTimeout('auth.verifySession', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: sessionToken, aavrit_url: aavritUrl }),
      })
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Session verification failed'))
      return response.json()
    })
  },

  async getUserProfile(token?: string, aavritUrl?: string) {
    return withRetry(async () => {
      const headers: Record<string, string> = {}
      if (token) headers['X-Aavrit-Session'] = token
      if (aavritUrl) headers['X-Aavrit-Server-URL'] = aavritUrl
      const response = await fetchWithTimeout('auth.profile', { headers })
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Profile fetch failed'))
      return response.json()
    })
  },

  async logout(token?: string, aavritUrl?: string) {
    const headers: Record<string, string> = {}
    if (token) headers.Authorization = `Bearer ${token}`
    if (aavritUrl) headers['X-Aavrit-Server-URL'] = aavritUrl
    const response = await fetchWithTimeout('auth.logout', {
      method: 'POST',
      headers,
    })
    return response.json()
  },
}
