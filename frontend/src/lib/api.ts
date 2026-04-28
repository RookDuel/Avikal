/**
 * API client for the Avikal backend.
 *
 * All outbound fetch calls are wrapped with a 30-second timeout.
 * Safe-to-retry requests are wrapped with retry logic for transient failures.
 */

import { BACKEND_BASE_URL } from './backend'
import { withRetry } from './retry'

const API_BASE = BACKEND_BASE_URL

async function readErrorResponse(response: Response, fallback: string): Promise<string> {
  const contentType = response.headers.get('content-type') || ''

  try {
    if (contentType.includes('application/json')) {
      const payload = await response.json()
      return payload?.detail || payload?.error || payload?.message || fallback
    }

    const text = (await response.text()).trim()
    if (!text) return fallback

    try {
      const parsed = JSON.parse(text)
      return parsed?.detail || parsed?.error || parsed?.message || text
    } catch {
      return text
    }
  } catch {
    return fallback
  }
}

export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 30_000,
): Promise<Response> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await fetch(url, { ...options, signal: controller.signal })
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw new Error(`Network error: request timed out after ${timeoutMs / 1000}s`)
    }
    throw err
  } finally {
    clearTimeout(timer)
  }
}

export interface EncryptRequest {
  input_files: string[]
  output_file: string
  password?: string
  keyphrase?: string[]
  unlock_datetime?: string
  use_timecapsule: boolean
  timecapsule_provider?: 'aavrit' | 'drand'
  pqc_enabled?: boolean
  pqc_keyfile_output?: string
}

export interface DecryptRequest {
  input_file: string
  output_dir: string
  password?: string
  keyphrase?: string[]
  pqc_keyfile?: string
}

export interface PreviewCleanupRequest {
  session_id: string
}

export interface ArchiveInspectRequest {
  input_file: string
}

export interface VerifySessionRequest {
  session_token: string
  aavrit_url?: string
}

export const api = {
  async encrypt(data: EncryptRequest, token?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (data.use_timecapsule && data.timecapsule_provider === 'aavrit' && token) {
      headers.Authorization = `Bearer ${token}`
    }

    const response = await fetch(`${API_BASE}/api/encrypt`, {
      method: 'POST',
      headers,
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Encryption failed'))
    return response.json()
  },

  async decrypt(data: DecryptRequest, token?: string) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    if (token) {
      headers.Authorization = `Bearer ${token}`
    }

    const response = await fetch(`${API_BASE}/api/decrypt`, {
      method: 'POST',
      headers,
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Decryption failed'))
    return response.json()
  },

  async inspectArchive(data: ArchiveInspectRequest) {
    const response = await fetchWithTimeout(`${API_BASE}/api/archive/inspect`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Archive inspection failed'))
    return response.json()
  },

  async cleanupDecryptSession(data: PreviewCleanupRequest) {
    const response = await fetchWithTimeout(`${API_BASE}/api/decrypt/cleanup-session`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    if (!response.ok) throw new Error(await readErrorResponse(response, 'Preview cleanup failed'))
    return response.json()
  },

  async generateKeyphrase(wordCount = 21) {
    return withRetry(async () => {
      const response = await fetchWithTimeout(`${API_BASE}/api/generate-keyphrase`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ word_count: wordCount, language: 'hindi' }),
      })
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Keyphrase generation failed'))
      return response.json()
    })
  },

  async verifySession(sessionToken: string, aavritUrl?: string) {
    return withRetry(async () => {
      const response = await fetchWithTimeout(`${API_BASE}/api/auth/verify-session`, {
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
      const response = await fetchWithTimeout(`${API_BASE}/api/auth/profile`, { headers })
      if (!response.ok) throw new Error(await readErrorResponse(response, 'Profile fetch failed'))
      return response.json()
    })
  },

  async logout() {
    const response = await fetchWithTimeout(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
    })
    return response.json()
  },
}
