import type { BackendRequestConfig } from '../types/electron'
import { waitForBackendReady } from './backendStatus'

export const DEFAULT_BACKEND_BASE_URL = 'http://127.0.0.1:5000'
export const DEFAULT_BACKEND_AUTH_HEADER = 'X-Avikal-Backend-Token'

const DEFAULT_BACKEND_REQUEST_CONFIG: BackendRequestConfig = {
  baseUrl: DEFAULT_BACKEND_BASE_URL,
  authHeader: DEFAULT_BACKEND_AUTH_HEADER,
  authToken: null,
}

function normalizeBackendPath(pathname: string): string {
  return pathname.startsWith('/') ? pathname : `/${pathname}`
}

export async function getBackendRequestConfig(): Promise<BackendRequestConfig> {
  if (typeof window === 'undefined' || !window.electron?.getBackendRequestConfig) {
    return DEFAULT_BACKEND_REQUEST_CONFIG
  }

  try {
    const config = await window.electron.getBackendRequestConfig()
    if (!config?.baseUrl || !config?.authHeader) {
      return DEFAULT_BACKEND_REQUEST_CONFIG
    }
    return config
  } catch {
    return DEFAULT_BACKEND_REQUEST_CONFIG
  }
}

export async function buildBackendUrl(pathname: string): Promise<string> {
  const config = await getBackendRequestConfig()
  return `${config.baseUrl}${normalizeBackendPath(pathname)}`
}

export async function createBackendHeaders(
  initialHeaders?: HeadersInit,
  overrides?: { includeAuthToken?: boolean },
): Promise<Headers> {
  const config = await getBackendRequestConfig()
  const headers = new Headers(initialHeaders ?? {})
  const includeAuthToken = overrides?.includeAuthToken ?? true

  if (includeAuthToken && config.authToken && !headers.has(config.authHeader)) {
    headers.set(config.authHeader, config.authToken)
  }

  return headers
}

export async function fetchBackend(
  pathname: string,
  init: RequestInit = {},
  timeoutMs = 30_000,
): Promise<Response> {
  await waitForBackendReady()

  const url = await buildBackendUrl(pathname)
  const headers = await createBackendHeaders(init.headers)
  const controller = new AbortController()
  const timer = window.setTimeout(() => controller.abort(), timeoutMs)

  try {
    return await fetch(url, { ...init, headers, signal: controller.signal })
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw new Error(`Network error: request timed out after ${Math.round(timeoutMs / 1000)}s`)
    }
    throw error
  } finally {
    window.clearTimeout(timer)
  }
}
