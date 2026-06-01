import { waitForBackendReady } from './backendStatus'
import { invokeCore } from './coreRpc'

export const DEFAULT_BACKEND_BASE_URL = 'stdio://avikal-core'

export async function createBackendHeaders(
  initialHeaders?: HeadersInit,
  _overrides?: { includeAuthToken?: boolean },
): Promise<Headers> {
  return new Headers(initialHeaders ?? {})
}

export async function callCoreResponse(
  pathname: string,
  init: RequestInit = {},
  timeoutMs = 30_000,
): Promise<Response> {
  await waitForBackendReady()
  try {
    if (init.signal?.aborted) {
      throw abortError()
    }
    const { method, params } = await mapBackendRequestToCore(pathname, init)
    const coreRequest = invokeCore(method, params, timeoutMs)
    const result = init.signal
      ? await Promise.race([coreRequest, rejectOnAbort(init.signal)])
      : await coreRequest
    return jsonResponse(result, 200)
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      throw error
    }
    const status = typeof (error as { code?: unknown }).code === 'number'
      ? normalizeStatus((error as { code: number }).code)
      : 500
    const message = error instanceof Error ? error.message : 'Avikal core request failed'
    return jsonResponse({ detail: message, error: message }, status)
  }
}

function abortError(): Error {
  const error = new Error('The operation was aborted.')
  error.name = 'AbortError'
  return error
}

function rejectOnAbort(signal: AbortSignal): Promise<never> {
  return new Promise((_resolve, reject) => {
    if (signal.aborted) {
      reject(abortError())
      return
    }
    signal.addEventListener('abort', () => reject(abortError()), { once: true })
  })
}

function jsonResponse(payload: unknown, status: number): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function normalizeStatus(code: number): number {
  return code >= 400 && code <= 599 ? code : 500
}

async function parseJsonBody(init: RequestInit): Promise<Record<string, unknown>> {
  if (!init.body) return {}
  if (typeof init.body === 'string') {
    const parsed = JSON.parse(init.body)
    return parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : {}
  }
  throw new Error('Unsupported Avikal core request body')
}

function headersToRecord(headersInit?: HeadersInit): Record<string, string> {
  const headers = new Headers(headersInit ?? {})
  const record: Record<string, string> = {}
  headers.forEach((value, key) => {
    record[key.toLowerCase()] = value
  })
  return record
}

async function mapBackendRequestToCore(
  pathname: string,
  init: RequestInit,
): Promise<{ method: string; params: Record<string, unknown> }> {
  const method = (init.method || 'GET').toUpperCase()
  const headers = headersToRecord(init.headers)

  if (!pathname.startsWith('/')) {
    const body = method === 'GET' ? {} : await parseJsonBody(init)
    if (pathname === 'auth.profile') {
      return {
        method: pathname,
        params: {
          session_token: headers['x-aavrit-session'] || '',
          aavrit_url: headers['x-aavrit-server-url'] || undefined,
        },
      }
    }
    if (pathname === 'auth.logout') {
      const auth = headers.authorization || ''
      return {
        method: pathname,
        params: {
          session_token: auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : headers['x-aavrit-session'] || '',
          aavrit_url: headers['x-aavrit-server-url'] || undefined,
        },
      }
    }
    if (pathname === 'archive.encrypt' || pathname === 'archive.decrypt') {
      const auth = headers.authorization || ''
      if (auth.toLowerCase().startsWith('bearer ')) body.session_token = auth.slice(7).trim()
    }
    return { method: pathname, params: body }
  }

  throw new Error(`Unsupported Avikal core request: ${method} ${pathname}`)
}
