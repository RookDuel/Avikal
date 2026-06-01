export async function invokeCore<T = unknown>(
  method: string,
  params: Record<string, unknown> = {},
  timeoutMs = 30_000,
): Promise<T> {
  if (typeof window === 'undefined' || !window.electron?.invokeCore) {
    throw new Error('Avikal desktop core bridge is unavailable')
  }
  return window.electron.invokeCore<T>(method, params, timeoutMs)
}

