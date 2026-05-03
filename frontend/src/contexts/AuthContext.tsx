/* eslint-disable react-refresh/only-export-components */
import React, { createContext, useContext, useEffect, useRef, useState } from 'react'
import { fetchBackend } from '../lib/backend'

export interface User {
  id: string
  email: string
  name: string
  emailVerification: boolean
}

type AavritMode = 'public' | 'private'

interface LoginRequest {
  aavrit_url: string
  email: string
  password: string
}

interface AuthContextType {
  isAuthenticated: boolean
  isAavritConnected: boolean
  sessionToken: string | null
  aavritServerUrl: string | null
  aavritMode: AavritMode | null
  user: User | null
  profileLoading: boolean
  connectServer: (aavritUrl: string) => Promise<AavritMode>
  login: (credentials: LoginRequest) => Promise<boolean>
  logout: () => void
  disconnectServer: () => void
  checkAuthStatus: () => Promise<void>
  refreshUserProfile: () => Promise<void>
  verifyAndSetSession: (sessionToken: string, aavritUrl?: string) => Promise<boolean>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const SESSION_STORAGE_KEY = 'avikal_secure_aavrit_session'
const AAVRIT_SERVER_STORAGE_KEY = 'avikal_aavrit_server_url'
const AAVRIT_MODE_STORAGE_KEY = 'avikal_aavrit_mode'
const PROFILE_TTL_MS = 5 * 60 * 1000

interface ProfileCacheEntry {
  user: User
  expiresAt: number
}

const profileCache: Map<string, ProfileCacheEntry> = new Map()

async function canPersistTokenSecurely(): Promise<boolean> {
  try {
    const safeStorage = window.electron?.safeStorage
    if (!safeStorage) return false
    return await safeStorage.isAvailable()
  } catch {
    return false
  }
}

async function saveSessionSecurely(sessionToken: string): Promise<void> {
  localStorage.removeItem(SESSION_STORAGE_KEY)

  if (!(await canPersistTokenSecurely())) {
    throw new Error('Electron secure storage is unavailable; token persistence is disabled')
  }

  const encrypted = await window.electron!.safeStorage.encrypt(sessionToken)
  localStorage.setItem(SESSION_STORAGE_KEY, encrypted)
}

async function loadSessionSecurely(): Promise<string | null> {
  try {
    const stored = localStorage.getItem(SESSION_STORAGE_KEY)
    if (!stored) return null

    if (!(await canPersistTokenSecurely())) {
      localStorage.removeItem(SESSION_STORAGE_KEY)
      return null
    }

    return await window.electron!.safeStorage.decrypt(stored)
  } catch {
    localStorage.removeItem(SESSION_STORAGE_KEY)
    return null
  }
}

function saveAavritServerUrl(url: string): void {
  localStorage.setItem(AAVRIT_SERVER_STORAGE_KEY, url)
}

function loadAavritServerUrl(): string | null {
  return localStorage.getItem(AAVRIT_SERVER_STORAGE_KEY)
}

function saveAavritMode(mode: AavritMode): void {
  localStorage.setItem(AAVRIT_MODE_STORAGE_KEY, mode)
}

function loadAavritMode(): AavritMode | null {
  const stored = localStorage.getItem(AAVRIT_MODE_STORAGE_KEY)
  return stored === 'public' || stored === 'private' ? stored : null
}

function clearStoredSession(): void {
  localStorage.removeItem(SESSION_STORAGE_KEY)
}

function clearStoredAavritConnection(): void {
  localStorage.removeItem(AAVRIT_SERVER_STORAGE_KEY)
  localStorage.removeItem(AAVRIT_MODE_STORAGE_KEY)
}

async function readErrorDetail(response: Response, fallback: string): Promise<string> {
  const contentType = response.headers.get('content-type') || ''

  try {
    if (contentType.includes('application/json')) {
      const payload = await response.json()
      return payload?.detail || payload?.error || payload?.message || fallback
    }

    const rawText = (await response.text()).trim()
    return rawText || fallback
  } catch {
    return fallback
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [sessionToken, setSessionToken] = useState<string | null>(null)
  const [aavritServerUrl, setAavritServerUrl] = useState<string | null>(() => {
    if (typeof window === 'undefined') return null
    return loadAavritServerUrl()
  })
  const [aavritMode, setAavritMode] = useState<AavritMode | null>(() => {
    if (typeof window === 'undefined') return null
    return loadAavritMode()
  })
  const [user, setUser] = useState<User | null>(null)
  const [profileLoading, setProfileLoading] = useState(false)
  const inflightProfile = useRef<Promise<void> | null>(null)
  const isAavritConnected = Boolean(
    aavritServerUrl &&
    aavritMode &&
    (aavritMode === 'public' || (aavritMode === 'private' && isAuthenticated && sessionToken)),
  )

  const clearLocalAuthState = (clearConnection = false) => {
    profileCache.clear()
    setSessionToken(null)
    setIsAuthenticated(false)
    setUser(null)
    clearStoredSession()
    if (clearConnection) {
      setAavritServerUrl(null)
      setAavritMode(null)
      clearStoredAavritConnection()
    }
  }

  const fetchUserProfile = async (token?: string, url?: string): Promise<void> => {
    if (inflightProfile.current) return inflightProfile.current

    const doFetch = async () => {
      try {
        const resolvedToken = token ?? sessionToken ?? ''
        const resolvedUrl = url ?? aavritServerUrl ?? loadAavritServerUrl() ?? ''
        if (!resolvedToken || !resolvedUrl) return

        setProfileLoading(true)

        const cacheKey = `${resolvedUrl}:${resolvedToken}`
        const cached = profileCache.get(cacheKey)
        if (cached && Date.now() < cached.expiresAt) {
          setUser(cached.user)
          return
        }

        const headers: Record<string, string> = { 'Content-Type': 'application/json' }
        headers['X-Aavrit-Session'] = resolvedToken
        headers['X-Aavrit-Server-URL'] = resolvedUrl

        const response = await fetchBackend('/api/auth/profile', { headers })
        if (!response.ok) {
          const errText = await response.text().catch(() => '(no body)')
          console.error(`[AuthContext] /api/auth/profile failed: HTTP ${response.status} - ${errText}`)
          return
        }

        const data = await response.json()
        if (data.success && data.user) {
          const nextUser: User = {
            id: data.user.id ?? '',
            email: data.user.email ?? '',
            name: data.user.name ?? '',
            emailVerification: data.user.emailVerification ?? false,
          }
          setUser(nextUser)
          profileCache.set(cacheKey, { user: nextUser, expiresAt: Date.now() + PROFILE_TTL_MS })
        }
      } catch (error) {
        console.error('[AuthContext] fetchUserProfile exception:', error)
      } finally {
        setProfileLoading(false)
        inflightProfile.current = null
      }
    }

    inflightProfile.current = doFetch()
    return inflightProfile.current
  }

  const connectServer = async (rawAavritUrl: string): Promise<AavritMode> => {
    const response = await fetchBackend('/api/auth/check-aavrit-server', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ aavrit_url: rawAavritUrl.trim() }),
    })

    if (!response.ok) {
      const message = await readErrorDetail(response, 'Aavrit server validation failed')
      throw new Error(message)
    }

    const data = await response.json()
    const nextUrl = data.aavrit_url ?? rawAavritUrl.trim()
    const nextMode: AavritMode = data.mode === 'private' ? 'private' : 'public'

    setAavritServerUrl(nextUrl)
    setAavritMode(nextMode)
    saveAavritServerUrl(nextUrl)
    saveAavritMode(nextMode)

      if (nextMode === 'public') {
        clearLocalAuthState(false)
      }

    return nextMode
  }

  const login = async (credentials: LoginRequest): Promise<boolean> => {
    const response = await fetchBackend('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    })

    if (!response.ok) {
      const message = await readErrorDetail(response, 'Aavrit login failed')
      throw new Error(message)
    }

    const data = await response.json()
    if (!data.success || typeof data.session_token !== 'string') {
      throw new Error('Aavrit login failed')
    }

    const nextUrl = data.aavrit_url ?? credentials.aavrit_url
    const nextMode: AavritMode = data.mode === 'private' ? 'private' : 'public'

    setSessionToken(data.session_token)
    setIsAuthenticated(true)
    setAavritServerUrl(nextUrl)
    setAavritMode(nextMode)
    saveAavritServerUrl(nextUrl)
    saveAavritMode(nextMode)

    if (data.user) {
      const nextUser: User = {
        id: data.user.id ?? '',
        email: data.user.email ?? '',
        name: data.user.name ?? '',
        emailVerification: data.user.emailVerification ?? false,
      }
      setUser(nextUser)
    }

    try {
      await saveSessionSecurely(data.session_token)
    } catch (storageError) {
      console.warn('[AuthContext] Secure token persistence unavailable:', storageError)
    }

    await fetchUserProfile(data.session_token, nextUrl)
    return true
  }

  const logout = async () => {
    try {
      await fetchBackend('/api/auth/logout', { method: 'POST' })
    } catch (error) {
      console.error('Logout request failed:', error)
    }

    clearLocalAuthState(true)
  }

  const disconnectServer = () => {
    clearLocalAuthState(true)
  }

  const checkAuthStatus = async () => {
    try {
      const storedSession = await loadSessionSecurely()
      const storedAavritUrl = loadAavritServerUrl()
      const storedAavritMode = loadAavritMode()

      if (!storedAavritUrl) {
        clearLocalAuthState(true)
        return
      }

      const serverCheck = await fetchBackend('/api/auth/check-aavrit-server', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ aavrit_url: storedAavritUrl }),
      })
      if (!serverCheck.ok) {
        clearLocalAuthState(true)
        return
      }

      const validated = await serverCheck.json()
      const nextUrl = validated.aavrit_url ?? storedAavritUrl
      const nextMode = (validated.mode === 'private' || validated.mode === 'public' ? validated.mode : storedAavritMode) ?? null

      if (nextUrl) {
        setAavritServerUrl(nextUrl)
        saveAavritServerUrl(nextUrl)
      }
      if (nextMode) {
        setAavritMode(nextMode)
        saveAavritMode(nextMode)
      }

      if (nextMode === 'public') {
        clearLocalAuthState(false)
        setAavritServerUrl(nextUrl)
        setAavritMode('public')
        saveAavritServerUrl(nextUrl)
        saveAavritMode('public')
        return
      }

      if (storedSession && nextUrl) {
        const success = await verifyAndSetSession(storedSession, nextUrl)
        if (success) return
      }

      clearLocalAuthState(false)
    } catch (error) {
      console.error('Auth status check failed:', error)
      clearLocalAuthState(true)
    }
  }

  const refreshUserProfile = async () => {
    if (!isAuthenticated || !sessionToken || !aavritServerUrl) return
    profileCache.delete(`${aavritServerUrl}:${sessionToken}`)
    await fetchUserProfile(sessionToken, aavritServerUrl)
  }

  const verifyAndSetSession = async (token: string, url?: string): Promise<boolean> => {
    try {
      const resolvedUrl = url ?? aavritServerUrl ?? loadAavritServerUrl() ?? undefined
      const response = await fetchBackend('/api/auth/verify-session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_token: token, aavrit_url: resolvedUrl }),
      })

      if (!response.ok) return false

      const data = await response.json()
      if (!data.success) return false

      const nextUrl = data.aavrit_url ?? resolvedUrl ?? null
      const nextMode: AavritMode | null = data.mode === 'private' || data.mode === 'public' ? data.mode : aavritMode

      setSessionToken(token)
      setIsAuthenticated(true)

      if (nextUrl) {
        setAavritServerUrl(nextUrl)
        saveAavritServerUrl(nextUrl)
      }
      if (nextMode) {
        setAavritMode(nextMode)
        saveAavritMode(nextMode)
      }

      if (data.user) {
        const nextUser: User = {
          id: data.user.id ?? '',
          email: data.user.email ?? '',
          name: data.user.name ?? '',
          emailVerification: data.user.emailVerification ?? false,
        }
        setUser(nextUser)
      }

      try {
        await saveSessionSecurely(token)
      } catch (storageError) {
        console.warn('[AuthContext] Secure token persistence unavailable:', storageError)
      }

      await fetchUserProfile(token, nextUrl ?? undefined)
      return true
    } catch (error) {
      console.error('Session verification failed:', error)
      return false
    }
  }

  useEffect(() => {
    void checkAuthStatus()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <AuthContext.Provider
      value={{
        isAuthenticated,
        isAavritConnected,
        sessionToken,
        aavritServerUrl,
        aavritMode,
        user,
        profileLoading,
        connectServer,
        login,
        logout,
        disconnectServer,
        checkAuthStatus,
        refreshUserProfile,
        verifyAndSetSession,
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}
