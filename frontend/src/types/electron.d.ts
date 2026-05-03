import type { ExternalLaunchAction } from '../lib/externalLaunch'

export interface ElectronDialogFilter {
  name: string
  extensions: string[]
}

export type ElectronOpenDialogProperty = 'openFile' | 'openDirectory' | 'multiSelections'

export interface ElectronOpenDialogOptions {
  properties?: ElectronOpenDialogProperty[]
  filters?: ElectronDialogFilter[]
  defaultPath?: string
}

export interface ElectronSaveDialogOptions {
  defaultPath?: string
  filters?: ElectronDialogFilter[]
}

export interface ElectronDirectoryNode {
  name: string
  path: string
  isDir: boolean
  size: number
  truncated?: boolean
  children?: ElectronDirectoryNode[]
  error?: boolean
}

export interface ElectronSaveTextOptions {
  defaultPath?: string
  filters?: ElectronDialogFilter[]
  content: string
}

export interface ElectronExportCopyOptions {
  sourcePath: string
  defaultPath?: string
  filters?: ElectronDialogFilter[]
}

export interface ElectronExportFilesToDirectoryOptions {
  title?: string
  files: Array<{
    sourcePath: string
    relativePath: string
  }>
}

export interface ElectronExportDirectoryResult {
  destinationPath: string
  copiedCount: number
}

export type BackendRuntimeState = 'idle' | 'starting' | 'ready' | 'error' | 'stopped'

export interface BackendRuntimeStatus {
  state: BackendRuntimeState
  baseUrl: string
  error: string | null
  updatedAt: number
}

export interface BackendRequestConfig {
  baseUrl: string
  authHeader: string
  authToken: string | null
}

declare global {
  interface ElectronAPI {
    openFile: (options?: ElectronOpenDialogOptions) => Promise<string[]>
    saveFile: (options?: ElectronSaveDialogOptions) => Promise<string | undefined>
    openDirectory: () => Promise<string | undefined>
    openFolders: () => Promise<string[]>
    scanDirectory: (dirPath: string) => Promise<ElectronDirectoryNode>
    saveTextFile?: (options: ElectronSaveTextOptions) => Promise<string | null>
    exportFileCopy?: (options: ElectronExportCopyOptions) => Promise<string | null>
    exportFilesToDirectory?: (options: ElectronExportFilesToDirectoryOptions) => Promise<ElectronExportDirectoryResult | null>
    openPath?: (path: string) => Promise<void>
    openExternal?: (url: string) => Promise<void>
    onBackendLog?: (callback: (message: string) => void) => () => void
    getBackendStatus?: () => Promise<BackendRuntimeStatus>
    getBackendRequestConfig?: () => Promise<BackendRequestConfig>
    onBackendStatus?: (callback: (status: BackendRuntimeStatus) => void) => () => void
    minimizeWindow: () => Promise<void>
    maximizeWindow: () => Promise<void>
    closeWindow: () => Promise<void>
    updateTheme?: (isDark: boolean) => void
    platform: string
    isWindows: boolean
    isMac: boolean
    isLinux: boolean
    safeStorage: {
      encrypt: (data: string) => Promise<string>
      decrypt: (encryptedData: string) => Promise<string>
      isAvailable: () => Promise<boolean>
    }
    getPendingLaunchAction?: () => Promise<ExternalLaunchAction | null>
    onLaunchAction?: (callback: (action: ExternalLaunchAction) => void) => () => void
  }

  interface Window {
    electron?: ElectronAPI
  }
}

export {}
