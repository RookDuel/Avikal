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
  children?: ElectronDirectoryNode[]
  error?: boolean
}

declare global {
  interface ElectronAPI {
    openFile: (options?: ElectronOpenDialogOptions) => Promise<string[]>
    saveFile: (options?: ElectronSaveDialogOptions) => Promise<string | undefined>
    openDirectory: () => Promise<string | undefined>
    openFolders: () => Promise<string[]>
    writeFile: (path: string, content: string) => Promise<boolean>
    readFile: (path: string) => Promise<string>
    copyFile: (sourcePath: string, destinationPath: string) => Promise<boolean>
    scanDirectory: (dirPath: string) => Promise<ElectronDirectoryNode>
    openPath?: (path: string) => Promise<void>
    openExternal?: (url: string) => Promise<void>
    onBackendLog?: (callback: (message: string) => void) => () => void
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
