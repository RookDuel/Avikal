/**
 * Avikal Electron Preload Script
 * Secure bridge between renderer and main process
 */

const { contextBridge, ipcRenderer } = require('electron');

const electronBridge = Object.freeze({
  // File dialogs
  openFile: (options) => ipcRenderer.invoke('dialog:openFile', options),
  saveFile: (options) => ipcRenderer.invoke('dialog:saveFile', options),
  openDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  openFolders: () => ipcRenderer.invoke('dialog:openFolders'),
  scanDirectory: (dirPath) => ipcRenderer.invoke('fs:scanDirectory', dirPath),
  saveTextFile: (options) => ipcRenderer.invoke('file:saveText', options),
  exportFileCopy: (options) => ipcRenderer.invoke('file:exportCopy', options),
  exportFilesToDirectory: (options) => ipcRenderer.invoke('file:exportFilesToDirectory', options),
  exportAssuranceReport: (options) => ipcRenderer.invoke('report:export', options),
  openPath: (path) => ipcRenderer.invoke('shell:openPath', path),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  
  // Window controls
  minimizeWindow: () => ipcRenderer.invoke('window:minimize'),
  maximizeWindow: () => ipcRenderer.invoke('window:maximize'),
  closeWindow: () => ipcRenderer.invoke('window:close'),
  updateTheme: (isDark) => ipcRenderer.send('theme:update', { isDark }),
  getVisualMode: () => ipcRenderer.invoke('visualMode:get'),
  setVisualMode: (mode) => ipcRenderer.invoke('visualMode:set', mode),
  onVisualModeChanged: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('visual-mode:changed', listener);
    return () => ipcRenderer.removeListener('visual-mode:changed', listener);
  },
  
  // Platform info
  platform: process.platform,
  isWindows: process.platform === 'win32',
  isMac: process.platform === 'darwin',
  isLinux: process.platform === 'linux',

  // Secure token storage
  safeStorage: Object.freeze({
    encrypt: (data) => ipcRenderer.invoke('safeStorage:encrypt', data),
    decrypt: (encryptedData) => ipcRenderer.invoke('safeStorage:decrypt', encryptedData),
    isAvailable: () => ipcRenderer.invoke('safeStorage:isAvailable'),
  }),
  creatorIdentity: Object.freeze({
    create: (label) => ipcRenderer.invoke('identity:create', label),
    list: () => ipcRenderer.invoke('identity:list'),
    delete: (identityId) => ipcRenderer.invoke('identity:delete', identityId),
    deleteTrusted: (identityId) => ipcRenderer.invoke('identity:deleteTrusted', identityId),
    exportPublic: (identityId) => ipcRenderer.invoke('identity:exportPublic', identityId),
    importTrusted: () => ipcRenderer.invoke('identity:importTrusted'),
    setTrust: (identityId, status) => ipcRenderer.invoke('identity:setTrust', identityId, status),
  }),
  getPendingLaunchAction: () => ipcRenderer.invoke('launchAction:getPending'),
  onLaunchAction: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('launch-action', listener);
    return () => ipcRenderer.removeListener('launch-action', listener);
  },
  onBackendLog: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('backend-log', listener);
    return () => ipcRenderer.removeListener('backend-log', listener);
  },
  getBackendStatus: () => ipcRenderer.invoke('backend:getStatus'),
  getAppInfo: () => ipcRenderer.invoke('app:getInfo'),
  checkForUpdates: () => ipcRenderer.invoke('updates:check'),
  openLatestRelease: () => ipcRenderer.invoke('updates:openLatest'),
  recordDiagnosticEvent: (event) => ipcRenderer.invoke('diagnostics:recordRenderer', event),
  exportDiagnostics: () => ipcRenderer.invoke('diagnostics:exportSupportLog'),
  invokeCore: (method, params, timeoutMs) => ipcRenderer.invoke('core:invoke', method, params, timeoutMs),
  onBackendStatus: (callback) => {
    const listener = (event, data) => callback(data);
    ipcRenderer.on('backend-status', listener);
    return () => ipcRenderer.removeListener('backend-status', listener);
  },
});

// Expose protected methods to renderer
contextBridge.exposeInMainWorld('electron', electronBridge);
