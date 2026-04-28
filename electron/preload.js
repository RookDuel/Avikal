/**
 * Avikal Electron Preload Script
 * Secure bridge between renderer and main process
 */

const { contextBridge, ipcRenderer } = require('electron');

// Expose protected methods to renderer
contextBridge.exposeInMainWorld('electron', {
  // File dialogs
  openFile: (options) => ipcRenderer.invoke('dialog:openFile', options),
  saveFile: (options) => ipcRenderer.invoke('dialog:saveFile', options),
  writeFile: (path, content) => ipcRenderer.invoke('fs:writeFile', path, content),
  readFile: (path) => ipcRenderer.invoke('fs:readFile', path),
  copyFile: (sourcePath, destinationPath) => ipcRenderer.invoke('fs:copyFile', sourcePath, destinationPath),
  openDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  openFolders: () => ipcRenderer.invoke('dialog:openFolders'),
  scanDirectory: (dirPath) => ipcRenderer.invoke('fs:scanDirectory', dirPath),
  openPath: (path) => ipcRenderer.invoke('shell:openPath', path),
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  
  // Window controls
  minimizeWindow: () => ipcRenderer.invoke('window:minimize'),
  maximizeWindow: () => ipcRenderer.invoke('window:maximize'),
  closeWindow: () => ipcRenderer.invoke('window:close'),
  updateTheme: (isDark) => ipcRenderer.send('theme:update', { isDark }),
  
  // Platform info
  platform: process.platform,
  isWindows: process.platform === 'win32',
  isMac: process.platform === 'darwin',
  isLinux: process.platform === 'linux',

  // Secure token storage
  safeStorage: {
    encrypt: (data) => ipcRenderer.invoke('safeStorage:encrypt', data),
    decrypt: (encryptedData) => ipcRenderer.invoke('safeStorage:decrypt', encryptedData),
    isAvailable: () => ipcRenderer.invoke('safeStorage:isAvailable'),
  },
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
});
