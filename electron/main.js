/**
 * RookDuel Avikal Electron Main Process
 * Manages window, Python backend, and IPC
 */

const { app, BrowserWindow, ipcMain, dialog, safeStorage } = require('electron');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const isDev = process.env.NODE_ENV === 'development';
const BACKEND_HOST = '127.0.0.1';
const BACKEND_PORT = 5000;
const BACKEND_BASE_URL = `http://${BACKEND_HOST}:${BACKEND_PORT}`;

let mainWindow;
let pythonProcess;
let pendingLaunchAction = parseLaunchAction(process.argv);
let isQuitting = false;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForBackendReady(timeoutMs = 20000) {
  const startedAt = Date.now();
  let lastError = null;

  while (Date.now() - startedAt < timeoutMs) {
    try {
      const response = await fetch(`${BACKEND_BASE_URL}/health`);
      if (response.ok) {
        return;
      }
      lastError = new Error(`Backend health check returned ${response.status}`);
    } catch (error) {
      lastError = error;
    }

    if (pythonProcess && pythonProcess.exitCode !== null) {
      throw new Error(`Python backend exited early with code ${pythonProcess.exitCode}`);
    }

    await sleep(250);
  }

  throw new Error(
    `Backend did not become ready within ${timeoutMs}ms${lastError ? `: ${lastError.message || lastError}` : ''}`
  );
}

function normalizeShellAction(value) {
  return value === 'encrypt' || value === 'timecapsule' ? value : null;
}

function normalizeLaunchPath(value) {
  if (!value) return null;
  const trimmed = value.trim().replace(/^"(.*)"$/, '$1');
  if (!trimmed || trimmed.startsWith('--')) return null;
  return path.normalize(trimmed);
}

function parseLaunchAction(argv = []) {
  let target = null;
  const paths = [];

  for (let index = 0; index < argv.length; index += 1) {
    const current = argv[index];
    if (!current) continue;

    if (current === '--shell-action') {
      target = normalizeShellAction(argv[index + 1]);
      index += 1;
      continue;
    }

    if (current.startsWith('--shell-action=')) {
      target = normalizeShellAction(current.split('=')[1]);
      continue;
    }

    if (!target) continue;

    const normalizedPath = normalizeLaunchPath(current);
    if (normalizedPath) {
      paths.push(normalizedPath);
    }
  }

  if (!target || paths.length === 0) {
    return null;
  }

  return {
    target,
    paths: Array.from(new Set(paths)),
    source: 'windows-context-menu',
  };
}

function focusMainWindow() {
  if (!mainWindow) return;
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.focus();
}

function dispatchLaunchAction(action) {
  if (!action) return;

  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isLoadingMainFrame()) {
    mainWindow.webContents.send('launch-action', action);
    pendingLaunchAction = null;
    return;
  }

  pendingLaunchAction = action;
}

function getAppIconPath() {
  const iconFile = process.platform === 'win32' ? 'icon.ico' : 'icon.png';
  return isDev
    ? path.join(__dirname, '../assets', iconFile)
    : path.join(process.resourcesPath, 'assets', iconFile);
}

function getBackendRoot() {
  return isDev
    ? path.join(__dirname, '../backend')
    : path.join(process.resourcesPath, 'backend');
}

function getPythonRuntimeRoot(backendRoot) {
  return isDev
    ? path.join(backendRoot, 'venv')
    : path.join(process.resourcesPath, 'backend-runtime');
}

function getPythonExecutable(backendRoot) {
  const runtimeRoot = getPythonRuntimeRoot(backendRoot);
  if (isDev) {
    return process.platform === 'win32'
      ? path.join(runtimeRoot, 'Scripts', 'python.exe')
      : path.join(runtimeRoot, 'bin', 'python');
  }
  return process.platform === 'win32'
    ? path.join(runtimeRoot, 'python.exe')
    : path.join(runtimeRoot, 'bin', 'python');
}

const gotTheLock = app.requestSingleInstanceLock()

if (!gotTheLock) {
  app.quit()
} else {
  if (process.platform === 'win32') {
    app.setAppUserModelId('tech.rookduel.avikal');
  }
  app.on('second-instance', (event, commandLine) => {
    focusMainWindow();
    dispatchLaunchAction(parseLaunchAction(commandLine));
  });
}

// Python backend management
function startPythonBackend() {
  const backendRoot = getBackendRoot();
  const runtimeRoot = getPythonRuntimeRoot(backendRoot);
  const pythonScript = path.join(backendRoot, 'api_server.py');
  const pythonExecutable = getPythonExecutable(backendRoot);

  if (!fs.existsSync(pythonExecutable)) {
    throw new Error(`Python runtime not found: ${pythonExecutable}`);
  }

  if (!fs.existsSync(pythonScript)) {
    throw new Error(`Backend entrypoint not found: ${pythonScript}`);
  }
  
  console.log(`Starting Python backend with: ${pythonExecutable}`);

  const pythonEnv = {
    ...process.env,
    PYTHONIOENCODING: 'utf-8',
    PYTHONUNBUFFERED: '1'
  };

  if (!isDev) {
    pythonEnv.AVIKAL_USER_DATA_DIR = app.getPath('userData');
    pythonEnv.PYTHONHOME = runtimeRoot;
    pythonEnv.PYTHONPATH = [
      backendRoot,
      path.join(runtimeRoot, 'Lib'),
      path.join(runtimeRoot, 'Lib', 'site-packages')
    ].join(path.delimiter);
    pythonEnv.PYTHONNOUSERSITE = '1';
  }
  
  pythonProcess = spawn(pythonExecutable, [pythonScript], {
    stdio: 'pipe',
    cwd: backendRoot,
    env: pythonEnv
  });
  
  pythonProcess.stdout.on('data', (data) => {
    const message = data.toString();
    console.log(`[Python] ${message}`);
    if (mainWindow) {
      mainWindow.webContents.send('backend-log', message);
    }
  });
  
  pythonProcess.stderr.on('data', (data) => {
    console.error(`[Python Error] ${data}`);
  });
  
  pythonProcess.on('close', (code) => {
    console.log(`Python process exited with code ${code}`);
  });

  return waitForBackendReady();
}

function stopPythonBackend() {
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
}

async function cleanupBackendPreviewSessions() {
  try {
    await fetch(`${BACKEND_BASE_URL}/api/decrypt/cleanup-all`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (error) {
    console.warn('Preview session cleanup failed during shutdown:', error);
  }
}

// Create main window
async function createWindow() {
  try {
    // Start Python backend first
    await startPythonBackend();
  } catch (error) {
    console.error('Failed to start Python backend:', error);
    dialog.showErrorBox(
      'RookDuel Avikal Startup Error',
      `The embedded backend could not be started.\n\n${error.message || error}`
    );
    app.quit();
    return;
  }
  
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 1000,
    minHeight: 700,
    backgroundColor: '#0A0E27',
    icon: getAppIconPath(),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      preload: path.join(__dirname, 'preload.js')
    },
    frame: false,
    show: false
  });
  
  // Load app
  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
  } else {
    const indexPath = path.join(__dirname, '../frontend/dist/index.html');
    console.log(`Loading frontend from: ${indexPath}`);
    mainWindow.loadFile(indexPath);
  }
  
  // Show when ready
  mainWindow.once('ready-to-show', () => {
    console.log('Window ready to show');
    mainWindow.show();
  });
  
  // Debug web contents
  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error(`Failed to load: ${errorCode} - ${errorDescription}`);
  });
  
  mainWindow.webContents.on('did-finish-load', () => {
    console.log('Web contents finished loading');
  });
  
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// IPC Handlers
ipcMain.handle('dialog:openFile', async (event, options) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
    ...options
  });
  return result.canceled ? [] : result.filePaths;
});

ipcMain.handle('dialog:saveFile', async (event, options) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: 'encrypted.avk',
    filters: [{ name: 'RookDuel Avikal Files', extensions: ['avk'] }],
    ...options
  });
  return result.filePath;
});

ipcMain.handle('dialog:openDirectory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  return result.filePaths[0];
});

ipcMain.handle('dialog:openFolders', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory', 'multiSelections']
  });
  return result.canceled ? [] : result.filePaths;
});

// Recursive directory scanner — builds a full tree for the UI
ipcMain.handle('fs:scanDirectory', async (event, dirPath) => {
  const fs = require('fs');
  const path = require('path');
  async function scan(p) {
    try {
      const stat = fs.statSync(p);
      const node = { name: path.basename(p), path: p, isDir: stat.isDirectory(), size: stat.size };
      if (stat.isDirectory()) {
        const entries = fs.readdirSync(p);
        node.children = [];
        for (const entry of entries) {
          try { node.children.push(await scan(path.join(p, entry))); } catch (_) {}
        }
        node.children.sort((a, b) => {
          if (a.isDir !== b.isDir) return a.isDir ? -1 : 1;
          return a.name.localeCompare(b.name);
        });
        node.size = node.children.reduce((s, c) => s + (c.size || 0), 0);
      }
      return node;
    } catch (e) { return { name: path.basename(p), path: p, isDir: false, size: 0, error: true }; }
  }
  return scan(dirPath);
});

ipcMain.handle('fs:writeFile', async (event, filePath, content) => {
  try {
    const fsPromises = require('fs').promises;
    await fsPromises.writeFile(filePath, content, 'utf8');
    return true;
  } catch (error) {
    console.error('fs:writeFile error:', error);
    throw error;
  }
});

ipcMain.handle('fs:readFile', async (event, filePath) => {
  try {
    const fsPromises = require('fs').promises;
    const content = await fsPromises.readFile(filePath, 'utf8');
    return content;
  } catch (error) {
    console.error('fs:readFile error:', error);
    throw error;
  }
});

ipcMain.handle('shell:openPath', async (event, targetPath) => {
  const { shell } = require('electron');
  shell.openPath(targetPath);
});

ipcMain.handle('shell:openExternal', async (event, url) => {
  const { shell } = require('electron');
  shell.openExternal(url);
});

ipcMain.on('theme:update', (event, { isDark }) => {
  // Native titleBarOverlay is removed; theme context is handled purely via React/CSS.
});

ipcMain.handle('window:minimize', () => {
  mainWindow.minimize();
});

ipcMain.handle('window:maximize', () => {
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

ipcMain.handle('window:close', () => {
  mainWindow.close();
});

ipcMain.handle('launchAction:getPending', async () => {
  const action = pendingLaunchAction;
  pendingLaunchAction = null;
  return action;
});

// Secure token storage
ipcMain.handle('safeStorage:encrypt', async (event, data) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable on this system')
  }
  return safeStorage.encryptString(data).toString('base64')
})

ipcMain.handle('safeStorage:decrypt', async (event, encryptedData) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable on this system')
  }
  const buffer = Buffer.from(encryptedData, 'base64')
  return safeStorage.decryptString(buffer)
})

ipcMain.handle('safeStorage:isAvailable', async () => {
  return safeStorage.isEncryptionAvailable()
})

// App lifecycle
app.whenReady().then(createWindow);

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.handle('fs:copyFile', async (event, sourcePath, destinationPath) => {
  try {
    const fsPromises = require('fs').promises;
    if (!sourcePath || !destinationPath) {
      throw new Error('Source and destination paths are required');
    }

    const source = path.resolve(String(sourcePath));
    const destination = path.resolve(String(destinationPath));

    await fsPromises.mkdir(path.dirname(destination), { recursive: true });
    await fsPromises.copyFile(source, destination, fs.constants.COPYFILE_EXCL);
    return true;
  } catch (error) {
    console.error('fs:copyFile error:', error);
    throw error;
  }
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

app.on('before-quit', (event) => {
  if (isQuitting) {
    stopPythonBackend();
    return;
  }

  isQuitting = true;
  event.preventDefault();

  cleanupBackendPreviewSessions()
    .finally(() => {
      stopPythonBackend();
      app.quit();
    });
});
