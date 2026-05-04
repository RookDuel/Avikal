/**
 * RookDuel Avikal Electron Main Process
 * Manages window, Python backend, and IPC
 */

const { app, BrowserWindow, ipcMain, dialog, safeStorage } = require('electron');
const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
const crypto = require('crypto');
const net = require('net');
const isDev = process.env.NODE_ENV === 'development';
const DEFAULT_BACKEND_HOST = '127.0.0.1';
const DEFAULT_BACKEND_PORT = 5000;
const BACKEND_READY_TIMEOUT_MS = isDev ? 30000 : 45000;
const BACKEND_HEALTH_POLL_INTERVAL_MS = 250;
const BACKEND_HEALTH_REQUEST_TIMEOUT_MS = 1500;
const BACKEND_AUTH_HEADER = 'X-Avikal-Backend-Token';
const MAX_DIRECTORY_SCAN_DEPTH = 12;
const MAX_DIRECTORY_SCAN_ENTRIES = 20000;
const MAX_SAVED_TEXT_BYTES = 5 * 1024 * 1024;

let mainWindow;
let pythonProcess;
let pendingLaunchAction = parseLaunchAction(process.argv);
let isQuitting = false;
let backendHost = DEFAULT_BACKEND_HOST;
let backendPort = DEFAULT_BACKEND_PORT;
let backendAuthToken = crypto.randomBytes(32).toString('hex');
let backendStartupState = createBackendStartupState();
let backendRuntimeStatus = createBackendRuntimeStatus('idle');

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function createBackendStartupState() {
  return {
    spawnError: null,
    lastOutputLine: null,
    lastErrorLine: null,
    listeningAnnounced: false,
  };
}

function getBackendBaseUrl() {
  return `http://${backendHost}:${backendPort}`;
}

function getBackendReadyLogMarker() {
  return `Uvicorn running on ${getBackendBaseUrl()}`;
}

function createBackendRequestConfig() {
  return {
    baseUrl: getBackendBaseUrl(),
    authHeader: BACKEND_AUTH_HEADER,
    authToken: backendAuthToken,
  };
}

function reserveBackendPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, backendHost, () => {
      const address = server.address();
      if (!address || typeof address === 'string') {
        server.close(() => reject(new Error('Failed to reserve a backend port')));
        return;
      }
      const { port } = address;
      server.close((error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve(port);
      });
    });
  });
}

function resetBackendStartupState() {
  backendStartupState = createBackendStartupState();
}

function createBackendRuntimeStatus(state, error = null) {
  return {
    state,
    baseUrl: getBackendBaseUrl(),
    error,
    updatedAt: Date.now(),
  };
}

function publishBackendRuntimeStatus(state, error = null) {
  backendRuntimeStatus = createBackendRuntimeStatus(state, error);
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.webContents.send('backend-status', backendRuntimeStatus);
  }
}

function recordBackendOutput(chunk, source) {
  const lines = String(chunk)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);

  for (const line of lines) {
    backendStartupState.lastOutputLine = line;
    if (source === 'stderr') {
      backendStartupState.lastErrorLine = line;
    }
    if (!backendStartupState.listeningAnnounced && line.includes(getBackendReadyLogMarker())) {
      backendStartupState.listeningAnnounced = true;
    }
  }
}

async function probeBackendHealth() {
  const controller = new AbortController();
  const timeoutHandle = setTimeout(() => controller.abort(), BACKEND_HEALTH_REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(`${getBackendBaseUrl()}/health`, {
      signal: controller.signal,
    });
    if (response.ok) {
      return { ok: true, error: null };
    }
    return {
      ok: false,
      error: new Error(`Backend health check returned ${response.status}`),
    };
  } catch (error) {
    return { ok: false, error };
  } finally {
    clearTimeout(timeoutHandle);
  }
}

async function waitForBackendReady(timeoutMs = BACKEND_READY_TIMEOUT_MS) {
  const startedAt = Date.now();
  let lastError = null;

  while (Date.now() - startedAt < timeoutMs) {
    if (backendStartupState.spawnError) {
      throw new Error(`Python backend failed to start: ${backendStartupState.spawnError.message || backendStartupState.spawnError}`);
    }

    if (backendStartupState.listeningAnnounced) {
      return;
    }

    const probe = await probeBackendHealth();
    if (probe.ok) {
      return;
    }
    lastError = probe.error;

    if (pythonProcess && pythonProcess.exitCode !== null) {
      throw new Error(`Python backend exited early with code ${pythonProcess.exitCode}`);
    }

    await sleep(BACKEND_HEALTH_POLL_INTERVAL_MS);
  }

  const diagnosticParts = [];
  if (lastError) {
    diagnosticParts.push(lastError.message || String(lastError));
  }
  if (backendStartupState.lastErrorLine) {
    diagnosticParts.push(`last backend log: ${backendStartupState.lastErrorLine}`);
  } else if (backendStartupState.lastOutputLine) {
    diagnosticParts.push(`last backend output: ${backendStartupState.lastOutputLine}`);
  }

  throw new Error(
    `Backend did not become ready within ${timeoutMs}ms${diagnosticParts.length > 0 ? `: ${diagnosticParts.join(' | ')}` : ''}`
  );
}

function isBackendStartupTimeout(error) {
  return String(error && (error.message || error)).includes('Backend did not become ready within');
}

function monitorBackendReadyAfterSlowStart() {
  if (!pythonProcess || pythonProcess.exitCode !== null) {
    return;
  }

  waitForBackendReady(BACKEND_READY_TIMEOUT_MS)
    .then(() => {
      publishBackendRuntimeStatus('ready');
    })
    .catch((error) => {
      if (isBackendStartupTimeout(error) && pythonProcess && pythonProcess.exitCode === null) {
        publishBackendRuntimeStatus(
          'starting',
          'Backend is still loading. Heavy startup work is continuing in the background.'
        );
        setTimeout(monitorBackendReadyAfterSlowStart, 1000);
        return;
      }

      console.error('Python backend failed while starting:', error);
      publishBackendRuntimeStatus('error', error.message || String(error));
    });
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

function isAllowedExternalUrl(value) {
  try {
    const parsed = new URL(String(value));
    return parsed.protocol === 'https:' || parsed.protocol === 'mailto:';
  } catch {
    return false;
  }
}

function resolveAbsolutePath(candidate, fieldName) {
  if (typeof candidate !== 'string' || candidate.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty path`);
  }
  return path.resolve(candidate);
}

function normalizeRelativePath(candidate) {
  if (typeof candidate !== 'string' || candidate.trim().length === 0) {
    throw new Error('Relative destination path is required');
  }
  const normalized = candidate.replace(/\//g, path.sep);
  const relativePath = path.normalize(normalized);
  if (path.isAbsolute(relativePath) || relativePath.startsWith('..') || relativePath.includes(`..${path.sep}`)) {
    throw new Error('Relative destination path must stay inside the selected export directory');
  }
  return relativePath;
}

async function buildDirectoryNode(targetPath, depth = 0, state = { count: 0 }) {
  const target = resolveAbsolutePath(targetPath, 'Path');
  const stats = await fs.promises.lstat(target);
  const node = {
    name: path.basename(target),
    path: target,
    isDir: stats.isDirectory(),
    size: stats.isFile() ? stats.size : 0,
  };

  if (!stats.isDirectory() || stats.isSymbolicLink()) {
    return node;
  }

  if (depth >= MAX_DIRECTORY_SCAN_DEPTH || state.count >= MAX_DIRECTORY_SCAN_ENTRIES) {
    return { ...node, truncated: true };
  }

  const entries = await fs.promises.readdir(target, { withFileTypes: true });
  const children = [];
  let totalSize = 0;

  for (const entry of entries) {
    if (state.count >= MAX_DIRECTORY_SCAN_ENTRIES) {
      break;
    }
    state.count += 1;
    try {
      const child = await buildDirectoryNode(path.join(target, entry.name), depth + 1, state);
      children.push(child);
      totalSize += child.size || 0;
    } catch (_error) {
      // Ignore unreadable children and continue scanning the rest of the tree.
    }
  }

  children.sort((left, right) => {
    if (left.isDir !== right.isDir) {
      return left.isDir ? -1 : 1;
    }
    return left.name.localeCompare(right.name);
  });

  return {
    ...node,
    children,
    size: totalSize,
    truncated: state.count >= MAX_DIRECTORY_SCAN_ENTRIES,
  };
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
  if (pythonProcess && pythonProcess.exitCode === null) {
    return waitForBackendReady();
  }

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
  resetBackendStartupState();

  const pythonEnv = {
    ...process.env,
    PYTHONIOENCODING: 'utf-8',
    PYTHONUNBUFFERED: '1',
    AVIKAL_BACKEND_HOST: backendHost,
    AVIKAL_BACKEND_PORT: String(backendPort),
    AVIKAL_BACKEND_TOKEN: backendAuthToken,
    // Pass the Electron executable path to the Python backend.
    // drand.py uses this with ELECTRON_RUN_AS_NODE=1 to run the drand helper script
    // using Electron's bundled Node.js runtime — no external Node.js installation needed.
    // This is the official Electron-documented pattern used by VS Code, Cursor, etc.
    AVIKAL_ELECTRON_EXEC: process.execPath,
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

  pythonProcess.on('error', (error) => {
    backendStartupState.spawnError = error;
    console.error('Python process failed to start:', error);
  });
  
  pythonProcess.stdout.on('data', (data) => {
    const message = data.toString();
    recordBackendOutput(message, 'stdout');
    console.log(`[Python] ${message}`);
    if (mainWindow) {
      mainWindow.webContents.send('backend-log', message);
    }
  });
  
  pythonProcess.stderr.on('data', (data) => {
    recordBackendOutput(data.toString(), 'stderr');
    console.error(`[Python Error] ${data}`);
  });
  
  pythonProcess.on('close', (code) => {
    console.log(`Python process exited with code ${code}`);
    if (!isQuitting) {
      publishBackendRuntimeStatus(
        code === 0 ? 'stopped' : 'error',
        code === 0 ? null : `Python backend exited with code ${code}`
      );
    }
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
    await fetch(`${getBackendBaseUrl()}/api/decrypt/cleanup-all`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        [BACKEND_AUTH_HEADER]: backendAuthToken,
      },
    });
  } catch (error) {
    console.warn('Preview session cleanup failed during shutdown:', error);
  }
}

// Create main window
async function createWindow() {
  if (!pythonProcess || pythonProcess.exitCode !== null) {
    backendPort = await reserveBackendPort();
    backendAuthToken = crypto.randomBytes(32).toString('hex');
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
  
  // Load app immediately
  if (isDev) {
    try {
      await mainWindow.webContents.session.clearCache();
      await mainWindow.webContents.session.clearStorageData({
        storages: ['serviceworkers'],
      });
    } catch (error) {
      console.warn('Failed to clear dev renderer cache:', error);
    }
    mainWindow.loadURL(`http://localhost:5173/?devts=${Date.now()}`);
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

  // Start Python backend in the background without blocking the UI
  publishBackendRuntimeStatus('starting');
  startPythonBackend()
    .then(() => {
      publishBackendRuntimeStatus('ready');
    })
    .catch((error) => {
      if (isBackendStartupTimeout(error) && pythonProcess && pythonProcess.exitCode === null) {
        console.warn('Python backend is still starting after initial readiness window:', error);
        publishBackendRuntimeStatus(
          'starting',
          'Backend is still loading. You can keep the app open while startup finishes.'
        );
        monitorBackendReadyAfterSlowStart();
        return;
      }

      console.error('Failed to start Python backend:', error);
      publishBackendRuntimeStatus('error', error.message || String(error));
      dialog.showErrorBox(
        'RookDuel Avikal Startup Error',
        `The embedded backend could not be started.\n\n${error.message || error}`
      );
      app.quit();
    });
  
  // Debug web contents
  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error(`Failed to load: ${errorCode} - ${errorDescription}`);
  });
  
  mainWindow.webContents.on('did-finish-load', () => {
    console.log('Web contents finished loading');
    mainWindow.webContents.send('backend-status', backendRuntimeStatus);
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
  try {
    return await buildDirectoryNode(dirPath);
  } catch (error) {
    console.error('fs:scanDirectory error:', error);
    const safePath = typeof dirPath === 'string' ? path.basename(dirPath) : 'unknown';
    return { name: safePath, path: safePath, isDir: false, size: 0, error: true };
  }
});

ipcMain.handle('file:saveText', async (event, options = {}) => {
  const content = typeof options.content === 'string' ? options.content : '';
  if (Buffer.byteLength(content, 'utf8') > MAX_SAVED_TEXT_BYTES) {
    throw new Error('Text export is too large to save safely');
  }

  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: options.defaultPath || 'export.txt',
    filters: Array.isArray(options.filters) ? options.filters : [{ name: 'Text Files', extensions: ['txt'] }],
  });
  if (result.canceled || !result.filePath) {
    return null;
  }

  const destination = resolveAbsolutePath(result.filePath, 'Destination path');
  await fs.promises.mkdir(path.dirname(destination), { recursive: true });
  await fs.promises.writeFile(destination, content, 'utf8');
  return destination;
});

ipcMain.handle('file:exportCopy', async (event, options = {}) => {
  const source = resolveAbsolutePath(options.sourcePath, 'Source path');
  const sourceStats = await fs.promises.stat(source);
  if (!sourceStats.isFile()) {
    throw new Error('Source path must point to a file');
  }

  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: options.defaultPath || path.basename(source),
    filters: Array.isArray(options.filters) ? options.filters : [{ name: 'All Files', extensions: ['*'] }],
  });
  if (result.canceled || !result.filePath) {
    return null;
  }

  const destination = resolveAbsolutePath(result.filePath, 'Destination path');
  await fs.promises.mkdir(path.dirname(destination), { recursive: true });
  await fs.promises.copyFile(source, destination, fs.constants.COPYFILE_EXCL);
  return destination;
});

ipcMain.handle('file:exportFilesToDirectory', async (event, options = {}) => {
  const fileEntries = Array.isArray(options.files) ? options.files : [];
  if (fileEntries.length === 0) {
    throw new Error('At least one file is required for export');
  }

  const result = await dialog.showOpenDialog(mainWindow, {
    title: options.title || 'Choose export folder',
    properties: ['openDirectory'],
  });
  if (result.canceled || result.filePaths.length === 0) {
    return null;
  }

  const destinationRoot = resolveAbsolutePath(result.filePaths[0], 'Destination directory');
  let copiedCount = 0;

  for (const entry of fileEntries) {
    const source = resolveAbsolutePath(entry?.sourcePath, 'Source path');
    const relativePath = normalizeRelativePath(entry?.relativePath);
    const destination = path.join(destinationRoot, relativePath);

    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    await fs.promises.copyFile(source, destination, fs.constants.COPYFILE_EXCL);
    copiedCount += 1;
  }

  return {
    destinationPath: destinationRoot,
    copiedCount,
  };
});

ipcMain.handle('shell:openPath', async (event, targetPath) => {
  const { shell } = require('electron');
  const resolvedPath = resolveAbsolutePath(targetPath, 'Path');
  await fs.promises.access(resolvedPath, fs.constants.F_OK);
  return shell.openPath(resolvedPath);
});

ipcMain.handle('shell:openExternal', async (event, url) => {
  const { shell } = require('electron');
  if (!isAllowedExternalUrl(url)) {
    throw new Error('Only https and mailto links can be opened externally');
  }
  await shell.openExternal(url);
  return true;
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

ipcMain.handle('backend:getStatus', async () => {
  return backendRuntimeStatus;
});

ipcMain.handle('backend:getRequestConfig', async () => {
  return createBackendRequestConfig();
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
