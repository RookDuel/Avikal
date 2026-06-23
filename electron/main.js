/**
 * RookDuel Avikal Electron Main Process
 * Manages window, the local Avikal core process, and IPC
 */

const { app, BrowserWindow, ipcMain, dialog, safeStorage, Menu, Tray } = require('electron');
const fs = require('fs');
const https = require('https');
const path = require('path');
const os = require('os');
const { pathToFileURL } = require('url');
const { spawn, spawnSync } = require('child_process');
const crypto = require('crypto');
const sourceDevMode = process.env.AVIKAL_USE_SOURCE_BACKEND === '1';
const devServerUrl = normalizeDevServerUrl(process.env.AVIKAL_DEV_SERVER_URL);
const frontendDevMode = Boolean(devServerUrl);
const productionRendererMode = !frontendDevMode;
const BACKEND_READY_TIMEOUT_MS = sourceDevMode ? 30000 : 45000;
const BACKEND_HEALTH_POLL_INTERVAL_MS = 250;
const BACKEND_HEALTH_REQUEST_TIMEOUT_MS = 1500;
const CORE_TRANSPORT_URL = 'stdio://avikal-core';
const UPDATE_REPO_OWNER = process.env.AVIKAL_UPDATE_REPO_OWNER || 'RookDuel';
const UPDATE_REPO_NAME = process.env.AVIKAL_UPDATE_REPO_NAME || 'Avikal';
const UPDATE_RELEASES_API_URL = process.env.AVIKAL_UPDATE_RELEASES_API_URL || `https://api.github.com/repos/${UPDATE_REPO_OWNER}/${UPDATE_REPO_NAME}/releases/latest`;
const UPDATE_RELEASES_PAGE_URL = process.env.AVIKAL_UPDATE_RELEASES_PAGE_URL || `https://github.com/${UPDATE_REPO_OWNER}/${UPDATE_REPO_NAME}/releases/latest`;
const OFFICIAL_RELEASE_HOSTS = new Set([
  'api.github.com',
  'github.com',
  'objects.githubusercontent.com',
  'github-releases.githubusercontent.com',
]);
const ALLOWED_EXTERNAL_HOSTS = new Set([
  'avikal.rookduel.tech',
  'github.com',
]);
const MAX_DIRECTORY_SCAN_DEPTH = 12;
const MAX_DIRECTORY_SCAN_ENTRIES = 20000;
const MAX_SAVED_TEXT_BYTES = 5 * 1024 * 1024;
const SHARED_CORE_VENDOR_DIR = path.join('RookDuel', 'Avikal', 'Core');
const PRODUCTION_RENDERER_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: file:",
  "font-src 'self' data:",
  "connect-src 'self'",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');
const CORE_METHOD_POLICIES = Object.freeze({
  'runtime.status': { timeoutMs: 5000 },
  'archive.encrypt': { timeoutMs: 0 },
  'archive.decrypt': { timeoutMs: 0 },
  'archive.inspect': { timeoutMs: 30000 },
  'archive.rekey': { timeoutMs: 120000 },
  'pqc.keyfileInspect': { timeoutMs: 10000 },
  'preview.cleanupSession': { timeoutMs: 10000 },
  'preview.cleanupAll': { timeoutMs: 10000 },
  'preview.cancel': { timeoutMs: 10000 },
  'keyphrase.generate': { timeoutMs: 30000 },
  'keyphrase.romanMap': { timeoutMs: 30000 },
  'time.ntp': { timeoutMs: 8000 },
  'auth.checkAavritServer': { timeoutMs: 30000 },
  'auth.login': { timeoutMs: 30000 },
  'auth.verifySession': { timeoutMs: 30000 },
  'auth.profile': { timeoutMs: 30000 },
  'auth.aavritDiagnostics': { timeoutMs: 30000 },
  'auth.logout': { timeoutMs: 30000 },
  'security.settings': { timeoutMs: 30000 },
  'security.preferencesUpdate': { timeoutMs: 30000 },
  'security.activityLogExport': { timeoutMs: 30000 },
  'security.activityLogClear': { timeoutMs: 30000 },
});

let mainWindow;
let pythonProcess;
let coreRpcClient = null;
let tray = null;
let pendingLaunchAction = parseLaunchAction(process.argv);
let isQuitting = false;
let backendStartupState = createBackendStartupState();
let backendRuntimeStatus = createBackendRuntimeStatus('idle');
const allowedFilePaths = new Set();
const allowedFileRoots = new Set();

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function normalizeVersion(value) {
  const match = String(value || '').trim().replace(/^v/i, '').match(/^(\d+)\.(\d+)\.(\d+)(?:[-+].*)?$/);
  if (!match) return null;
  return match.slice(1, 4).map((part) => Number(part));
}

function compareVersions(left, right) {
  const a = normalizeVersion(left);
  const b = normalizeVersion(right);
  if (!a || !b) return 0;
  for (let index = 0; index < 3; index += 1) {
    if (a[index] > b[index]) return 1;
    if (a[index] < b[index]) return -1;
  }
  return 0;
}

function assertOfficialReleaseUrl(url) {
  const parsed = new URL(String(url));
  if (parsed.protocol !== 'https:' || !OFFICIAL_RELEASE_HOSTS.has(parsed.hostname.toLowerCase())) {
    throw new Error('Update metadata must come from the official GitHub release source');
  }
  return parsed;
}

function httpsText(url, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = assertOfficialReleaseUrl(url);
    } catch (error) {
      reject(error);
      return;
    }
    const request = https.get(url, {
      headers: {
        accept: 'application/vnd.github+json',
        'user-agent': `RookDuel-Avikal/${app.getVersion()}`,
      },
      timeout: 15000,
    }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode) && response.headers.location) {
        response.resume();
        if (redirectCount >= 4) {
          reject(new Error('Update metadata redirect limit exceeded'));
          return;
        }
        const nextUrl = new URL(response.headers.location, parsed).href;
        httpsText(nextUrl, redirectCount + 1).then(resolve, reject);
        return;
      }
      let body = '';
      response.setEncoding('utf8');
      response.on('data', (chunk) => {
        body += chunk;
        if (body.length > 1024 * 1024) {
          request.destroy(new Error('Update response is too large'));
        }
      });
      response.on('end', () => {
        if (response.statusCode < 200 || response.statusCode >= 300) {
          reject(new Error(`Update server returned HTTP ${response.statusCode}`));
          return;
        }
        resolve(body);
      });
    });
    request.on('timeout', () => request.destroy(new Error('Update check timed out')));
    request.on('error', reject);
  });
}

async function httpsJson(url) {
  const body = await httpsText(url);
  try {
    return JSON.parse(body);
  } catch (_error) {
    throw new Error('Update server returned invalid JSON');
  }
}

function findReleaseAsset(assets, pattern) {
  return assets.find((asset) => pattern.test(asset.name));
}

async function readReleaseMetadataAsset(assets) {
  const metadataAsset = findReleaseAsset(assets, /^avikal-release-metadata\.json$/i);
  if (!metadataAsset) {
    return null;
  }
  try {
    return await httpsJson(metadataAsset.url);
  } catch (error) {
    console.warn('Failed to read release metadata asset:', error);
    return null;
  }
}

function normalizeSha256(value) {
  const hash = String(value || '').trim().toLowerCase();
  return /^[a-f0-9]{64}$/.test(hash) ? hash : null;
}

function buildRecommendedInstaller(asset, hash, kind) {
  if (!asset) return null;
  return {
    kind,
    name: asset.name,
    size: asset.size,
    url: asset.url,
    sha256: normalizeSha256(hash),
  };
}

function validateReleaseUrl(url) {
  try {
    const parsed = new URL(String(url));
    return parsed.protocol === 'https:' && parsed.hostname.toLowerCase() === 'github.com'
      ? parsed.href
      : UPDATE_RELEASES_PAGE_URL;
  } catch {
    return UPDATE_RELEASES_PAGE_URL;
  }
}

function assertReleaseMetadataMatchesAssets(metadata, assets) {
  if (!metadata || typeof metadata !== 'object') return false;
  const guiName = String(metadata.gui_installer_name || '');
  const cliName = String(metadata.cli_installer_name || '');
  if (!guiName || !cliName) return false;
  if (!normalizeSha256(metadata.gui_installer_sha256) || !normalizeSha256(metadata.cli_installer_sha256)) return false;
  if (!assets.some((asset) => asset.name === guiName)) return false;
  if (!assets.some((asset) => asset.name === cliName)) return false;
  return true;
}

function getReleaseTagVersion(payload) {
  return String(payload.tag_name || payload.name || '').replace(/^v/i, '');
}

async function checkLatestRelease() {
  const payload = await httpsJson(UPDATE_RELEASES_API_URL);
  const currentVersion = app.getVersion();
  const latestVersion = getReleaseTagVersion(payload);
  if (!normalizeVersion(latestVersion)) {
    throw new Error('Latest release version is unavailable');
  }
  const assets = Array.isArray(payload.assets)
    ? payload.assets
        .filter((asset) => asset && typeof asset.name === 'string')
        .map((asset) => ({
          name: asset.name,
          size: Number(asset.size || 0),
          url: asset.browser_download_url || '',
        }))
        .filter((asset) => {
          try {
            assertOfficialReleaseUrl(asset.url);
            return true;
          } catch {
            return false;
          }
        })
    : [];
  const metadata = await readReleaseMetadataAsset(assets);
  const metadataVerified = assertReleaseMetadataMatchesAssets(metadata, assets);
  const guiAsset = metadataVerified
    ? findReleaseAsset(assets, new RegExp(`^${metadata.gui_installer_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
    : findReleaseAsset(assets, /^RookDuel Avikal\.exe$/i);
  const cliAsset = metadataVerified
    ? findReleaseAsset(assets, new RegExp(`^${metadata.cli_installer_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
    : findReleaseAsset(assets, /^RookDuel Avikal CLI\.exe$/i);
  const recommendedInstallers = [
    buildRecommendedInstaller(guiAsset, metadataVerified ? metadata.gui_installer_sha256 : null, 'windows-gui'),
    buildRecommendedInstaller(cliAsset, metadataVerified ? metadata.cli_installer_sha256 : null, 'windows-cli'),
  ].filter(Boolean);
  return {
    success: true,
    currentVersion,
    latestVersion,
    updateAvailable: compareVersions(latestVersion, currentVersion) > 0,
    releaseName: String(payload.name || payload.tag_name || `v${latestVersion}`),
    releaseUrl: validateReleaseUrl(payload.html_url || UPDATE_RELEASES_PAGE_URL),
    publishedAt: payload.published_at || null,
    prerelease: Boolean(payload.prerelease),
    assets,
    metadataVerified,
    releaseMetadata: metadataVerified ? metadata : null,
    recommendedInstallers,
  };
}

function normalizeDevServerUrl(value) {
  if (typeof value !== 'string') {
    return null;
  }
  const trimmed = value.trim().replace(/\/+$/, '');
  if (!trimmed) {
    return null;
  }
  try {
    const parsed = new URL(trimmed);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return null;
    }
    return trimmed;
  } catch {
    return null;
  }
}

function createBackendStartupState() {
  return {
    spawnError: null,
    lastOutputLine: null,
    lastErrorLine: null,
  };
}

function getBackendBaseUrl() {
  return CORE_TRANSPORT_URL;
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

class CoreRpcClient {
  constructor(childProcess) {
    this.childProcess = childProcess;
    this.nextId = 1;
    this.pending = new Map();
    this.buffer = Buffer.alloc(0);
    this.disposed = false;
    childProcess.stdout.on('data', (chunk) => this._handleData(chunk));
  }

  request(method, params = {}, timeoutMs = 300000) {
    if (this.disposed || !this.childProcess.stdin || this.childProcess.exitCode !== null) {
      return Promise.reject(new Error('Avikal core process is not available'));
    }

    const id = this.nextId++;
    const message = { jsonrpc: '2.0', id, method, params };
    const body = Buffer.from(JSON.stringify(message), 'utf8');
    const frame = Buffer.concat([
      Buffer.from(`Content-Length: ${body.length}\r\n\r\n`, 'ascii'),
      body,
    ]);

    return new Promise((resolve, reject) => {
      const timeout = timeoutMs > 0 ? setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Avikal core request timed out: ${method}`));
      }, timeoutMs) : null;
      this.pending.set(id, { resolve, reject, timeout, method });
      this.childProcess.stdin.write(frame, (error) => {
        if (!error) return;
        if (timeout) clearTimeout(timeout);
        this.pending.delete(id);
        reject(error);
      });
    });
  }

  cancel(id) {
    return this.request('request.cancel', { id }, 5000).catch(() => null);
  }

  dispose(error = new Error('Avikal core process stopped')) {
    this.disposed = true;
    for (const [id, pending] of this.pending.entries()) {
      if (pending.timeout) clearTimeout(pending.timeout);
      pending.reject(error);
      this.pending.delete(id);
    }
  }

  _handleData(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    while (true) {
      const headerEnd = this.buffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return;
      const headerText = this.buffer.subarray(0, headerEnd).toString('ascii');
      const match = /content-length:\s*(\d+)/i.exec(headerText);
      if (!match) {
        console.error('Avikal core emitted malformed JSON-RPC header');
        this.buffer = Buffer.alloc(0);
        return;
      }
      const bodyLength = Number(match[1]);
      const frameEnd = headerEnd + 4 + bodyLength;
      if (this.buffer.length < frameEnd) return;

      const body = this.buffer.subarray(headerEnd + 4, frameEnd);
      this.buffer = this.buffer.subarray(frameEnd);
      try {
        this._handleMessage(JSON.parse(body.toString('utf8')));
      } catch (error) {
        console.error('Failed to parse Avikal core JSON-RPC frame:', error);
      }
    }
  }

  _handleMessage(message) {
    if (Object.prototype.hasOwnProperty.call(message, 'id')) {
      const pending = this.pending.get(message.id);
      if (!pending) return;
      if (pending.timeout) clearTimeout(pending.timeout);
      this.pending.delete(message.id);
      if (message.error) {
        const error = new Error(message.error.message || `Avikal core request failed: ${pending.method}`);
        error.code = message.error.code;
        error.data = message.error.data;
        pending.reject(error);
      } else {
        pending.resolve(message.result);
      }
      return;
    }

    if (message.method === 'progress.update') {
      const line = `__AVIKAL_PROGRESS__${JSON.stringify(message.params || {})}`;
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('backend-log', line);
      }
      return;
    }

    if (message.method === 'runtime.statusChanged') {
      publishBackendRuntimeStatus(message.params?.state || 'ready', message.params?.error || null);
      return;
    }

    if (message.method === 'log.event' && mainWindow && !mainWindow.isDestroyed()) {
      mainWindow.webContents.send('backend-log', String(message.params?.message || ''));
    }
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
  }
}

async function probeBackendHealth() {
  try {
    if (!coreRpcClient) {
      return { ok: false, error: new Error('Avikal core RPC is not initialized') };
    }
    const response = await coreRpcClient.request('runtime.status', {}, BACKEND_HEALTH_REQUEST_TIMEOUT_MS);
    if (response?.success) {
      return { ok: true, error: null };
    }
    return {
      ok: false,
      error: new Error('Avikal core runtime status check failed'),
    };
  } catch (error) {
    return { ok: false, error };
  }
}

async function waitForBackendReady(timeoutMs = BACKEND_READY_TIMEOUT_MS) {
  const startedAt = Date.now();
  let lastError = null;

  while (Date.now() - startedAt < timeoutMs) {
    if (backendStartupState.spawnError) {
      throw new Error(`Avikal core failed to start: ${backendStartupState.spawnError.message || backendStartupState.spawnError}`);
    }

    const probe = await probeBackendHealth();
    if (probe.ok) {
      return;
    }
    lastError = probe.error;

    if (pythonProcess && pythonProcess.exitCode !== null) {
      throw new Error(`Avikal core exited early with code ${pythonProcess.exitCode}`);
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

      console.error('Avikal core failed while starting:', error);
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
    if (parsed.protocol === 'mailto:') {
      return true;
    }
    return parsed.protocol === 'https:' && ALLOWED_EXTERNAL_HOSTS.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function isTrustedRendererUrl(value) {
  if (typeof value !== 'string' || value.length === 0) {
    return false;
  }
  if (frontendDevMode && devServerUrl) {
    return value === devServerUrl || value.startsWith(`${devServerUrl}/`);
  }
  const trustedIndexUrl = pathToFileURL(getRendererIndexPath()).href;
  return value === trustedIndexUrl || value.startsWith(`${trustedIndexUrl}?`) || value.startsWith(`${trustedIndexUrl}#`);
}

function assertTrustedIpcSender(event, channel) {
  if (!mainWindow || mainWindow.isDestroyed()) {
    throw new Error(`IPC channel ${channel} is unavailable because the main window is not ready`);
  }
  if (event.sender !== mainWindow.webContents) {
    throw new Error(`IPC channel ${channel} rejected an unexpected sender`);
  }
  const senderUrl = event.senderFrame?.url || event.sender.getURL?.() || '';
  if (!isTrustedRendererUrl(senderUrl)) {
    throw new Error(`IPC channel ${channel} rejected an untrusted renderer origin`);
  }
}

function registerTrustedHandler(channel, handler) {
  ipcMain.handle(channel, async (event, ...args) => {
    assertTrustedIpcSender(event, channel);
    return handler(event, ...args);
  });
}

function registerTrustedListener(channel, handler) {
  ipcMain.on(channel, (event, ...args) => {
    assertTrustedIpcSender(event, channel);
    handler(event, ...args);
  });
}

function resolveAbsolutePath(candidate, fieldName) {
  if (typeof candidate !== 'string' || candidate.trim().length === 0) {
    throw new Error(`${fieldName} must be a non-empty path`);
  }
  return path.resolve(candidate);
}

function normalizeCapabilityPath(candidate) {
  const resolved = path.resolve(candidate);
  try {
    return fs.realpathSync.native(resolved);
  } catch {
    return resolved;
  }
}

function isPathInsideRoot(root, candidate) {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function getPreviewCapabilityRoots() {
  return [
    path.join(app.getPath('userData'), 'preview_sessions'),
    path.join(os.tmpdir(), 'avikal-runtime', 'preview_sessions'),
  ].map(normalizeCapabilityPath);
}

function registerPathCapability(candidate) {
  if (typeof candidate !== 'string' || candidate.trim().length === 0) {
    return;
  }
  const normalized = normalizeCapabilityPath(candidate);
  try {
    const stats = fs.lstatSync(normalized);
    if (stats.isSymbolicLink()) {
      throw new Error('Symbolic links are not accepted as capability roots');
    }
    if (stats.isDirectory()) {
      allowedFileRoots.add(normalized);
      return;
    }
  } catch {
    // Paths selected for save may not exist yet; keep an exact-file capability.
  }
  allowedFilePaths.add(normalized);
}

function registerSaveDestination(candidate) {
  registerPathCapability(candidate);
  if (typeof candidate === 'string' && candidate.trim().length > 0) {
    registerPathCapability(path.dirname(path.resolve(candidate)));
  }
}

function registerPathCapabilities(paths) {
  if (!Array.isArray(paths)) {
    return;
  }
  for (const candidate of paths) {
    registerPathCapability(candidate);
  }
}

function isPathCapabilityAllowed(candidate) {
  const normalized = normalizeCapabilityPath(candidate);
  if (allowedFilePaths.has(normalized)) {
    return true;
  }
  for (const root of allowedFileRoots) {
    if (isPathInsideRoot(root, normalized)) {
      return true;
    }
  }
  for (const root of getPreviewCapabilityRoots()) {
    if (isPathInsideRoot(root, normalized)) {
      return true;
    }
  }
  return false;
}

function assertPathCapability(candidate, action) {
  if (!isPathCapabilityAllowed(candidate)) {
    throw new Error(`${action} rejected an unapproved source path`);
  }
}

function registerCoreResultCapabilities(value) {
  if (!value || typeof value !== 'object') {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      registerCoreResultCapabilities(item);
    }
    return;
  }
  for (const [key, nested] of Object.entries(value)) {
    if (
      typeof nested === 'string'
      && ['path', 'output_file', 'output_dir', 'output_directory', 'destinationPath'].includes(key)
    ) {
      if (key === 'output_file') {
        registerSaveDestination(nested);
      } else {
        registerPathCapability(nested);
      }
      continue;
    }
    if (nested && typeof nested === 'object') {
      registerCoreResultCapabilities(nested);
    }
  }
}

function normalizeCoreTimeout(method, requestedTimeoutMs) {
  const policy = CORE_METHOD_POLICIES[method];
  if (!policy) {
    throw new Error('Unsupported Avikal core method');
  }
  const requested = Number(requestedTimeoutMs);
  if (policy.timeoutMs === 0) {
    return 0;
  }
  if (!Number.isFinite(requested) || requested <= 0) {
    return policy.timeoutMs;
  }
  return Math.min(Math.floor(requested), policy.timeoutMs);
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
  if (!mainWindow.isVisible()) {
    mainWindow.show();
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.focus();
}

function showMainWindow() {
  if (!mainWindow) {
    void createWindow();
    return;
  }

  if (!mainWindow.isVisible()) {
    mainWindow.show();
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.focus();
}

function hideMainWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    mainWindow.hide();
  }
}

function dispatchLaunchAction(action) {
  if (!action) return;
  registerPathCapabilities(action.paths);

  if (mainWindow && !mainWindow.isDestroyed() && !mainWindow.webContents.isLoadingMainFrame()) {
    mainWindow.webContents.send('launch-action', action);
    pendingLaunchAction = null;
    return;
  }

  pendingLaunchAction = action;
}

function getAppIconPath() {
  const iconFile = process.platform === 'win32' ? 'icon.ico' : 'icon.png';
  return sourceDevMode
    ? path.join(__dirname, '../assets', iconFile)
    : path.join(process.resourcesPath, 'assets', iconFile);
}

function createTray() {
  if (tray || process.platform !== 'win32') {
    return;
  }

  tray = new Tray(getAppIconPath());
  tray.setToolTip('RookDuel Avikal');
  tray.setContextMenu(
    Menu.buildFromTemplate([
      {
        label: 'Open Avikal',
        click: () => {
          showMainWindow();
        },
      },
      {
        type: 'separator',
      },
      {
        label: 'Quit Avikal',
        click: () => {
          app.quit();
        },
      },
    ]),
  );

  tray.on('click', () => {
    if (!mainWindow || mainWindow.isDestroyed() || !mainWindow.isVisible()) {
      showMainWindow();
      return;
    }

    if (mainWindow.isFocused()) {
      hideMainWindow();
      return;
    }

    focusMainWindow();
  });
}

function isDevToolsShortcut(input) {
  const key = String(input?.key || '').toLowerCase();
  const code = String(input?.code || '').toLowerCase();
  const ctrlOrMeta = Boolean(input?.control || input?.meta);
  const shift = Boolean(input?.shift);

  if (key === 'f12' || code === 'f12') {
    return true;
  }

  if (ctrlOrMeta && shift && ['i', 'j', 'c'].includes(key)) {
    return true;
  }

  return false;
}

function hardenProductionWebContents(webContents) {
  if (!productionRendererMode || !webContents) {
    return;
  }

  webContents.on('before-input-event', (event, input) => {
    if (isDevToolsShortcut(input)) {
      event.preventDefault();
    }
  });

  webContents.on('devtools-opened', () => {
    webContents.closeDevTools();
  });

  webContents.on('context-menu', (event) => {
    event.preventDefault();
  });
}

function getBackendRoot() {
  return sourceDevMode
    ? path.join(__dirname, '../backend')
    : path.join(process.resourcesPath, 'backend');
}

function getRendererIndexPath() {
  return path.resolve(__dirname, '../frontend/dist/index.html');
}

function getPythonRuntimeRoot(backendRoot) {
  const sharedRuntimeRoot = path.join(path.dirname(backendRoot), 'backend-runtime');
  if (!sourceDevMode && fs.existsSync(sharedRuntimeRoot)) {
    return sharedRuntimeRoot;
  }
  return sourceDevMode
    ? path.join(backendRoot, 'venv')
    : path.join(process.resourcesPath, 'backend-runtime');
}

function getPythonExecutable(backendRoot) {
  const runtimeRoot = getPythonRuntimeRoot(backendRoot);
  if (sourceDevMode) {
    return process.platform === 'win32'
      ? path.join(runtimeRoot, 'Scripts', 'python.exe')
      : path.join(runtimeRoot, 'bin', 'python');
  }
  return process.platform === 'win32'
    ? path.join(runtimeRoot, 'python.exe')
    : path.join(runtimeRoot, 'bin', 'python');
}

function getPackagedBackendExecutable(backendRoot) {
  if (sourceDevMode) {
    return null;
  }
  return process.platform === 'win32'
    ? path.join(backendRoot, 'avikal-backend.exe')
    : path.join(backendRoot, 'avikal-backend');
}

function getSharedCoreVersionRoot() {
  const localAppData = process.env.LOCALAPPDATA || app.getPath('userData');
  return path.join(localAppData, SHARED_CORE_VENDOR_DIR, app.getVersion());
}

function getSharedCoreBackendRoot(coreRoot) {
  return path.join(coreRoot, 'backend');
}

function hashFileIfPresent(filePath) {
  try {
    if (!fs.existsSync(filePath)) return null;
    const hash = crypto.createHash('sha256');
    hash.update(fs.readFileSync(filePath));
    return hash.digest('hex');
  } catch {
    return null;
  }
}

function getPqcRuntimeExecutable(coreRoot) {
  return process.platform === 'win32'
    ? path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'openssl.exe')
    : path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'openssl');
}

function getNativeModulePath(coreRoot) {
  const candidates = [
    path.join(coreRoot, 'backend', '_internal', 'avikal_backend', '_native.pyd'),
    path.join(coreRoot, 'backend', 'avikal_backend', '_native.pyd'),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function readSharedCoreManifest(coreRoot) {
  try {
    return JSON.parse(fs.readFileSync(path.join(coreRoot, 'core.json'), 'utf8'));
  } catch {
    return null;
  }
}

function verifySharedCoreManifest(coreRoot, executablePath) {
  const manifest = readSharedCoreManifest(coreRoot);
  if (!manifest || manifest.version !== app.getVersion() || manifest.platform !== process.platform) {
    return false;
  }
  if (manifest.executablePath && path.normalize(manifest.executablePath) !== path.normalize(executablePath)) {
    return false;
  }

  const nativeModulePath = getNativeModulePath(coreRoot);
  const pqcExecutable = getPqcRuntimeExecutable(coreRoot);
  if (!nativeModulePath || !fs.existsSync(pqcExecutable)) {
    return false;
  }
  return manifest.nativeModuleHash === hashFileIfPresent(nativeModulePath)
    && manifest.pqcRuntimeHash === hashFileIfPresent(pqcExecutable);
}

function runCoreRuntimeVerification(executablePath) {
  if (!fs.existsSync(executablePath)) {
    return false;
  }
  const result = spawnSync(executablePath, ['--verify-runtime'], {
    cwd: path.dirname(executablePath),
    env: {
      ...process.env,
      AVIKAL_USER_DATA_DIR: app.getPath('userData'),
      AVIKAL_PQC_TEMP_DIR: path.join(app.getPath('userData'), 'pqc-work'),
    },
    encoding: 'utf8',
    windowsHide: true,
    timeout: 30000,
  });
  if (result.status !== 0) {
    console.warn('Shared Avikal core verification failed:', result.stderr || result.stdout || result.error);
    return false;
  }
  return true;
}

function verifyCoreExecutable(executablePath, coreRoot) {
  if (!fs.existsSync(executablePath) || !verifySharedCoreManifest(coreRoot, executablePath)) {
    return false;
  }
  return runCoreRuntimeVerification(executablePath);
}

function writeSharedCoreManifest(coreRoot, executablePath) {
  const nativeModulePath = getNativeModulePath(coreRoot);
  const pqcExecutable = getPqcRuntimeExecutable(coreRoot);
  if (!nativeModulePath) {
    throw new Error('Bundled Avikal core is missing the native crypto module');
  }
  if (!fs.existsSync(pqcExecutable)) {
    throw new Error('Bundled Avikal core is missing the PQC runtime');
  }
  const manifest = {
    version: app.getVersion(),
    appVersion: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    executablePath,
    nativeModuleHash: hashFileIfPresent(nativeModulePath),
    pqcRuntimeHash: hashFileIfPresent(pqcExecutable),
    archiveCompatibility: 'avk-v1',
    installedAt: new Date().toISOString(),
  };
  fs.writeFileSync(path.join(coreRoot, 'core.json'), JSON.stringify(manifest, null, 2), 'utf8');
}

function ensureSharedCoreInstalled(bundledBackendRoot) {
  if (sourceDevMode || !process.resourcesPath) {
    return null;
  }
  const coreRoot = getSharedCoreVersionRoot();
  const sharedBackendRoot = getSharedCoreBackendRoot(coreRoot);
  const sharedExecutable = getPackagedBackendExecutable(sharedBackendRoot);
  if (sharedExecutable && verifyCoreExecutable(sharedExecutable, coreRoot)) {
    return sharedBackendRoot;
  }

  const bundledRuntimeRoot = path.join(process.resourcesPath, 'backend-runtime');
  const bundledExecutable = getPackagedBackendExecutable(bundledBackendRoot);
  if (!bundledExecutable || !fs.existsSync(bundledExecutable) || !fs.existsSync(bundledRuntimeRoot)) {
    return null;
  }

  const parent = path.dirname(coreRoot);
  const tempRoot = `${coreRoot}.tmp-${process.pid}`;
  fs.mkdirSync(parent, { recursive: true });
  fs.rmSync(tempRoot, { recursive: true, force: true });
  fs.mkdirSync(tempRoot, { recursive: true });
  fs.cpSync(bundledBackendRoot, path.join(tempRoot, 'backend'), { recursive: true });
  fs.cpSync(bundledRuntimeRoot, path.join(tempRoot, 'backend-runtime'), { recursive: true });
  const tempExecutable = getPackagedBackendExecutable(path.join(tempRoot, 'backend'));
  const finalExecutable = getPackagedBackendExecutable(sharedBackendRoot);
  writeSharedCoreManifest(tempRoot, finalExecutable);

  if (!runCoreRuntimeVerification(tempExecutable)) {
    fs.rmSync(tempRoot, { recursive: true, force: true });
    throw new Error('Bundled Avikal core failed verification and cannot be shared');
  }

  fs.rmSync(coreRoot, { recursive: true, force: true });
  fs.renameSync(tempRoot, coreRoot);
  if (!verifyCoreExecutable(finalExecutable, coreRoot)) {
    fs.rmSync(coreRoot, { recursive: true, force: true });
    throw new Error('Installed Avikal shared core failed manifest verification');
  }
  return sharedBackendRoot;
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

// Avikal core process management
function startPythonBackend() {
  if (pythonProcess && pythonProcess.exitCode === null) {
    return waitForBackendReady();
  }

  const bundledBackendRoot = getBackendRoot();
  const backendRoot = ensureSharedCoreInstalled(bundledBackendRoot) || bundledBackendRoot;
  const runtimeRoot = getPythonRuntimeRoot(backendRoot);
  const packagedBackendExecutable = getPackagedBackendExecutable(backendRoot);
  const usePackagedBackend = !sourceDevMode && packagedBackendExecutable && fs.existsSync(packagedBackendExecutable);
  const pythonScript = path.join(backendRoot, 'core_server.py');
  const pythonExecutable = getPythonExecutable(backendRoot);
  let backendCommand = packagedBackendExecutable;
  let backendArgs = ['--gui-mode'];

  if (usePackagedBackend) {
    console.log(`Starting packaged Avikal core with: ${packagedBackendExecutable}`);
  } else {
    if (!fs.existsSync(pythonExecutable)) {
      throw new Error(`Python runtime not found: ${pythonExecutable}`);
    }

    if (!fs.existsSync(pythonScript)) {
      throw new Error(`Backend entrypoint not found: ${pythonScript}`);
    }

    console.log(`Starting source Avikal core with: ${pythonExecutable}`);
    backendCommand = pythonExecutable;
    backendArgs = [pythonScript, '--gui-mode'];
  }
  resetBackendStartupState();

  const pythonEnv = {
    ...process.env,
    PYTHONIOENCODING: 'utf-8',
    PYTHONUNBUFFERED: '1',
    AVIKAL_STDIO_RPC: '1',
    // Pass the Electron executable path to the Avikal core.
    // drand.py uses this with ELECTRON_RUN_AS_NODE=1 to run the drand helper script
    // using Electron's bundled Node.js runtime — no external Node.js installation needed.
    // This is the official Electron-documented pattern used by VS Code, Cursor, etc.
    AVIKAL_ELECTRON_EXEC: process.execPath,
    AVIKAL_PQC_TEMP_DIR: path.join(app.getPath('userData'), 'pqc-work'),
  };

  if (!sourceDevMode && !usePackagedBackend) {
    pythonEnv.AVIKAL_USER_DATA_DIR = app.getPath('userData');
    pythonEnv.PYTHONHOME = runtimeRoot;
    pythonEnv.PYTHONPATH = [
      backendRoot,
      path.join(runtimeRoot, 'Lib'),
      path.join(runtimeRoot, 'Lib', 'site-packages')
    ].join(path.delimiter);
    pythonEnv.PYTHONNOUSERSITE = '1';
  }

  if (!sourceDevMode && usePackagedBackend) {
    pythonEnv.AVIKAL_USER_DATA_DIR = app.getPath('userData');
  }

  pythonProcess = spawn(backendCommand, backendArgs, {
    stdio: 'pipe',
    cwd: backendRoot,
    env: pythonEnv,
    windowsHide: true
  });

  pythonProcess.on('error', (error) => {
    backendStartupState.spawnError = error;
    console.error('Python process failed to start:', error);
  });

  coreRpcClient = new CoreRpcClient(pythonProcess);
  
  pythonProcess.stderr.on('data', (data) => {
    recordBackendOutput(data.toString(), 'stderr');
    console.error(`[Avikal Core Error] ${data}`);
  });
  
  pythonProcess.on('close', (code) => {
    console.log(`Avikal core process exited with code ${code}`);
    if (coreRpcClient) {
      coreRpcClient.dispose(new Error(`Avikal core exited with code ${code}`));
      coreRpcClient = null;
    }
    if (!isQuitting) {
      publishBackendRuntimeStatus(
        code === 0 ? 'stopped' : 'error',
        code === 0 ? null : `Avikal core exited with code ${code}`
      );
    }
  });

  return waitForBackendReady();
}

function stopPythonBackend() {
  if (coreRpcClient) {
    coreRpcClient.dispose();
    coreRpcClient = null;
  }
  if (pythonProcess) {
    pythonProcess.kill();
    pythonProcess = null;
  }
}

async function cleanupBackendPreviewSessions() {
  try {
    if (coreRpcClient) {
      await coreRpcClient.request('preview.cleanupAll', {}, 10000);
    }
  } catch (error) {
    console.warn('Preview session cleanup failed during shutdown:', error);
  }
}

// Create main window
async function createWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    showMainWindow();
    return;
  }

  if (!pythonProcess || pythonProcess.exitCode !== null) {
    coreRpcClient = null;
  }
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 760,
    minHeight: 620,
    backgroundColor: '#0A0E27',
    icon: getAppIconPath(),
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
      sandbox: true,
      webviewTag: false,
      spellcheck: false,
      devTools: !productionRendererMode,
      preload: path.join(__dirname, 'preload.js')
    },
    frame: false,
    show: false
  });
  hardenProductionWebContents(mainWindow.webContents);
  
  // Load app immediately
  if (frontendDevMode) {
    try {
      await mainWindow.webContents.session.clearCache();
      await mainWindow.webContents.session.clearStorageData({
        storages: ['serviceworkers'],
      });
    } catch (error) {
      console.warn('Failed to clear dev renderer cache:', error);
    }
    mainWindow.loadURL(`${devServerUrl}/?devts=${Date.now()}`);
  } else {
    mainWindow.webContents.session.webRequest.onHeadersReceived((details, callback) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          'Content-Security-Policy': [PRODUCTION_RENDERER_CSP],
        },
      });
    });
    const indexPath = getRendererIndexPath();
    console.log(`Loading frontend from: ${indexPath}`);
    mainWindow.loadFile(indexPath);
  }
  
  // Show when ready
  mainWindow.once('ready-to-show', () => {
    console.log('Window ready to show');
    mainWindow.show();
  });

  // Start the Avikal core in the background without blocking the UI
  publishBackendRuntimeStatus('starting');
  startPythonBackend()
    .then(() => {
      publishBackendRuntimeStatus('ready');
    })
    .catch((error) => {
      if (isBackendStartupTimeout(error) && pythonProcess && pythonProcess.exitCode === null) {
        console.warn('Avikal core is still starting after initial readiness window:', error);
        publishBackendRuntimeStatus(
          'starting',
          'Backend is still loading. You can keep the app open while startup finishes.'
        );
        monitorBackendReadyAfterSlowStart();
        return;
      }

      console.error('Failed to start Avikal core:', error);
      publishBackendRuntimeStatus('error', error.message || String(error));
      dialog.showErrorBox(
        'RookDuel Avikal Startup Error',
        `The Avikal core could not be started.\n\n${error.message || error}`
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

  mainWindow.on('close', (event) => {
    if (isQuitting) {
      return;
    }

    event.preventDefault();
    hideMainWindow();
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    if (isAllowedExternalUrl(url)) {
      require('electron').shell.openExternal(url).catch((error) => {
        console.error('Failed to open external URL:', error);
      });
    }
    return { action: 'deny' };
  });

  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isTrustedRendererUrl(url)) {
      event.preventDefault();
    }
  });

  mainWindow.webContents.on('will-attach-webview', (event) => {
    event.preventDefault();
  });

  mainWindow.webContents.session.setPermissionRequestHandler((_webContents, _permission, callback) => {
    callback(false);
  });
}

// IPC Handlers
registerTrustedHandler('dialog:openFile', async (_event, options) => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openFile', 'multiSelections'],
    ...options
  });
  registerPathCapabilities(result.filePaths);
  return result.canceled ? [] : result.filePaths;
});

registerTrustedHandler('dialog:saveFile', async (_event, options) => {
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: 'encrypted.avk',
    filters: [{ name: 'RookDuel Avikal Files', extensions: ['avk'] }],
    ...options
  });
  if (result.filePath) {
    registerSaveDestination(result.filePath);
  }
  return result.filePath;
});

registerTrustedHandler('dialog:openDirectory', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory']
  });
  registerPathCapabilities(result.filePaths);
  return result.filePaths[0];
});

registerTrustedHandler('dialog:openFolders', async () => {
  const result = await dialog.showOpenDialog(mainWindow, {
    properties: ['openDirectory', 'multiSelections']
  });
  registerPathCapabilities(result.filePaths);
  return result.canceled ? [] : result.filePaths;
});

// Recursive directory scanner — builds a full tree for the UI
registerTrustedHandler('fs:scanDirectory', async (_event, dirPath) => {
  try {
    assertPathCapability(dirPath, 'Directory scan');
    return await buildDirectoryNode(dirPath);
  } catch (error) {
    console.error('fs:scanDirectory error:', error);
    const safePath = typeof dirPath === 'string' ? path.basename(dirPath) : 'unknown';
    return { name: safePath, path: safePath, isDir: false, size: 0, error: true };
  }
});

registerTrustedHandler('file:saveText', async (_event, options = {}) => {
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
  registerSaveDestination(destination);
  return destination;
});

registerTrustedHandler('file:exportCopy', async (_event, options = {}) => {
  const source = resolveAbsolutePath(options.sourcePath, 'Source path');
  assertPathCapability(source, 'File export');
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
  registerSaveDestination(destination);
  return destination;
});

registerTrustedHandler('file:exportFilesToDirectory', async (_event, options = {}) => {
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
    assertPathCapability(source, 'Directory export');
    const relativePath = normalizeRelativePath(entry?.relativePath);
    const destination = path.join(destinationRoot, relativePath);

    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    await fs.promises.copyFile(source, destination, fs.constants.COPYFILE_EXCL);
    registerSaveDestination(destination);
    copiedCount += 1;
  }

  return {
    destinationPath: destinationRoot,
    copiedCount,
  };
});

registerTrustedHandler('shell:openPath', async (_event, targetPath) => {
  const { shell } = require('electron');
  const resolvedPath = resolveAbsolutePath(targetPath, 'Path');
  assertPathCapability(resolvedPath, 'Open path');
  await fs.promises.access(resolvedPath, fs.constants.F_OK);
  return shell.openPath(resolvedPath);
});

registerTrustedHandler('shell:openExternal', async (_event, url) => {
  const { shell } = require('electron');
  if (!isAllowedExternalUrl(url)) {
    throw new Error('Only https and mailto links can be opened externally');
  }
  await shell.openExternal(url);
  return true;
});

registerTrustedListener('theme:update', (_event, { isDark }) => {
  // Native titleBarOverlay is removed; theme context is handled purely via React/CSS.
});

registerTrustedHandler('window:minimize', async () => {
  mainWindow.minimize();
});

registerTrustedHandler('window:maximize', async () => {
  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize();
  } else {
    mainWindow.maximize();
  }
});

registerTrustedHandler('window:close', async () => {
  hideMainWindow();
});

registerTrustedHandler('launchAction:getPending', async () => {
  const action = pendingLaunchAction;
  pendingLaunchAction = null;
  if (action) {
    registerPathCapabilities(action.paths);
  }
  return action;
});

registerTrustedHandler('backend:getStatus', async () => {
  return backendRuntimeStatus;
});

registerTrustedHandler('app:getInfo', async () => {
  return {
    name: app.getName(),
    version: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    packaged: app.isPackaged,
    updateFeed: UPDATE_RELEASES_PAGE_URL,
  };
});

registerTrustedHandler('updates:check', async () => {
  return checkLatestRelease();
});

registerTrustedHandler('updates:openLatest', async () => {
  const { shell } = require('electron');
  await shell.openExternal(UPDATE_RELEASES_PAGE_URL);
  return true;
});

registerTrustedHandler('core:invoke', async (_event, method, params = {}, timeoutMs = 300000) => {
  if (typeof method !== 'string' || method.length === 0 || method.length > 128) {
    throw new Error('Invalid Avikal core method');
  }
  if (!coreRpcClient) {
    throw new Error('Avikal core is not ready');
  }
  const safeTimeoutMs = normalizeCoreTimeout(method, timeoutMs);
  const result = await coreRpcClient.request(method, params && typeof params === 'object' ? params : {}, safeTimeoutMs);
  registerCoreResultCapabilities(result);
  return result;
});

// Secure token storage
registerTrustedHandler('safeStorage:encrypt', async (_event, data) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable on this system')
  }
  if (typeof data !== 'string' || Buffer.byteLength(data, 'utf8') > 16384) {
    throw new Error('Secure storage input must be a string up to 16 KB')
  }
  return safeStorage.encryptString(data).toString('base64')
})

registerTrustedHandler('safeStorage:decrypt', async (_event, encryptedData) => {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Secure storage is unavailable on this system')
  }
  if (typeof encryptedData !== 'string' || encryptedData.length > 65536) {
    throw new Error('Secure storage payload is invalid')
  }
  const buffer = Buffer.from(encryptedData, 'base64')
  return safeStorage.decryptString(buffer)
})

registerTrustedHandler('safeStorage:isAvailable', async () => {
  return safeStorage.isEncryptionAvailable()
})

// App lifecycle
app.whenReady().then(() => {
  if (productionRendererMode) {
    Menu.setApplicationMenu(null);
  }
  createTray();
  return createWindow();
});

app.on('window-all-closed', () => {
  // Keep the app and backend resident in the background until the user exits explicitly.
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0 || !mainWindow || mainWindow.isDestroyed()) {
    void createWindow();
    return;
  }

  showMainWindow();
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
