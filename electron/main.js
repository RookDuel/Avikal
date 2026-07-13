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
const packagedApp = app.isPackaged;
const verifyInstallationMode = packagedApp && process.env.AVIKAL_VERIFY_INSTALLATION === '1';
delete process.env.AVIKAL_VERIFY_INSTALLATION;
const sourceDevMode = !packagedApp && process.env.AVIKAL_USE_SOURCE_BACKEND === '1';
const devServerUrl = packagedApp ? null : normalizeDevServerUrl(process.env.AVIKAL_DEV_SERVER_URL);
const frontendDevMode = Boolean(devServerUrl);
const productionRendererMode = !frontendDevMode;
const BACKEND_READY_TIMEOUT_MS = sourceDevMode ? 30000 : 45000;
const BACKEND_HEALTH_POLL_INTERVAL_MS = 250;
const BACKEND_HEALTH_REQUEST_TIMEOUT_MS = 1500;
const CORE_TRANSPORT_URL = 'stdio://avikal-core';
const UPDATE_REPO_OWNER = 'RookDuel';
const UPDATE_REPO_NAME = 'Avikal';
const UPDATE_RELEASES_API_URL = `https://api.github.com/repos/${UPDATE_REPO_OWNER}/${UPDATE_REPO_NAME}/releases/latest`;
const UPDATE_RELEASES_PAGE_URL = `https://github.com/${UPDATE_REPO_OWNER}/${UPDATE_REPO_NAME}/releases/latest`;
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
const MAX_ASSURANCE_REPORT_BYTES = 2 * 1024 * 1024;
const FORBIDDEN_REPORT_FIELDS = new Set([
  'password', 'keyphrase', 'private_bundle', 'private_key', 'master_key',
  'payload_key', 'derived_key', 'pqc_shared_secret', 'absolute_path',
]);
const CREATOR_IDENTITY_STORE_VERSION = 1;
const RELEASE_SIGNING_PUBLIC_KEY_PATH = path.join(__dirname, 'release-signing-public.pem');
const SHARED_CORE_VENDOR_DIR = path.join('RookDuel', 'Avikal', 'Core');
const SHARED_CORE_MANIFEST_VERSION = 2;
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
  'archive.splitVolumes': { timeoutMs: 0 },
  'archive.joinVolumes': { timeoutMs: 0 },
  'archive.openSession': { timeoutMs: 0 },
  'archive.extractSelection': { timeoutMs: 0 },
  'archive.extractAll': { timeoutMs: 0 },
  'archive.verifyAll': { timeoutMs: 0 },
  'archive.closeSession': { timeoutMs: 10000 },
  'archive.rekey': { timeoutMs: 0 },
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
  'security.diagnosticsExport': { timeoutMs: 30000 },
});
const CORE_API_SIGNATURE = crypto
  .createHash('sha256')
  .update(JSON.stringify(Object.keys(CORE_METHOD_POLICIES).sort()))
  .digest('hex');
const DIAGNOSTIC_LOG_MAX_BYTES = 8 * 1024 * 1024;
const DIAGNOSTIC_SENSITIVE_KEYS = new Set([
  'authorization', 'keyphrase', 'new_keyphrase', 'old_keyphrase', 'new_password',
  'old_password', 'password', 'pqc_keyfile_password', 'secret', 'session_token',
  'token', 'sender_message', 'creator_signing_identity', 'private_bundle', 'private_key', 'payload_key',
  'master_key', 'derived_key',
]);
const DIAGNOSTIC_PATH_KEYS = new Set([
  'input_file', 'input_files', 'output_file', 'output_folder', 'keyfile_path',
  'pqc_keyfile', 'archive_path', 'file_path', 'path',
]);

function creatorIdentityStorePath() {
  return path.join(app.getPath('userData'), 'creator-identities.json');
}

function diagnosticDirectory() {
  const target = path.join(app.getPath('userData'), 'diagnostics');
  fs.mkdirSync(target, { recursive: true });
  return target;
}

function electronDiagnosticLogPath() {
  return path.join(diagnosticDirectory(), 'avikal-electron-diagnostics.jsonl');
}

function hashDiagnosticText(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex').slice(0, 16);
}

function summarizeDiagnosticPath(value) {
  const text = String(value || '');
  return {
    basename: path.basename(text),
    path_hash: hashDiagnosticText(text),
  };
}

function isDiagnosticSensitiveKey(key) {
  const normalized = String(key || '').trim().toLowerCase().replace(/-/g, '_');
  return DIAGNOSTIC_SENSITIVE_KEYS.has(normalized) || normalized.endsWith('_secret') || normalized.endsWith('_token');
}

function sanitizeDiagnosticValue(value, key = '', depth = 0) {
  if (depth > 8) return '[DEPTH_LIMIT]';
  if (isDiagnosticSensitiveKey(key)) return '[REDACTED]';
  const normalizedKey = String(key || '').trim().toLowerCase();
  if (typeof value === 'string' && DIAGNOSTIC_PATH_KEYS.has(normalizedKey)) {
    return summarizeDiagnosticPath(value);
  }
  if (Array.isArray(value) && DIAGNOSTIC_PATH_KEYS.has(normalizedKey)) {
    return value.slice(0, 100).map((item) => typeof item === 'string' ? summarizeDiagnosticPath(item) : '[INVALID_PATH]');
  }
  if (Array.isArray(value)) {
    const limited = value.slice(0, 200).map((item) => sanitizeDiagnosticValue(item, '', depth + 1));
    if (value.length > 200) limited.push(`[TRUNCATED_${value.length - 200}_ITEMS]`);
    return limited;
  }
  if (value && typeof value === 'object') {
    const output = {};
    for (const [itemKey, itemValue] of Object.entries(value)) {
      output[itemKey] = sanitizeDiagnosticValue(itemValue, itemKey, depth + 1);
    }
    return output;
  }
  if (typeof value === 'string') {
    const redacted = value
      .replace(/\b(password|keyphrase|token|secret)\b\s*[:=]\s*('[^']*'|"[^"]*"|[^\s,;]+)/gi, '$1=[REDACTED]')
      .replace(/(bearer\s+)[A-Za-z0-9._~+/=-]{8,}/gi, '$1[REDACTED]');
    return redacted.length > 4096 ? `${redacted.slice(0, 4096)}...[TRUNCATED_${redacted.length - 4096}_CHARS]` : redacted;
  }
  return value;
}

function serializeDiagnosticError(error) {
  if (!error) return null;
  return {
    name: error.name || 'Error',
    message: sanitizeDiagnosticValue(error.message || String(error)),
    code: error.code,
    data: sanitizeDiagnosticValue(error.data),
    stack: sanitizeDiagnosticValue(error.stack || ''),
  };
}

function writeDiagnosticEvent(event) {
  try {
    const logPath = electronDiagnosticLogPath();
    if (fs.existsSync(logPath) && fs.statSync(logPath).size > DIAGNOSTIC_LOG_MAX_BYTES) {
      const rotated = path.join(path.dirname(logPath), 'avikal-electron-diagnostics.1.jsonl');
      if (fs.existsSync(rotated)) fs.unlinkSync(rotated);
      fs.renameSync(logPath, rotated);
    }
    const entry = {
      schema_version: 1,
      event_id: crypto.randomBytes(8).toString('hex'),
      logged_at_utc: new Date().toISOString(),
      source: 'electron',
      app_version: app.getVersion(),
      packaged: app.isPackaged,
      platform: process.platform,
      arch: process.arch,
      ...sanitizeDiagnosticValue(event),
    };
    fs.appendFileSync(logPath, `${JSON.stringify(entry, null, 0)}\n`, 'utf8');
  } catch (error) {
    console.warn('Failed to write Avikal diagnostic event:', error);
  }
}

function summarizeCoreResult(result) {
  if (!result || typeof result !== 'object') return { type: typeof result };
  const keys = Object.keys(result);
  return {
    type: Array.isArray(result) ? 'array' : 'object',
    keys: keys.slice(0, 30),
    success: Boolean(result.success),
    mode: result.mode,
    provider: result.provider,
    session_id_present: typeof result.session_id === 'string',
    result_type: result.result && typeof result.result === 'object' ? Object.keys(result.result).slice(0, 20) : undefined,
  };
}

function readElectronDiagnosticEntries(limit = 400) {
  const logPath = electronDiagnosticLogPath();
  if (!fs.existsSync(logPath)) return [];
  const lines = fs.readFileSync(logPath, 'utf8').split(/\r?\n/).filter(Boolean);
  return lines.slice(-limit).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return { parse_error: true, raw: line.slice(0, 512) };
    }
  });
}

function buildElectronDiagnosticsMarkdown() {
  const entries = readElectronDiagnosticEntries();
  const lines = [
    '# Electron IPC Diagnostics',
    '',
    `- Exported events: ${entries.length}`,
    `- Raw log storage: \`${electronDiagnosticLogPath()}\``,
    '',
  ];
  if (entries.length === 0) {
    lines.push('No Electron diagnostic events have been recorded yet.', '');
  } else {
    for (const entry of entries.reverse()) {
      lines.push(
        `## ${entry.logged_at_utc || '-'} - ${entry.event || 'event'} - ${entry.status || 'unknown'}`,
        '',
        `- Correlation ID: \`${entry.correlation_id || '-'}\``,
        `- Channel: \`${entry.channel || '-'}\``,
        `- Method: \`${entry.method || '-'}\``,
        '',
        '```json',
        JSON.stringify(entry, null, 2),
        '```',
        '',
      );
    }
  }
  return lines.join('\n');
}

async function readCreatorIdentityStore() {
  try {
    const parsed = JSON.parse(await fs.promises.readFile(creatorIdentityStorePath(), 'utf8'));
    if (parsed?.version !== CREATOR_IDENTITY_STORE_VERSION || !Array.isArray(parsed.identities) || !Array.isArray(parsed.trusted)) {
      throw new Error('Signing key store format is invalid');
    }
    return parsed;
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return { version: CREATOR_IDENTITY_STORE_VERSION, identities: [], trusted: [] };
    }
    throw error;
  }
}

function hardenWindowsPrivatePath(target) {
  if (process.platform !== 'win32') return;
  const identity = spawnSync('whoami.exe', ['/user', '/fo', 'csv', '/nh'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 10000,
  });
  const match = String(identity.stdout || '').match(/"[^"]+","(S-1-[^"]+)"/);
  if (identity.status !== 0 || !match) {
    throw new Error('Unable to determine the Windows user identity for private storage');
  }
  const acl = spawnSync('icacls.exe', [target, '/inheritance:r', '/grant:r', `*${match[1]}:F`, '/Q'], {
    encoding: 'utf8',
    windowsHide: true,
    timeout: 15000,
  });
  if (acl.status !== 0) {
    throw new Error('Unable to apply a private Windows ACL to signing key storage');
  }
}

async function writeCreatorIdentityStore(store) {
  const target = creatorIdentityStorePath();
  await fs.promises.mkdir(path.dirname(target), { recursive: true });
  const temporary = `${target}.${crypto.randomBytes(8).toString('hex')}.tmp`;
  const payload = JSON.stringify(store, null, 2);
  await fs.promises.writeFile(temporary, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
  await fs.promises.rename(temporary, target);
  hardenWindowsPrivatePath(target);
}

function publicIdentityView(record) {
  return {
    identity_id: record.identity_id,
    label: record.label,
    created_at: record.created_at,
    public_bundle: record.public_bundle,
    persistent: true,
  };
}

async function loadCreatorSigningIdentity(identityId) {
  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('OS secure storage is unavailable; signing key cannot be unlocked');
  }
  const store = await readCreatorIdentityStore();
  const record = store.identities.find((item) => item.identity_id === identityId);
  if (!record) throw new Error('Selected signing key was not found');
  const privateJson = safeStorage.decryptString(Buffer.from(record.encrypted_private_bundle, 'base64'));
  let privateBundle;
  try {
    privateBundle = JSON.parse(privateJson);
  } catch {
    throw new Error('Stored signing key is corrupted');
  }
  return { public_bundle: record.public_bundle, private_bundle: privateBundle };
}

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
let activeVisualMode = detectDefaultVisualMode();
let activeVisualEngine = 'none';

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function detectDefaultVisualMode() {
  if (process.platform !== 'win32') return 'normal';
  const totalMemoryGb = os.totalmem() / (1024 ** 3);
  const logicalCores = os.cpus()?.length || 1;
  if (totalMemoryGb < 7.5 || logicalCores < 4) return 'normal';
  return 'effects';
}

function normalizeVisualMode(mode) {
  return mode === 'effects' ? 'effects' : 'normal';
}

function applyWindowVisualMode(mode) {
  activeVisualMode = normalizeVisualMode(mode);
  activeVisualEngine = activeVisualMode === 'effects' ? 'css' : 'none';
  if (!mainWindow || mainWindow.isDestroyed()) return activeVisualMode;

  try {
    if (process.platform === 'win32' && typeof mainWindow.setBackgroundMaterial === 'function') {
      const buildNumber = Number(os.release().split('.')[2] || 0);
      const supportsNativeMaterial = Number.isFinite(buildNumber) && buildNumber >= 22000;
      mainWindow.setBackgroundMaterial(activeVisualMode === 'effects' && supportsNativeMaterial ? 'acrylic' : 'none');
      activeVisualEngine = activeVisualMode === 'effects' && supportsNativeMaterial ? 'native' : activeVisualEngine;
    }
  } catch (error) {
    console.warn('Failed to apply native background material:', error);
    activeVisualEngine = activeVisualMode === 'effects' ? 'css' : 'none';
  }

  try {
    mainWindow.setBackgroundColor('#050505');
  } catch (error) {
    console.warn('Failed to apply window background color:', error);
  }

  try {
    mainWindow.webContents.send('visual-mode:changed', { mode: activeVisualMode, engine: activeVisualEngine });
  } catch {
    // Window may not be ready yet.
  }
  return activeVisualMode;
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

async function readVerifiedReleaseMetadataAsset(assets) {
  const metadataAsset = findReleaseAsset(assets, /^avikal-release-metadata\.json$/i);
  const signatureAsset = findReleaseAsset(assets, /^avikal-release-metadata\.json\.sig$/i);
  if (!metadataAsset || !signatureAsset) {
    return null;
  }
  try {
    const [metadataText, signatureText] = await Promise.all([
      httpsText(metadataAsset.url),
      httpsText(signatureAsset.url),
    ]);
    const signature = Buffer.from(signatureText.trim(), 'base64');
    if (signature.length !== 64) {
      throw new Error('Release metadata signature has an invalid length');
    }
    const publicKey = fs.readFileSync(RELEASE_SIGNING_PUBLIC_KEY_PATH, 'utf8');
    const verified = crypto.verify(null, Buffer.from(metadataText, 'utf8'), publicKey, signature);
    if (!verified) {
      throw new Error('Release metadata signature verification failed');
    }
    return JSON.parse(metadataText);
  } catch (error) {
    console.warn('Failed to verify release metadata asset:', error);
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

function assertReleaseMetadataMatchesAssets(metadata, assets, expectedVersion) {
  if (!metadata || typeof metadata !== 'object') return false;
  const guiName = String(metadata.gui_installer_name || '');
  const cliName = String(metadata.cli_installer_name || '');
  if (!guiName || !cliName) return false;
  if (!normalizeSha256(metadata.gui_installer_sha256) || !normalizeSha256(metadata.cli_installer_sha256)) return false;
  if (!assets.some((asset) => asset.name === guiName)) return false;
  if (!assets.some((asset) => asset.name === cliName)) return false;
  const metadataVersion = String(metadata.product_version || '').replace(/^v/i, '');
  if (!normalizeVersion(metadataVersion) || compareVersions(metadataVersion, expectedVersion) !== 0) return false;
  if (!/^[a-f0-9]{40,64}$/i.test(String(metadata.source_commit || ''))) return false;
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
  const metadata = await readVerifiedReleaseMetadataAsset(assets);
  const metadataVerified = assertReleaseMetadataMatchesAssets(metadata, assets, latestVersion);
  const guiAsset = metadataVerified
    ? findReleaseAsset(assets, new RegExp(`^${metadata.gui_installer_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
    : findReleaseAsset(assets, /^RookDuel-Avikal\.exe$/i);
  const cliAsset = metadataVerified
    ? findReleaseAsset(assets, new RegExp(`^${metadata.cli_installer_name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i'))
    : findReleaseAsset(assets, /^RookDuel-Avikal-CLI\.exe$/i);
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
    try {
      return await handler(event, ...args);
    } catch (error) {
      writeDiagnosticEvent({
        event: 'ipc_handler',
        status: 'failed',
        level: 'error',
        channel,
        args: sanitizeDiagnosticValue(args),
        error: serializeDiagnosticError(error),
      });
      throw error;
    }
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

function getPqcRuntimeLibrary(coreRoot) {
  let candidates;
  if (process.platform === 'win32') {
    candidates = [
      path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'libcrypto-3-x64.dll'),
      path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'libcrypto-3.dll'),
    ];
  } else if (process.platform === 'darwin') {
    candidates = [
      path.join(coreRoot, 'backend-runtime', 'pqc', 'lib', 'libcrypto.3.dylib'),
      path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'libcrypto.3.dylib'),
    ];
  } else {
    candidates = [
      path.join(coreRoot, 'backend-runtime', 'pqc', 'lib', 'libcrypto.so.3'),
      path.join(coreRoot, 'backend-runtime', 'pqc', 'lib64', 'libcrypto.so.3'),
      path.join(coreRoot, 'backend-runtime', 'pqc', 'bin', 'libcrypto.so.3'),
    ];
  }
  return candidates.find((candidate) => fs.existsSync(candidate)) || candidates[0];
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

function verifySignedRuntimeManifest(coreRoot) {
  try {
    const manifestPath = path.join(coreRoot, 'backend-runtime', 'avikal-runtime-integrity.json');
    const signaturePath = `${manifestPath}.sig`;
    const manifestBytes = fs.readFileSync(manifestPath);
    const signature = Buffer.from(fs.readFileSync(signaturePath, 'ascii').trim(), 'base64');
    const publicKey = fs.readFileSync(RELEASE_SIGNING_PUBLIC_KEY_PATH, 'utf8');
    if (signature.length !== 64 || !crypto.verify(null, manifestBytes, publicKey, signature)) {
      return false;
    }
    const manifest = JSON.parse(manifestBytes.toString('utf8'));
    if (manifest?.format !== 'avikal-runtime-integrity' || manifest.version !== 1 || manifest.product_version !== app.getVersion()) {
      return false;
    }
    if (!Array.isArray(manifest.files) || manifest.files.length < 4 || manifest.files.length > 32) {
      return false;
    }
    for (const entry of manifest.files) {
      if (!entry || typeof entry.path !== 'string' || !/^[a-zA-Z0-9_./-]+$/.test(entry.path)) return false;
      const target = path.resolve(coreRoot, entry.path);
      const relative = path.relative(path.resolve(coreRoot), target);
      if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || !fs.existsSync(target)) return false;
      const stat = fs.statSync(target);
      if (!stat.isFile() || stat.size !== entry.size || hashFileIfPresent(target) !== entry.sha256) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function verifySharedCoreManifest(coreRoot, executablePath, expectedBackendHash = null) {
  const manifest = readSharedCoreManifest(coreRoot);
  if (
    !manifest
    || manifest.manifestVersion !== SHARED_CORE_MANIFEST_VERSION
    || manifest.version !== app.getVersion()
    || manifest.platform !== process.platform
    || manifest.coreApiSignature !== CORE_API_SIGNATURE
    || !verifySignedRuntimeManifest(coreRoot)
  ) {
    return false;
  }
  if (manifest.executablePath && path.normalize(manifest.executablePath) !== path.normalize(executablePath)) {
    return false;
  }

  const nativeModulePath = getNativeModulePath(coreRoot);
  const pqcExecutable = getPqcRuntimeExecutable(coreRoot);
  const pqcLibrary = getPqcRuntimeLibrary(coreRoot);
  if (!nativeModulePath || !fs.existsSync(pqcExecutable) || !fs.existsSync(pqcLibrary)) {
    return false;
  }
  const backendExecutableHash = hashFileIfPresent(executablePath);
  return Boolean(backendExecutableHash)
    && manifest.backendExecutableHash === backendExecutableHash
    && (!expectedBackendHash || manifest.backendExecutableHash === expectedBackendHash)
    && manifest.nativeModuleHash === hashFileIfPresent(nativeModulePath)
    && manifest.pqcRuntimeHash === hashFileIfPresent(pqcExecutable)
    && manifest.pqcLibraryHash === hashFileIfPresent(pqcLibrary);
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

function verifyCoreExecutable(executablePath, coreRoot, expectedBackendHash = null) {
  if (!fs.existsSync(executablePath) || !verifySharedCoreManifest(coreRoot, executablePath, expectedBackendHash)) {
    return false;
  }
  return runCoreRuntimeVerification(executablePath);
}

function writeSharedCoreManifest(coreRoot, executablePath) {
  const backendExecutableForHash = getPackagedBackendExecutable(getSharedCoreBackendRoot(coreRoot));
  const nativeModulePath = getNativeModulePath(coreRoot);
  const pqcExecutable = getPqcRuntimeExecutable(coreRoot);
  const pqcLibrary = getPqcRuntimeLibrary(coreRoot);
  if (!backendExecutableForHash || !fs.existsSync(backendExecutableForHash)) {
    throw new Error('Bundled Avikal core is missing the backend executable');
  }
  if (!nativeModulePath) {
    throw new Error('Bundled Avikal core is missing the native crypto module');
  }
  if (!fs.existsSync(pqcExecutable)) {
    throw new Error('Bundled Avikal core is missing the PQC runtime');
  }
  if (!fs.existsSync(pqcLibrary)) {
    throw new Error('Bundled Avikal core is missing the PQC libcrypto runtime');
  }
  const manifest = {
    manifestVersion: SHARED_CORE_MANIFEST_VERSION,
    version: app.getVersion(),
    appVersion: app.getVersion(),
    platform: process.platform,
    arch: process.arch,
    executablePath,
    backendExecutableHash: hashFileIfPresent(backendExecutableForHash),
    coreApiSignature: CORE_API_SIGNATURE,
    nativeModuleHash: hashFileIfPresent(nativeModulePath),
    pqcRuntimeHash: hashFileIfPresent(pqcExecutable),
    pqcLibraryHash: hashFileIfPresent(pqcLibrary),
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
  const bundledRuntimeRoot = path.join(process.resourcesPath, 'backend-runtime');
  const bundledExecutable = getPackagedBackendExecutable(bundledBackendRoot);
  if (!bundledExecutable || !fs.existsSync(bundledExecutable) || !fs.existsSync(bundledRuntimeRoot)) {
    return null;
  }
  const bundledBackendHash = hashFileIfPresent(bundledExecutable);
  if (sharedExecutable && bundledBackendHash && verifyCoreExecutable(sharedExecutable, coreRoot, bundledBackendHash)) {
    return sharedBackendRoot;
  }

  if (!verifySignedRuntimeManifest(process.resourcesPath)) {
    throw new Error('Bundled Avikal core failed publisher manifest verification');
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
  if (!verifyCoreExecutable(finalExecutable, coreRoot, bundledBackendHash)) {
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

  if (packagedApp) {
    for (const key of [
      'AVIKAL_USE_SOURCE_BACKEND',
      'AVIKAL_DEV_SERVER_URL',
      'AVIKAL_OPENSSL_EXEC',
      'AVIKAL_PQC_RUNTIME_DIR',
      'AVIKAL_UPDATE_REPO_OWNER',
      'AVIKAL_UPDATE_REPO_NAME',
      'AVIKAL_UPDATE_RELEASES_API_URL',
      'AVIKAL_UPDATE_RELEASES_PAGE_URL',
      'PYTHONINSPECT',
      'PYTHONSTARTUP',
      'PYTHONUSERBASE',
      'OPENSSL_CONF',
      'OPENSSL_MODULES',
    ]) {
      delete pythonEnv[key];
    }
    pythonEnv.AVIKAL_PACKAGED_RUNTIME = '1';
    pythonEnv.AVIKAL_SECURITY_POLICY_FILE = path.join(process.resourcesPath, 'security-policy.json');
  }

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
    backgroundColor: '#050505',
    backgroundMaterial: 'none',
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
  applyWindowVisualMode(activeVisualMode);
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

function validateAssuranceReport(report) {
  if (!report || typeof report !== 'object' || Array.isArray(report) || report.format !== 'avikal-assurance-report') {
    throw new Error('Only canonical Avikal assurance reports can be exported');
  }
  const inspect = (value) => {
    if (Array.isArray(value)) {
      value.forEach(inspect);
      return;
    }
    if (!value || typeof value !== 'object') return;
    for (const [key, nested] of Object.entries(value)) {
      if (FORBIDDEN_REPORT_FIELDS.has(String(key).trim().toLowerCase())) {
        throw new Error('Assurance report contains a forbidden secret field');
      }
      inspect(nested);
    }
  };
  inspect(report);
  const json = JSON.stringify(report, null, 2);
  if (Buffer.byteLength(json, 'utf8') > MAX_ASSURANCE_REPORT_BYTES) {
    throw new Error('Assurance report is too large to export safely');
  }
  return json;
}

function escapeReportHtml(value) {
  return String(value ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function reportPdfHtml(report) {
  const sections = ['archive', 'compatibility', 'verification_ledger', 'assurance', 'protection', 'payload', 'chess', 'timings', 'operation', 'runtime_attestation', 'redaction_declaration', 'limitations'];
  const blocks = sections
    .filter((name) => report[name] && typeof report[name] === 'object')
    .map((name) => `<section><h2>${escapeReportHtml(name.replaceAll('_', ' '))}</h2><pre>${escapeReportHtml(JSON.stringify(report[name], null, 2))}</pre></section>`)
    .join('');
  return `<!doctype html><html><head><meta charset="utf-8"><style>
    @page{size:A4;margin:17mm}*{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;color:#172033;font-size:10px;line-height:1.5}
    header{border-bottom:2px solid #172033;padding-bottom:12px;margin-bottom:18px}h1{font-size:22px;margin:0 0 4px}header p{margin:0;color:#526078}
    section{break-inside:avoid;margin:0 0 16px}h2{text-transform:capitalize;font-size:13px;letter-spacing:.05em;margin:0 0 6px;color:#263b63}
    pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f6f9;border:1px solid #dce2eb;border-radius:8px;padding:10px;font:9px/1.5 Consolas,monospace}
    footer{margin-top:18px;border-top:1px solid #dce2eb;padding-top:8px;color:#667085}
  </style></head><body><header><h1>Avikal Assurance Report</h1><p>${escapeReportHtml(report.report_type)} · ${escapeReportHtml(report.generated_at_utc)}</p></header>${blocks}<footer>Report digest: ${escapeReportHtml(report.report_digest_sha256)}<br>PDF is a human-readable rendering. Verify the exported JSON with <strong>avikal verify-report</strong>.</footer></body></html>`;
}

registerTrustedHandler('report:export', async (_event, options = {}) => {
  const report = options.report;
  const format = options.format === 'pdf' ? 'pdf' : 'json';
  const json = validateAssuranceReport(report);
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: options.defaultPath || `avikal-assurance-report.${format}`,
    filters: [{ name: format === 'pdf' ? 'PDF Document' : 'Avikal Assurance Report', extensions: [format] }],
  });
  if (result.canceled || !result.filePath) return null;
  const destination = resolveAbsolutePath(result.filePath, 'Report destination');
  await fs.promises.mkdir(path.dirname(destination), { recursive: true });
  if (format === 'json') {
    await fs.promises.writeFile(destination, `${json}\n`, { encoding: 'utf8' });
  } else {
    const reportWindow = new BrowserWindow({ show: false, webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false } });
    try {
      await reportWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(reportPdfHtml(report))}`);
      const pdf = await reportWindow.webContents.printToPDF({ printBackground: true, pageSize: 'A4' });
      await fs.promises.writeFile(destination, pdf);
    } finally {
      reportWindow.destroy();
    }
  }
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
  let createdDirectoryCount = 0;

  for (const entry of fileEntries) {
    const source = resolveAbsolutePath(entry?.sourcePath, 'Source path');
    assertPathCapability(source, 'Directory export');
    const relativePath = normalizeRelativePath(entry?.relativePath);
    const destination = path.join(destinationRoot, relativePath);

    if (entry?.type === 'directory') {
      await fs.promises.mkdir(destination, { recursive: true });
      createdDirectoryCount += 1;
      continue;
    }
    await fs.promises.mkdir(path.dirname(destination), { recursive: true });
    await fs.promises.copyFile(source, destination, fs.constants.COPYFILE_EXCL);
    registerSaveDestination(destination);
    copiedCount += 1;
  }

  return {
    destinationPath: destinationRoot,
    copiedCount,
    createdDirectoryCount,
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

registerTrustedHandler('visualMode:get', async () => ({
  mode: activeVisualMode,
  engine: activeVisualEngine,
  automaticMode: detectDefaultVisualMode(),
}));

registerTrustedHandler('visualMode:set', async (_event, mode) => ({
  mode: applyWindowVisualMode(mode),
  engine: activeVisualEngine,
}));

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

registerTrustedHandler('diagnostics:recordRenderer', async (_event, event = {}) => {
  writeDiagnosticEvent({
    event: 'renderer_event',
    status: event.status || 'logged',
    level: event.level || 'info',
    channel: 'renderer',
    renderer: sanitizeDiagnosticValue(event),
  });
  return true;
});

registerTrustedHandler('diagnostics:exportSupportLog', async () => {
  const backendDiagnostics = coreRpcClient
    ? await coreRpcClient.request('security.diagnosticsExport', {}, 30000).catch((error) => ({
        success: false,
        markdown: `# Backend Diagnostics\n\nBackend diagnostics export failed.\n\n\`\`\`json\n${JSON.stringify(serializeDiagnosticError(error), null, 2)}\n\`\`\`\n`,
      }))
    : { success: false, markdown: '# Backend Diagnostics\n\nAvikal core is not ready.\n' };
  const markdown = [
    '# RookDuel Avikal Support Diagnostics',
    '',
    `- Generated at: ${new Date().toISOString()}`,
    `- App version: ${app.getVersion()}`,
    `- Packaged: ${app.isPackaged ? 'yes' : 'no'}`,
    '',
    backendDiagnostics.markdown || '# Backend Diagnostics\n\nNo backend diagnostics were returned.\n',
    buildElectronDiagnosticsMarkdown(),
  ].join('\n');
  if (Buffer.byteLength(markdown, 'utf8') > MAX_SAVED_TEXT_BYTES) {
    throw new Error('Diagnostic export is too large to save safely');
  }
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: 'avikal-support-diagnostics.md',
    filters: [{ name: 'Markdown', extensions: ['md'] }],
  });
  if (result.canceled || !result.filePath) return null;
  const destination = resolveAbsolutePath(result.filePath, 'Diagnostic export destination');
  await fs.promises.mkdir(path.dirname(destination), { recursive: true });
  await fs.promises.writeFile(destination, markdown, { encoding: 'utf8' });
  registerSaveDestination(destination);
  return destination;
});

registerTrustedHandler('core:invoke', async (_event, method, params = {}, timeoutMs = 300000) => {
  if (typeof method !== 'string' || method.length === 0 || method.length > 128) {
    throw new Error('Invalid Avikal core method');
  }
  if (!coreRpcClient) {
    throw new Error('Avikal core is not ready');
  }
  const safeTimeoutMs = normalizeCoreTimeout(method, timeoutMs);
  const forwardedParams = params && typeof params === 'object' ? { ...params } : {};
  const correlationId = `AVK-${Date.now().toString(36)}-${crypto.randomBytes(4).toString('hex')}`;
  const startedAt = Date.now();
  delete forwardedParams.creator_signing_identity;
  delete forwardedParams.creator_trust_policy;
  delete forwardedParams.__diagnostic_context;
  forwardedParams.__diagnostic_context = {
    correlation_id: correlationId,
    method,
    packaged: app.isPackaged,
  };
  let signingIdentity = null;
  try {
    if ((method === 'archive.encrypt' || method === 'archive.rekey') && typeof forwardedParams.creator_identity_id === 'string') {
      signingIdentity = await loadCreatorSigningIdentity(forwardedParams.creator_identity_id);
      forwardedParams.creator_signing_identity = signingIdentity;
    }
    if (method === 'archive.openSession' || method === 'archive.decrypt') {
      const identityStore = await readCreatorIdentityStore();
      forwardedParams.creator_trust_policy = Object.fromEntries(
        identityStore.trusted.map((item) => [item.identity_id, item.status])
      );
    }
    const result = await coreRpcClient.request(method, forwardedParams, safeTimeoutMs);
    writeDiagnosticEvent({
      event: 'core_invoke',
      status: 'success',
      level: 'info',
      correlation_id: correlationId,
      method,
      duration_ms: Date.now() - startedAt,
      timeout_ms: safeTimeoutMs,
      request: forwardedParams,
      response: summarizeCoreResult(result),
    });
    registerCoreResultCapabilities(result);
    return result;
  } catch (error) {
    writeDiagnosticEvent({
      event: 'core_invoke',
      status: 'failed',
      level: Number(error?.code) >= 500 || Number(error?.code) < 0 ? 'error' : 'warning',
      correlation_id: correlationId,
      method,
      duration_ms: Date.now() - startedAt,
      timeout_ms: safeTimeoutMs,
      request: forwardedParams,
      error: serializeDiagnosticError(error),
      backend_state: {
        last_error_line: backendStartupState.lastErrorLine,
        last_output_line: backendStartupState.lastOutputLine,
      },
    });
    if (error && typeof error === 'object') {
      error.data = {
        ...(error.data && typeof error.data === 'object' ? error.data : {}),
        correlation_id: correlationId,
      };
    }
    throw error;
  } finally {
    if (signingIdentity?.private_bundle?.keys) {
      for (const key of Object.keys(signingIdentity.private_bundle.keys)) {
        signingIdentity.private_bundle.keys[key] = '';
      }
    }
    delete forwardedParams.creator_signing_identity;
    delete forwardedParams.creator_trust_policy;
    delete forwardedParams.__diagnostic_context;
  }
});

registerTrustedHandler('identity:create', async (_event, label) => {
  if (!safeStorage.isEncryptionAvailable()) throw new Error('OS secure storage is unavailable');
  if (!coreRpcClient) throw new Error('Avikal core is not ready');
  const normalizedLabel = String(label || '').trim();
  if (!normalizedLabel || Buffer.byteLength(normalizedLabel, 'utf8') > 128) throw new Error('Identity label is invalid');
  const generated = await coreRpcClient.request('identity.generate', { label: normalizedLabel }, 0);
  const encryptedPrivate = safeStorage.encryptString(JSON.stringify(generated.private_bundle)).toString('base64');
  const store = await readCreatorIdentityStore();
  if (store.identities.some((item) => item.identity_id === generated.identity_id)) {
    throw new Error('Signing key already exists');
  }
  const record = {
    identity_id: generated.identity_id,
    label: normalizedLabel,
    created_at: new Date().toISOString(),
    public_bundle: generated.public_bundle,
    encrypted_private_bundle: encryptedPrivate,
  };
  store.identities.push(record);
  await writeCreatorIdentityStore(store);
  return publicIdentityView(record);
});

registerTrustedHandler('identity:list', async () => {
  const store = await readCreatorIdentityStore();
  return {
    identities: store.identities.map(publicIdentityView),
    trusted: store.trusted.map((item) => ({ ...item })),
    secureStorageAvailable: safeStorage.isEncryptionAvailable(),
  };
});

registerTrustedHandler('identity:delete', async (_event, identityId) => {
  const store = await readCreatorIdentityStore();
  const before = store.identities.length;
  store.identities = store.identities.filter((item) => item.identity_id !== identityId);
  if (store.identities.length === before) return false;
  await writeCreatorIdentityStore(store);
  return true;
});

registerTrustedHandler('identity:deleteTrusted', async (_event, identityId) => {
  const store = await readCreatorIdentityStore();
  const before = store.trusted.length;
  store.trusted = store.trusted.filter((item) => item.identity_id !== identityId);
  if (store.trusted.length === before) return false;
  await writeCreatorIdentityStore(store);
  return true;
});

registerTrustedHandler('identity:exportPublic', async (_event, identityId) => {
  const store = await readCreatorIdentityStore();
  const record = store.identities.find((item) => item.identity_id === identityId);
  if (!record) throw new Error('Signing key was not found');
  const result = await dialog.showSaveDialog(mainWindow, {
    defaultPath: `${record.label.replace(/[^a-z0-9_-]+/gi, '-') || 'avikal-identity'}.avikal-id.json`,
    filters: [{ name: 'Avikal Public Identity', extensions: ['json'] }],
  });
  if (result.canceled || !result.filePath) return null;
  await fs.promises.writeFile(result.filePath, JSON.stringify(publicIdentityView(record), null, 2), { encoding: 'utf8', flag: 'w' });
  return result.filePath;
});

registerTrustedHandler('identity:importTrusted', async () => {
  if (!coreRpcClient) throw new Error('Avikal core is not ready');
  const result = await dialog.showOpenDialog(mainWindow, { properties: ['openFile'], filters: [{ name: 'Avikal Public Identity', extensions: ['json'] }] });
  if (result.canceled || !result.filePaths[0]) return null;
  const raw = await fs.promises.readFile(result.filePaths[0], 'utf8');
  if (Buffer.byteLength(raw, 'utf8') > 128 * 1024) throw new Error('Public identity file is too large');
  const document = JSON.parse(raw);
  const validated = await coreRpcClient.request('identity.validate', { identity: { public_bundle: document.public_bundle }, require_private: false }, 30000);
  const store = await readCreatorIdentityStore();
  const trustedRecord = {
    identity_id: validated.identity_id,
    label: String(document.label || 'Trusted author').slice(0, 128),
    public_bundle: validated.public_bundle,
    status: 'trusted',
    trusted_at: new Date().toISOString(),
  };
  store.trusted = store.trusted.filter((item) => item.identity_id !== trustedRecord.identity_id);
  store.trusted.push(trustedRecord);
  await writeCreatorIdentityStore(store);
  return trustedRecord;
});

registerTrustedHandler('identity:setTrust', async (_event, identityId, status) => {
  if (!['trusted', 'revoked'].includes(status)) throw new Error('Trust status is invalid');
  const store = await readCreatorIdentityStore();
  const record = store.trusted.find((item) => item.identity_id === identityId);
  if (!record) throw new Error('Trusted author card was not found');
  record.status = status;
  record.updated_at = new Date().toISOString();
  await writeCreatorIdentityStore(store);
  return { ...record };
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
app.whenReady().then(async () => {
  if (verifyInstallationMode) {
    try {
      const bundledBackendRoot = getBackendRoot();
      const backendRoot = ensureSharedCoreInstalled(bundledBackendRoot) || bundledBackendRoot;
      const executable = getPackagedBackendExecutable(backendRoot);
      const bundledExecutable = getPackagedBackendExecutable(bundledBackendRoot);
      const bundledBackendHash = bundledExecutable ? hashFileIfPresent(bundledExecutable) : null;
      if (!executable || !verifyCoreExecutable(executable, path.dirname(backendRoot), bundledBackendHash)) {
        throw new Error('Installed Avikal core verification failed');
      }
      console.log('Avikal installation verification passed');
      app.exit(0);
    } catch (error) {
      console.error(error instanceof Error ? error.message : String(error));
      app.exit(1);
    }
    return;
  }
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
