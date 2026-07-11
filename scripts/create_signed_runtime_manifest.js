/** Build and sign the immutable Avikal core runtime manifest. */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const stagingRoot = path.join(projectRoot, '.app-build');
const outputPath = path.join(stagingRoot, 'backend-runtime', 'avikal-runtime-integrity.json');
const signaturePath = `${outputPath}.sig`;

function loadPrivateKey() {
  const encoded = String(process.env.AVIKAL_RELEASE_SIGNING_PRIVATE_KEY_B64 || '').trim();
  if (encoded) return Buffer.from(encoded, 'base64').toString('utf8');
  const explicitPath = String(process.env.AVIKAL_RELEASE_SIGNING_PRIVATE_KEY_FILE || '').trim();
  const defaultPath = path.join(os.homedir(), 'Documents', 'Avikal Release Keys', 'avikal-release-ed25519-private.pem');
  return fs.readFileSync(path.resolve(explicitPath || defaultPath), 'utf8');
}

function findExisting(candidates, description) {
  const found = candidates.find((candidate) => fs.existsSync(path.join(stagingRoot, candidate)));
  if (!found) throw new Error(`Missing ${description} in staged runtime`);
  return found.replaceAll(path.sep, '/');
}

function hash(relativePath) {
  const target = path.join(stagingRoot, relativePath);
  const descriptor = fs.openSync(target, 'r');
  const digest = crypto.createHash('sha256');
  const buffer = Buffer.allocUnsafe(4 * 1024 * 1024);
  let size = 0;
  try {
    while (true) {
      const count = fs.readSync(descriptor, buffer, 0, buffer.length, null);
      if (count === 0) break;
      digest.update(buffer.subarray(0, count));
      size += count;
    }
  } finally {
    fs.closeSync(descriptor);
  }
  return {
    path: relativePath,
    size,
    sha256: digest.digest('hex'),
  };
}

const packageJson = JSON.parse(fs.readFileSync(path.join(projectRoot, 'package.json'), 'utf8'));
const criticalFiles = [
  findExisting(['backend/avikal-backend.exe', 'backend/avikal-backend'], 'backend executable'),
  findExisting([
    'backend/_internal/avikal_backend/_native.pyd',
    'backend/avikal_backend/_native.pyd',
    'backend/_internal/avikal_backend/_native.so',
  ], 'native crypto module'),
  findExisting([
    'backend-runtime/pqc/bin/openssl.exe',
    'backend-runtime/pqc/bin/openssl',
  ], 'OpenSSL executable'),
  findExisting([
    'backend-runtime/pqc/bin/libcrypto-3-x64.dll',
    'backend-runtime/pqc/lib/libcrypto.so.3',
    'backend-runtime/pqc/lib64/libcrypto.so.3',
    'backend-runtime/pqc/lib/libcrypto.3.dylib',
  ], 'OpenSSL crypto library'),
];

const manifest = {
  format: 'avikal-runtime-integrity',
  version: 1,
  product_version: packageJson.version,
  signature_algorithm: 'Ed25519',
  files: criticalFiles.map(hash),
};
const payload = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
const signature = crypto.sign(null, payload, loadPrivateKey());
fs.writeFileSync(outputPath, payload, { flag: 'w' });
fs.writeFileSync(signaturePath, `${signature.toString('base64')}\n`, { encoding: 'ascii', flag: 'w' });
console.log(`Signed ${manifest.files.length} critical runtime files with Ed25519`);
