/** Sign canonical release metadata with Avikal's offline Ed25519 release key. */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const projectRoot = path.resolve(__dirname, '..');
const metadataPath = path.resolve(process.argv[2] || path.join(projectRoot, 'dist', 'avikal-release-metadata.json'));
const signaturePath = path.resolve(process.argv[3] || `${metadataPath}.sig`);

function loadPrivateKey() {
  const encoded = String(process.env.AVIKAL_RELEASE_SIGNING_PRIVATE_KEY_B64 || '').trim();
  if (encoded) {
    return Buffer.from(encoded, 'base64').toString('utf8');
  }
  const explicitPath = String(process.env.AVIKAL_RELEASE_SIGNING_PRIVATE_KEY_FILE || '').trim();
  const defaultPath = path.join(os.homedir(), 'Documents', 'Avikal Release Keys', 'avikal-release-ed25519-private.pem');
  return fs.readFileSync(path.resolve(explicitPath || defaultPath), 'utf8');
}

const metadata = fs.readFileSync(metadataPath);
if (metadata.length === 0 || metadata.length > 1024 * 1024) {
  throw new Error('Release metadata size is invalid');
}
const signature = crypto.sign(null, metadata, loadPrivateKey());
fs.writeFileSync(signaturePath, `${signature.toString('base64')}\n`, { encoding: 'ascii', flag: 'w' });
console.log(`Signed ${path.basename(metadataPath)} with Ed25519`);
