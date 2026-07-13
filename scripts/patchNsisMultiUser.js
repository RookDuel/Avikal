const fs = require('fs');
const path = require('path');

const PATCH_MARKER = '# Avikal: avoid electron-builder System.dll access violation (issues #7921 and #8536)';
const STORE_CALLS = [
  '      System::Store S',
  '      System::Store L',
];

function resolveMultiUserTemplate() {
  const packageRoot = path.dirname(require.resolve('app-builder-lib/package.json'));
  return path.join(packageRoot, 'templates', 'nsis', 'multiUser.nsh');
}

function patchMultiUserTemplate(templatePath = resolveMultiUserTemplate()) {
  const source = fs.readFileSync(templatePath, 'utf8');
  if (source.includes(PATCH_MARKER)) {
    return templatePath;
  }

  for (const call of STORE_CALLS) {
    const occurrences = source.split(call).length - 1;
    if (occurrences !== 1) {
      throw new Error(`Expected exactly one '${call.trim()}' call in ${templatePath}, found ${occurrences}`);
    }
  }

  const patched = source
    .replace(STORE_CALLS[0], `      ${PATCH_MARKER}\n      # ${STORE_CALLS[0].trim()} intentionally disabled`)
    .replace(STORE_CALLS[1], `      # ${STORE_CALLS[1].trim()} intentionally disabled`);
  fs.writeFileSync(templatePath, patched, 'utf8');
  return templatePath;
}

module.exports = async function patchNsisMultiUser() {
  const templatePath = patchMultiUserTemplate();
  console.log(`[beforePack] Patched NSIS per-user installer template: ${templatePath}`);
};

module.exports.patchMultiUserTemplate = patchMultiUserTemplate;
