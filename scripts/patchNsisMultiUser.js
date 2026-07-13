const fs = require('fs');
const path = require('path');

const PATCH_MARKER = '# Avikal: backport safe per-user folder lookup from electron-builder #9564';
const BLOCK_START = '      StrCpy $0 "$LocalAppData\\Programs"';
const BLOCK_END = '      StrCpy $INSTDIR "$0\\${APP_FILENAME}"';

function resolveMultiUserTemplate() {
  const packageRoot = path.dirname(require.resolve('app-builder-lib/package.json'));
  return path.join(packageRoot, 'templates', 'nsis', 'multiUser.nsh');
}

function patchMultiUserTemplate(templatePath = resolveMultiUserTemplate()) {
  const source = fs.readFileSync(templatePath, 'utf8');
  if (source.includes(PATCH_MARKER)) {
    return templatePath;
  }

  const startOccurrences = source.split(BLOCK_START).length - 1;
  const endOccurrences = source.split(BLOCK_END).length - 1;
  if (startOccurrences !== 1 || endOccurrences !== 1) {
    throw new Error(
      `Expected one NSIS per-user folder block in ${templatePath}; found ${startOccurrences} starts and ${endOccurrences} ends`,
    );
  }

  const startIndex = source.indexOf(BLOCK_START);
  const endIndex = source.indexOf(BLOCK_END, startIndex) + BLOCK_END.length;
  const vulnerableBlock = source.slice(startIndex, endIndex);
  const isUpstreamVulnerable = vulnerableBlock.includes('System::Store S')
    && vulnerableBlock.includes('System::Store L');
  const isPreviousAvikalPatch = vulnerableBlock.includes('System::Store S intentionally disabled')
    && vulnerableBlock.includes('System::Store L intentionally disabled');
  if (!isUpstreamVulnerable && !isPreviousAvikalPatch) {
    throw new Error(`NSIS per-user folder block in ${templatePath} does not match a supported vulnerable template`);
  }

  const eol = source.includes('\r\n') ? '\r\n' : '\n';
  const safeBlock = [
    BLOCK_START,
    `      ${PATCH_MARKER}`,
    '      Push $1',
    '      Push $2',
    '      # UserProgramFiles can be configured to a non-default per-user location.',
    '      StrCpy $2 0',
    '      System::Call \'SHELL32::SHGetKnownFolderPath(g "${FOLDERID_UserProgramFiles}", i ${KF_FLAG_CREATE}, p 0, *p .r2)i.r1\'',
    '      ${If} $1 == 0',
    '        System::Call \'KERNEL32::lstrcpynW(w .r0, p r2, i ${NSIS_MAX_STRLEN})p\'',
    '      ${endif}',
    '      # SHGetKnownFolderPath may allocate memory even when it reports failure.',
    '      ${If} $2 != 0',
    '        System::Call \'OLE32::CoTaskMemFree(p r2)\'',
    '      ${endif}',
    '      Pop $2',
    '      Pop $1',
    BLOCK_END,
  ].join(eol);
  const patched = `${source.slice(0, startIndex)}${safeBlock}${source.slice(endIndex)}`;
  fs.writeFileSync(templatePath, patched, 'utf8');
  return templatePath;
}

module.exports = async function patchNsisMultiUser() {
  const templatePath = patchMultiUserTemplate();
  console.log(`[beforePack] Patched NSIS per-user installer template: ${templatePath}`);
};

module.exports.patchMultiUserTemplate = patchMultiUserTemplate;
