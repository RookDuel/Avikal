const path = require("path");
const { stampExecutableMetadata } = require("./windowsMetadata");

module.exports = async function artifactBuildCompleted(context) {
  if (process.platform !== "win32") {
    return;
  }

  if (!context || !context.file || path.extname(context.file).toLowerCase() !== ".exe") {
    return;
  }

  // Do not mutate generated installer executables. NSIS stores the packaged
  // application payload as an executable overlay, and post-build resource edits
  // can strip that overlay, leaving only a tiny web/bootstrap stub. The app
  // executable inside win-unpacked is already stamped in afterPack.js.
  const normalizedFile = path.normalize(context.file).toLowerCase();
  if (!normalizedFile.includes(`${path.sep}win-unpacked${path.sep}`)) {
    return;
  }

  await stampExecutableMetadata(context.file, context.packager.appInfo.version);
};
