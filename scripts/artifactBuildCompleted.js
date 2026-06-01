const path = require("path");
const { stampExecutableMetadata } = require("./windowsMetadata");

module.exports = async function artifactBuildCompleted(context) {
  if (process.platform !== "win32") {
    return;
  }

  if (!context || !context.file || path.extname(context.file).toLowerCase() !== ".exe") {
    return;
  }

  await stampExecutableMetadata(context.file, context.packager.appInfo.version);
};
