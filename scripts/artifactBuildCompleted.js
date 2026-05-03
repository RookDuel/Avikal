const path = require("path");

module.exports = async function artifactBuildCompleted(context) {
  if (!context || !context.file) {
    return;
  }

  const fileName = path.basename(context.file).toLowerCase();

  // The unpacked app executable is already stamped safely in afterPack.
  // Re-stamping final NSIS installer artifacts here can corrupt the bundled payload
  // and produce the tiny non-working setup stub. Leave release .exe artifacts untouched.
  if (fileName !== "rookduel avikal.exe") {
    return;
  }
};
