const path = require("path");
const { spawn } = require("child_process");

const RCEDIT_PATH = path.join(
  __dirname,
  "..",
  "node_modules",
  "electron-winstaller",
  "vendor",
  "rcedit.exe",
);

const BRANDING = Object.freeze({
  companyName: "RookDuel",
  productName: "RookDuel Avikal",
  fileDescription: "RookDuel Avikal - Quantum-Resistant File Encryption",
  homepage: "https://avikal.rookduel.tech",
  copyright: "Copyright (c) 2026 RookDuel",
  originalFilename: "RookDuel Avikal.exe",
  internalName: "RookDuel Avikal",
});

function runRcedit(targetPath, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(RCEDIT_PATH, [targetPath, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });

    let stderr = "";

    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });

    child.on("error", reject);
    child.on("close", (code) => {
      if (code === 0) {
        resolve();
        return;
      }

      reject(
        new Error(
          `rcedit failed for ${targetPath} with exit code ${code}${
            stderr ? `: ${stderr.trim()}` : ""
          }`,
        ),
      );
    });
  });
}

async function stampExecutableMetadata(targetPath, version) {
  const args = [
    "--set-version-string",
    "CompanyName",
    BRANDING.companyName,
    "--set-version-string",
    "ProductName",
    BRANDING.productName,
    "--set-version-string",
    "FileDescription",
    BRANDING.fileDescription,
    "--set-version-string",
    "LegalCopyright",
    BRANDING.copyright,
    "--set-version-string",
    "OriginalFilename",
    BRANDING.originalFilename,
    "--set-version-string",
    "InternalName",
    BRANDING.internalName,
    "--set-version-string",
    "Website",
    BRANDING.homepage,
  ];

  if (version) {
    args.push("--set-file-version", version, "--set-product-version", version);
  }

  await runRcedit(targetPath, args);
}

module.exports = {
  BRANDING,
  stampExecutableMetadata,
};
