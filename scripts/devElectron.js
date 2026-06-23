/**
 * Launch Electron for Avikal development while clearing hostile global env vars.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Atharva Sen Barai.
 */

const { spawn } = require('child_process');
const path = require('path');

const mode = process.argv[2] || 'source';
const rootDir = path.resolve(__dirname, '..');
const electronBinary = require('electron');
const env = { ...process.env };

delete env.ELECTRON_RUN_AS_NODE;

if (mode === 'source') {
  env.AVIKAL_USE_SOURCE_BACKEND = '1';
  env.AVIKAL_DEV_SERVER_URL = 'http://localhost:5173';
  launch(electronBinary, ['.'], env);
} else if (mode === 'packaged') {
  env.AVIKAL_DEV_SERVER_URL = 'http://localhost:5173';
  launch(path.join(rootDir, 'dist', 'win-unpacked', 'RookDuel Avikal.exe'), [], env);
} else {
  console.error(`Unknown dev Electron mode: ${mode}`);
  process.exit(1);
}

function launch(command, args, childEnv) {
  const child = spawn(command, args, {
    cwd: rootDir,
    env: childEnv,
    stdio: 'inherit',
    windowsHide: false,
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code ?? 0);
  });

  child.on('error', (error) => {
    console.error(`Failed to launch Electron dev process: ${error.message}`);
    process.exit(1);
  });
}
