const { spawnSync } = require('child_process');

const channel = String(process.argv[2] || '').toLowerCase();
const command = String(process.argv[3] || '').toLowerCase();

if (!['beta', 'production'].includes(channel) || !['dev', 'build'].includes(command)) {
  console.error('Usage: node scripts/run_frontend_with_channel.js <beta|production> <dev|build>');
  process.exit(2);
}

const commandParts = process.platform === 'win32'
  ? ['cmd.exe', ['/d', '/s', '/c', `npm --prefix frontend run ${command}`]]
  : ['npm', ['--prefix', 'frontend', 'run', command]];

const result = spawnSync(commandParts[0], commandParts[1], {
  stdio: 'inherit',
  env: {
    ...process.env,
    VITE_AVIKAL_RELEASE_CHANNEL: channel,
  },
});

if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}

process.exit(result.status ?? 1);
