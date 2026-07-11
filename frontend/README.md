# RookDuel Avikal Frontend

This folder contains the React + TypeScript renderer used by the Electron desktop app.

## Commands

```bash
npm run dev
npm run build
npm run build:check
npm run lint
```

## Environment

Copy `.env.example` to `.env.local` if you want to override the public Aavrit request link shown in the app:

```bash
VITE_CUSTOM_AAVRIT_REQUEST_URL=https://avikal.rookduel.tech/aavrit
```

The renderer talks to the local Avikal core through the Electron preload bridge. In desktop mode Electron spawns the Python/Rust core as a child process and uses framed JSON-RPC over stdin/stdout; no loopback port or backend token is used by the desktop transport.
