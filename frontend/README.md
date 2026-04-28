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
VITE_CUSTOM_AAVRIT_REQUEST_URL=https://avikal.rookduel.tech/custom-aavrit
```

The renderer talks to the local backend at `http://127.0.0.1:5000` through the Electron preload bridge. That URL is intentionally not configurable from browser env vars.
