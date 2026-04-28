# Avikal Architecture

This document describes the current architecture of Avikal as it exists in this repository. It focuses on actual runtime behavior and code boundaries rather than intended future designs.

## 1. System overview

Avikal is a layered archive system with two user-facing products built on one shared Python core:

- a desktop application
- a standalone CLI package

At runtime the system looks like this:

```text
Desktop app
+-- Electron main process
+-- Electron preload bridge
+-- React renderer
\-- local Python FastAPI backend
    \-- shared archive core

CLI package
\-- shared archive core
```

The important design fact is that the desktop app and the CLI do not implement separate archive engines. They both reuse the same `avikal_backend.archive` modules.

## 2. Major components

### 2.1 Electron

The Electron layer lives in `electron/`.

It has two responsibilities:

- start and supervise the local Python backend
- expose desktop capabilities to the renderer through the preload bridge

Main process responsibilities include:

- waiting for the frontend dev server in development
- launching `backend/api_server.py`
- polling the backend health endpoint
- creating the browser window
- handling native dialogs and file operations
- bridging safe storage and shell actions

### 2.2 Preload bridge

The preload bridge exposes a controlled `window.electron` surface to the React app.

It provides:

- open/save file dialogs
- folder selection
- directory scanning
- file read/write/copy helpers
- shell open helpers
- window controls
- platform safe-storage helpers

The renderer uses this bridge for desktop-native behavior. It does not use the preload bridge for encryption or decryption.

### 2.3 React frontend

The frontend lives in `frontend/src`.

It is responsible for:

- archive creation forms
- decryption and preview workflow
- TimeCapsule configuration
- Aavrit connection and session UX
- progress and result presentation

The renderer communicates with:

- the Python backend over local HTTP
- the Electron preload bridge for local desktop operations

### 2.4 Python FastAPI backend

The backend lives in `backend/src/avikal_backend/api`.

Its responsibilities are:

- receive desktop app requests over HTTP
- normalize and validate request data
- coordinate Aavrit and drand flows
- manage decryption preview sessions
- call the shared archive core

The backend is launched by Electron through `backend/api_server.py`, which forwards into `avikal_backend.api.server`.

### 2.5 Shared archive core

The shared archive core lives in `backend/src/avikal_backend/archive`.

This is the single source of truth for:

- archive container format
- metadata packing and unpacking
- encryption and decryption
- password and keyphrase handling
- PQC keyfile handling
- single-file and multi-file archive pipelines
- trusted time handling for time-locked creation

Core subareas:

```text
archive/
+-- format/    # container, header, manifest, metadata serialization
+-- pipeline/  # encode/decode workflows
+-- security/  # crypto, PQC keyfile, time-lock helpers
\-- ...        # path safety, runtime logging, chess metadata
```

### 2.6 CLI

The CLI lives in `backend/src/avikal_backend/cli`.

It is a direct interface to the shared archive core. It does not depend on FastAPI and does not call the desktop HTTP routes for normal archive operations.

Entry points:

- `avikal`
- `python -m avikal_backend`
- `python -m avikal_backend.cli`

For packaging purposes, the published PyPI distribution includes the CLI and the shared archive
modules, but excludes `avikal_backend.api`. The desktop app continues to use the full repository
source tree and launches the API layer locally through `backend/api_server.py`.

## 3. Execution model

### 3.1 Desktop launch sequence

Desktop startup is:

```text
User starts Avikal
-> Electron main process starts
-> Electron starts backend/api_server.py
-> api_server.py loads avikal_backend.api.server
-> FastAPI starts on 127.0.0.1:5000
-> Electron waits for /health
-> BrowserWindow opens
-> React UI loads
-> React sends requests to the local backend
```

In development:

- the React app is served by Vite on `http://localhost:5173`
- Electron loads that URL

In packaged mode:

- Electron loads `frontend/dist/index.html`
- the backend is still a local Python process

### 3.2 CLI execution

CLI execution is simpler:

```text
User runs avikal ...
-> argparse resolves the command
-> CLI handler imports archive pipeline modules
-> shared archive core performs the work
-> CLI prints formatted results
```

No Electron process is involved. No FastAPI server is required.

## 3.3 Python package boundary

The repository contains both desktop-backend code and CLI code, but the publishable Python package
is intentionally narrower than the repo itself.

PyPI package contents:

```text
avikal_backend.archive.*
avikal_backend.cli.*
avikal_backend.mnemonic.*
avikal_backend.services.*
avikal_backend.audit.*
avikal_backend.chess.*
avikal_backend.chess_codec.*
avikal_backend.wordlists.*
```

Excluded from the published package:

```text
avikal_backend.api.*
backend/api_server.py
```

This keeps the CLI distribution focused while preserving a single shared archive engine.

## 4. Why the desktop app uses a local HTTP backend

The frontend is written in TypeScript and runs inside the Electron renderer. The archive engine is written in Python.

Instead of binding React directly to Python internals through a custom native bridge, Avikal uses a local FastAPI service as the desktop boundary.

That design gives the project:

- one long-lived Python process
- a stable request/response contract for the GUI
- clean separation between renderer code and archive code
- reuse of the same Python backend for desktop flows
- a path to test GUI-facing backend behavior independently of Electron

The cost is that the desktop app has an extra local process and a local HTTP startup dependency. That tradeoff is intentional in the current architecture.

## 5. Shared core and archive format

The core archive engine is shared by the API and the CLI:

```text
CLI -> avikal_backend.archive.*
API -> avikal_backend.archive.*
```

This matters because it keeps the following consistent across both surfaces:

- `.avk` container rules
- password and keyphrase validation
- PQC `.avkkey` behavior
- archive metadata structure
- time-lock key derivation rules

### 5.1 Archive structure

The archive container is structured around three files:

- `header.bin`
- `keychain.pgn`
- `payload.enc`

At a high level:

- `header.bin` carries format-level control values
- `keychain.pgn` stores structured archive metadata encoded through the chess PGN layer
- `payload.enc` stores the archive payload stream

Protected archive modes bind metadata and payload validation to the archive structure through authenticated handling in the shared core.

## 6. Desktop encrypt flow

The desktop encrypt flow is:

```text
User selects files/folders and options in React
-> React sends POST /api/encrypt
-> FastAPI validates the request
-> backend chooses regular, drand, or Aavrit path
-> backend calls shared archive pipeline
-> shared archive core writes the .avk archive
-> result is returned to React
```

Important request decisions made by the backend:

- regular archive vs TimeCapsule
- single-file vs multi-file pipeline
- password or keyphrase use
- optional PQC `.avkkey` generation
- Aavrit or drand provider path for TimeCapsule

Unlock datetimes are normalized to UTC in the backend and validated against trusted time services instead of being stored as a local-time-only rule.

## 7. Desktop decrypt flow

The desktop decrypt flow is:

```text
User selects an archive
-> React may inspect it first through /api/archive/inspect
-> React sends POST /api/decrypt
-> backend detects archive/provider mode
-> backend unlocks through regular, drand, or Aavrit path
-> backend decrypts into a preview-session directory
-> React shows previewable files
-> user can open, inspect, or extract results
-> preview session can be cleaned up explicitly
```

The preview-session layer is a desktop-specific behavior. It is one of the reasons the API layer is not a thin passthrough over the core.

## 8. CLI architecture

The CLI is implemented with `argparse` and command handlers under `backend/src/avikal_backend/cli/commands`.

Current top-level commands:

- `encode` / `enc`
- `decode` / `dec` / `extract`
- `inspect` / `info`
- `contents` / `ls` / `list`
- `validate` / `check`
- `doctor` / `diag`

The CLI supports direct local archive operations including:

- password-protected archives
- keyphrase-protected archives
- PQC-assisted archives
- local time-locked archive creation
- archive inspection and validation

Current Aavrit support in the CLI is intentionally limited. The CLI can probe Aavrit connectivity through `doctor`, but the desktop app is the primary surface for Aavrit session-driven creation and reveal workflows.

## 9. Packaging and distribution

### 9.1 Desktop app packaging

The repository root `package.json` builds the desktop app.

The packaging process:

```text
npm run build:frontend
-> build React app into frontend/dist
-> prepare embedded Python runtime into .app-build/backend-runtime
-> electron-builder packages Electron + frontend + backend resources
```

What gets bundled for the desktop app:

- Electron code
- built frontend assets
- backend source resources
- prepared Python runtime and selected Python dependencies

### 9.2 CLI packaging

The CLI is packaged separately as a Python project from `backend/pyproject.toml`.

It exposes:

```text
avikal = avikal_backend.cli.main:main
```

That means a developer can install the CLI without the desktop app from a package index release or directly from source:

```powershell
pip install avikal
```

or directly from a source checkout:

```powershell
pip install .\backend
```

## 10. Aavrit: separate external system

This section describes the Aavrit integration contract used by Avikal. Aavrit itself is not part of this repository.

### 10.1 What Aavrit is

Aavrit is an external time-release authority designed around a commit/reveal model.

Conceptually, Aavrit does four things:

- exposes whether the server is in public or private mode
- publishes a signing public key
- signs a commit for a requested future unlock time
- later signs a reveal that allows the client to verify release

Avikal is one client of that system. Aavrit is intended to be released separately as its own project and is currently treated as an independent service under development and testing.

The intended role of Aavrit is:

- self-hostable
- developer-friendly
- usable by clients other than Avikal

### 10.2 Aavrit is not in this repository

This repository contains:

- the Avikal Aavrit client integration
- Aavrit request/response verification logic
- desktop-side session handling for private Aavrit mode

This repository does not contain:

- the Aavrit server implementation
- Aavrit deployment code
- Aavrit persistence, operator, or infrastructure logic

### 10.3 Aavrit endpoints used by Avikal

Avikal currently expects the following Aavrit endpoints:

- `GET /config`
- `GET /public-key`
- `POST /commit`
- `POST /reveal`

When the server runs in private mode, Avikal also uses:

- `POST /auth/login`
- `POST /auth/verify`
- `POST /auth/logout`

### 10.4 Aavrit creation flow

For an Aavrit-backed TimeCapsule, the high-level flow is:

```text
React selects Aavrit provider
-> backend validates unlock time against trusted time
-> backend checks Aavrit mode through /config
-> if private, backend requires a valid session
-> backend creates a local data hash
-> backend sends commit request to Aavrit
-> backend fetches the Aavrit public key
-> backend verifies the signed commit locally
-> backend derives the archive time-key material
-> backend stores Aavrit metadata inside the archive
```

### 10.5 Aavrit unlock flow

For Aavrit-backed unlock, the high-level flow is:

```text
backend reads archive metadata
-> backend detects provider = Aavrit
-> backend restores Aavrit server context from archive metadata
-> if private, backend requires a valid session
-> backend fetches Aavrit public key
-> backend requests reveal by commit_id
-> backend verifies the signed reveal locally
-> backend recomputes and verifies commit linkage
-> backend decrypts through the shared archive core
```

### 10.6 Aavrit security model

Avikal does not blindly trust unsigned Aavrit responses.

The Aavrit integration is based on:

- signed commit payloads
- signed reveal payloads
- local Ed25519 verification inside Avikal
- archive metadata that binds the archive to the Aavrit commit state

The remaining trust assumption is operational:

- the Aavrit server operator controls release timing and key custody
- a compromised or misconfigured Aavrit deployment can weaken release guarantees even if the local archive engine remains correct

## 11. Current coupling points

The current architecture is deliberate, but a few coupling points are worth knowing:

- the desktop app depends on a local backend process being available
- the backend stores current Aavrit session state in process-global memory
- the desktop decrypt experience depends on preview-session lifecycle management
- the CLI and the API share core logic but not identical user experience flows

These are not accidental duplications. They are part of the current design.

## 12. Practical summary

The architecture can be reduced to this:

```text
Desktop GUI
-> local FastAPI backend
-> shared archive core

CLI
-> shared archive core

Aavrit
-> separate external service used through HTTP
```

That is the key boundary model for understanding this repository.
