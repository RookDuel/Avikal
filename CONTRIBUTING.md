# Contributing to Avikal

Thanks for taking the time to contribute. Avikal is a security-sensitive project with a shared archive core used by both the desktop app and the CLI, so changes need to stay focused and well explained.

## Before you start

Open an issue or start a discussion before working on large changes, especially if they affect:

- archive format structure
- encryption or key-derivation behavior
- TimeCapsule provider contracts
- Electron security boundaries
- packaging or distribution flow

Small fixes, documentation corrections, and isolated bug fixes can usually go straight to a pull request.

## Design rules for contributions

Please follow these project boundaries:

- Do not duplicate archive logic between the CLI and the API.
- Keep the shared archive core in `backend/src/avikal_backend/archive` as the single source of truth.
- Do not change archive format semantics casually. Archive compatibility matters.
- Do not change Aavrit API expectations in this repository without coordinating the matching server-side change separately.
- Keep UI, API, and CLI behavior aligned when they rely on the same archive rule.

## Local setup

### 1. Install JavaScript dependencies

From the repository root:

```powershell
npm install
cd frontend
npm install
cd ..
```

### 2. Install backend dependencies

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cd ..
```

This gives you:

- the local FastAPI backend dependencies
- the `avikal` CLI command
- editable installs for backend Python code

## Running the project

### Desktop app

```powershell
npm run dev
```

This starts:

- the Vite frontend dev server
- the Electron shell
- the local Python backend launched by Electron

### CLI

```powershell
avikal --help
```

The CLI does not require the Electron app or the FastAPI server to be running.

## Recommended checks

Run the checks that match your change.

### Frontend build

```powershell
cd frontend
npm run build
cd ..
```

### Backend test suite

```powershell
cd backend
venv\Scripts\python.exe -m pytest -p no:cacheprovider
cd ..
```

### Backend import/compile sanity check

```powershell
cd backend
venv\Scripts\python.exe -m compileall src\avikal_backend
cd ..
```

If your change touches only one subsystem, note which checks you ran and why that scope was sufficient.

## Pull request checklist

Each pull request should include:

- a short description of the change
- the user-visible or developer-visible impact
- any archive-format impact
- any security impact
- the checks you ran

Also update documentation when you change:

- command names or CLI behavior
- API routes or request shapes
- TimeCapsule provider expectations
- packaging steps
- security assumptions

## Areas that need extra care

Please call out changes clearly if they affect:

- `backend/src/avikal_backend/archive/security`
- `backend/src/avikal_backend/archive/format`
- `backend/src/avikal_backend/api/server.py`
- `backend/src/avikal_backend/api/aavrit_client.py`
- Electron preload or native file access behavior

## Commit and review style

- Keep commits focused.
- Avoid unrelated refactors in the same change.
- Prefer explicit, reviewable patches over broad rewrites.
- When in doubt, choose the simplest change that matches the current architecture.
