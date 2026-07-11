# Setup

This guide covers source development on Windows. Windows is the primary supported packaging and QA target for the current release line.

## Prerequisites

- Node.js 22 or newer
- npm
- Python 3.13
- Rust toolchain
- PowerShell

PQC features also require the project OpenSSL PQC runtime when running packaged builds or a configured runtime for source/CLI workflows.

## Install Dependencies

From the repository root:

```powershell
npm install
cd frontend
npm install
cd ..
```

Create the backend virtual environment:

```powershell
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-build.txt
pip install -e .
cd ..
```

Build the native Rust extension:

```powershell
npm run build:native:quick
```

## Run Development Desktop

```powershell
npm run dev
```

This starts the Vite renderer and Electron. Electron launches the Avikal core process and communicates with it over JSON-RPC/stdin-stdout.

## CLI Quick Check

```powershell
avikal --help
avikal doctor
```

## Build

```powershell
npm run build:frontend
npm run build:runtime
```

Package Windows desktop:

```powershell
npm run package:windows
```

Package CLI wheel:

```powershell
npm run package:cli
npm run verify:cli
```

## Generated Files

Do not commit generated folders or runtime artifacts such as:

- `node_modules`
- `frontend/dist`
- `dist`
- `.app-build`
- `.tmp_*`
- `backend/venv`
- `backend/build`
- `*.egg-info`
- `__pycache__`
