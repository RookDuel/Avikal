# Contributing to Avikal

Avikal is an open-source, maintainer-led security project. External review, issue reports, and focused contributions are welcome, but final design, security, roadmap, and release decisions remain with the maintainer.

Contributions should be focused, reviewable, and clear about user impact. Opening an issue or pull request does not guarantee acceptance or merge.

## Before You Start

Open an issue or discussion before large changes, especially changes affecting:

- archive format behavior
- cryptography, key derivation, or PQC handling
- TimeCapsule provider contracts
- Electron preload or filesystem boundaries
- packaging, installer, or update behavior
- CLI and desktop compatibility

Small bug fixes, documentation corrections, and isolated UI fixes can usually go directly to a pull request. Maintainers may still close pull requests that do not fit the project direction, risk model, or review capacity.

## Maintainer-Led Areas

The following areas are restricted and require maintainer approval before implementation:

- archive format changes
- cryptography, key derivation, PQC, and signing behavior
- TimeCapsule release authority behavior
- Aavrit protocol integration
- Electron IPC, preload, filesystem, and process boundaries
- packaging, installer, shared-core, and update behavior
- public release workflows and distribution assets

Unsolicited rewrites of these areas may be closed without merge, even if technically functional.

## Architecture Rules

- Keep archive behavior in the shared backend core.
- Do not duplicate archive logic between desktop, CLI, and compatibility layers.
- Do not change archive semantics casually. Compatibility matters.
- Keep the Rust native crypto path mandatory for production crypto flows.
- Keep renderer-to-core communication behind Electron IPC and the stdio JSON-RPC core bridge.
- Coordinate Aavrit protocol changes with the separate Aavrit server project.

## Local Setup

```powershell
npm install
cd frontend
npm install
cd ..
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-build.txt
pip install -e .
cd ..
npm run build:native:quick
```

Run the desktop app:

```powershell
npm run dev
```

Run the CLI:

```powershell
avikal --help
```

## Recommended Checks

Run checks that match your change.

Frontend:

```powershell
cd frontend
npm run build:check
cd ..
```

Backend:

```powershell
cd backend
venv\Scripts\python.exe -m pytest -p no:cacheprovider
cd ..
```

Native module:

```powershell
npm run build:native:quick
```

Packaging:

```powershell
npm run package:windows
npm run package:cli
npm run verify:cli
```

If you run a narrower check, explain why that scope is sufficient.

## Pull Request Checklist

Each pull request should include:

- summary of the change
- user-visible impact
- security impact, if any
- archive-format impact, if any
- tests or checks performed
- documentation updates, if behavior changed

## High-Risk Areas

Call out changes clearly when they affect:

- `backend/src/avikal_backend/archive/security`
- `backend/src/avikal_backend/archive/format`
- `backend/src/avikal_backend/archive/pipeline`
- `backend/native/avikal_backend_native`
- `electron/main.js`
- `electron/preload.js`
- packaging scripts

## Review Style

- Keep commits focused.
- Avoid unrelated refactors.
- Prefer explicit patches over broad rewrites.
- Do not include generated files, caches, virtual environments, build outputs, private keys, `.env` files, or local archives.
