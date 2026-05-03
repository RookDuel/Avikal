<p align="center">
  <strong>ROOKDUEL</strong>
</p>

<h1 align="center">RookDuel Avikal</h1>

<p align="center">
  Secure <code>.avk</code> archives for desktop and terminal workflows.
</p>

<p align="center">
  Electron desktop app, Python CLI, shared archive core, and TimeCapsule flows through drand or Aavrit.
</p>

<p align="center">
  <a href="https://github.com/RookDuel/Avikal/stargazers"><img src="https://img.shields.io/github/stars/RookDuel/Avikal?style=for-the-badge&label=Stars&color=1f6feb" alt="GitHub stars" /></a>
  <a href="https://github.com/RookDuel/Avikal/forks"><img src="https://img.shields.io/github/forks/RookDuel/Avikal?style=for-the-badge&label=Forks&color=6d28d9" alt="GitHub forks" /></a>
  <a href="https://github.com/RookDuel/Avikal/issues"><img src="https://img.shields.io/github/issues/RookDuel/Avikal?style=for-the-badge&label=Issues&color=dc2626" alt="GitHub issues" /></a>
  <a href="https://github.com/RookDuel/Avikal/commits"><img src="https://img.shields.io/github/last-commit/RookDuel/Avikal?style=for-the-badge&label=Last%20Commit&color=0f172a" alt="GitHub last commit" /></a>
  <a href="https://github.com/RookDuel/Avikal/blob/main/LICENSE"><img src="https://img.shields.io/github/license/RookDuel/Avikal?style=for-the-badge&label=License&color=238636" alt="GitHub license" /></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Build-Verified-1f6feb?style=for-the-badge" alt="Build Verified" />
  <img src="https://img.shields.io/badge/Desktop-Electron-0f172a?style=for-the-badge&logo=electron&logoColor=white" alt="Electron Desktop" />
  <img src="https://img.shields.io/badge/Frontend-React-0f172a?style=for-the-badge&logo=react&logoColor=61dafb" alt="React Frontend" />
  <img src="https://img.shields.io/badge/Backend-FastAPI-0f172a?style=for-the-badge&logo=fastapi&logoColor=10b981" alt="FastAPI Backend" />
  <img src="https://img.shields.io/badge/CLI-Python-0f172a?style=for-the-badge&logo=python&logoColor=facc15" alt="Python CLI" />
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Languages-Python%20%7C%20TypeScript-7c3aed?style=for-the-badge" alt="Languages used" />
  <img src="https://img.shields.io/badge/Format-.avk-bd561d?style=for-the-badge" alt="AVK archive format" />
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-9a3412?style=for-the-badge" alt="AES-256-GCM encryption" />
  <img src="https://img.shields.io/badge/Protection-Password%20%7C%20Keyphrase%20%7C%20PQC-334155?style=for-the-badge" alt="Protection modes" />
  <img src="https://img.shields.io/badge/TimeCapsule-drand%20%7C%20Aavrit-334155?style=for-the-badge" alt="TimeCapsule providers" />
</p>

<p align="center">
  <a href="https://github.com/RookDuel/Avikal"><strong>Repository</strong></a>
  &nbsp;|&nbsp;
  <a href="./ARCHITECTURE.md"><strong>Architecture</strong></a>
  &nbsp;|&nbsp;
  <a href="./SECURITY.md"><strong>Security</strong></a>
  &nbsp;|&nbsp;
  <a href="./CONTRIBUTING.md"><strong>Contributing</strong></a>
  &nbsp;|&nbsp;
  <a href="./CLI_USAGE.md"><strong>CLI Usage</strong></a>
</p>

---

<p align="center">
  <img src="./assets/Encode.png" alt="Avikal Encode UI" width="1100" />
</p>

<p align="center">
  <sub>Encode view shown in both dark and light themes.</sub>
</p>

## Overview

Avikal is a secure archive system built around the `.avk` format. It exposes two user-facing surfaces:

- a desktop app built with Electron and React
- a standalone Python CLI exposed as `avikal`

Both surfaces use the same Python archive core. Encryption, decryption, keyphrase handling, PQC keyfile support, archive validation, and TimeCapsule behavior are implemented once and reused across the app and the CLI.

## Why Avikal

| Area | Current behavior |
| --- | --- |
| Archive model | Structured `.avk` archives using `keychain.pgn` for the protected control plane, wrapped payload keys, and `payload.enc` for streamed payload data |
| Protection options | Password, 21-word Hindi keyphrase, and optional PQC `.avkkey` support |
| Time release | Future unlocks through `drand` or external `Aavrit` commit/reveal verification |
| Interfaces | Desktop GUI and standalone CLI |
| Decryption flow | Desktop preview-session workflow before final extraction |

## Product surfaces

| Surface | Best for | Runtime model |
| --- | --- | --- |
| Desktop app | Interactive archive creation, decryption, preview, and TimeCapsule workflows | Electron launches a local Python FastAPI backend and the React UI talks to it over `127.0.0.1:5000` |
| CLI package | Developers, scripting, CI, and local archive operations | `avikal` calls the shared archive core directly inside Python, without shipping the desktop API layer |
| Shared archive core | Format, crypto, metadata, PQC, and time-lock behavior | Reused by both GUI and CLI |

## UI walkthrough

### Encode

The app opens on the archive creation flow. Users can package files, apply password or keyphrase protection, and optionally create a separate `.avkkey` file for PQC-assisted recovery.

![Avikal Encode page](./assets/Encode.png)

### Decode

The decrypt flow verifies the archive, collects the required access material, and opens the decrypted result through a controlled preview-session workflow before cleanup or extraction.

![Avikal Decode page](./assets/Decode.png)

### TimeCapsule

TimeCapsule supports two release authorities:

- `drand` for public time-based unlocks
- `Aavrit` for signed commit/reveal verification through an external authority

![Avikal TimeCapsule page](./assets/Time.png)

## How the system is structured

At a high level:

```text
Desktop app
-> Electron shell
-> local FastAPI backend
-> shared archive core

CLI
-> shared archive core

Aavrit
-> external service used only through HTTP
```

This separation keeps the product clean:

- the desktop app gets native dialogs, session UX, and preview workflows
- the CLI stays lightweight and does not require Electron or the desktop API service package
- archive behavior remains consistent because both surfaces reuse the same core

More detail is available in [ARCHITECTURE.md](./ARCHITECTURE.md).

## Key features

### Archive protection

- password-protected archives
- 21-word Hindi keyphrase-protected archives
- optional external `.avkkey` generation for PQC-assisted unlock

### TimeCapsule modes

- `drand`: public delayed unlock path
- `Aavrit`: external signed commit/reveal authority used through HTTP

### Shared-core design

- one archive engine for the GUI and the CLI
- consistent encryption, validation, and extraction rules
- no duplicate archive logic across surfaces

## Installation

### Desktop users

Use a published desktop release when available.

If you are running from source instead:

```powershell
npm install
cd frontend
npm install
cd ..
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
cd ..
npm run dev
```

### CLI users

Install the CLI from the backend package:

```powershell
pip install .\backend
avikal --help
```

That installation publishes the CLI and shared archive core only. The desktop app's FastAPI layer
stays in the repository and in desktop builds; it is not part of the PyPI-facing CLI package.

Module entry points also work:

```powershell
python -m avikal_backend --help
python -m avikal_backend.cli --help
```

If a package index release is published separately, the install command becomes:

```powershell
pip install avikal
```

### Contributors

For local development with editable backend installs:

```powershell
npm install
cd frontend
npm install
cd ..
cd backend
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
cd ..
```

Run the desktop app:

```powershell
npm run dev
```

Run the CLI:

```powershell
avikal --help
```

## CLI quick start

| Task | Command |
| --- | --- |
| Create a protected archive | `avikal enc document.pdf --password-prompt` |
| Create with keyphrase | `avikal enc document.pdf --keyphrase "word1 word2 ... word21"` |
| Create with PQC keyfile | `avikal enc document.pdf --password-prompt --pqc` |
| Create a time-locked archive | `avikal enc reports --timecapsule -u "2026-05-01 12:00" -p "StrongPass#123"` |
| Rotate credentials | `avikal rekey locked.avk --old-password-prompt --new-password-prompt` |
| Inspect archive metadata | `avikal info locked.avk` |
| List contents | `avikal ls locked.avk -p "StrongPass#123"` |
| Extract archive | `avikal dec locked.avk -d output -p "StrongPass#123"` |

Full CLI usage is documented in [CLI_USAGE.md](./CLI_USAGE.md).

## Repository layout

```text
OpenSource/
+-- electron/                  # Electron main process and preload bridge
+-- frontend/                  # React renderer
+-- backend/
|   +-- api_server.py          # Electron-facing backend launcher
|   +-- pyproject.toml         # Python package definition for the CLI
|   \-- src/avikal_backend/
|       +-- api/               # FastAPI layer for the desktop app
|       +-- archive/           # shared archive core
|       +-- cli/               # standalone CLI
|       +-- mnemonic/          # Hindi keyphrase generation and validation
|       \-- services/          # trusted time helpers
\-- scripts/                   # packaging and runtime preparation
```

## Security notes

- Losing the password, keyphrase, or required `.avkkey` can make recovery impossible.
- Quantum Keyfile archives require the external `.avkkey` file during unlock and use Avikal's fixed hybrid suite: ML-KEM-1024 + X25519 with ML-DSA-87 and SLH-DSA-SHA2-256s.
- Aavrit-backed TimeCapsule relies on the security and integrity of the external Aavrit deployment.
- The desktop app decrypts into temporary preview-session directories before cleanup or final extraction.

See [SECURITY.md](./SECURITY.md) for the current trust model and reporting guidance.

## Documentation

- [ARCHITECTURE.md](./ARCHITECTURE.md) - system design, runtime flow, and Aavrit integration
- [SECURITY.md](./SECURITY.md) - security boundaries, trust model, and reporting process
- [CONTRIBUTING.md](./CONTRIBUTING.md) - contributor workflow and review expectations
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) - participation standards
- [CLI_USAGE.md](./CLI_USAGE.md) - standalone CLI guide and examples

## License

Avikal is licensed under the [Apache License 2.0](./LICENSE).
