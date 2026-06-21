<p align="center">
  <img src="./assets/logo.png" alt="RookDuel Avikal logo" width="96" />
</p>

<h1 align="center">RookDuel Avikal</h1>

<p align="center">
  Secure <code>.avk</code> archives for files, folders, TimeCapsule releases, and post-quantum protected workflows.
</p>

<p align="center">
  <a href="https://github.com/RookDuel/Avikal/stargazers"><img src="https://img.shields.io/github/stars/RookDuel/Avikal?style=for-the-badge&label=Stars&color=2563eb" alt="GitHub stars" /></a>
  <a href="https://github.com/RookDuel/Avikal/forks"><img src="https://img.shields.io/github/forks/RookDuel/Avikal?style=for-the-badge&label=Forks&color=0f172a" alt="GitHub forks" /></a>
  <a href="https://github.com/RookDuel/Avikal/issues"><img src="https://img.shields.io/github/issues/RookDuel/Avikal?style=for-the-badge&label=Issues&color=b45309" alt="GitHub issues" /></a>
  <a href="./LICENSE"><img src="https://img.shields.io/badge/License-Apache--2.0-2563eb?style=for-the-badge" alt="Apache-2.0 license" /></a>
  <img src="https://img.shields.io/badge/Status-Beta-0f172a?style=for-the-badge" alt="Beta status" />
  <img src="https://img.shields.io/badge/Desktop-Windows%20First-111827?style=for-the-badge" alt="Windows-first desktop" />
  <img src="https://img.shields.io/badge/Core-Python%20%2B%20Rust-b45309?style=for-the-badge" alt="Python and Rust core" />
  <img src="https://img.shields.io/badge/Format-.avk-334155?style=for-the-badge" alt=".avk archive format" />
</p>

<p align="center">
  <a href="#features"><strong>Features</strong></a>
  &nbsp;|&nbsp;
  <a href="#how-avikal-protects-files"><strong>Protection Model</strong></a>
  &nbsp;|&nbsp;
  <a href="#quick-start"><strong>Quick Start</strong></a>
  &nbsp;|&nbsp;
  <a href="./SECURITY.md"><strong>Security</strong></a>
  &nbsp;|&nbsp;
  <a href="./CLI_USAGE.md"><strong>CLI</strong></a>
</p>

---

<p align="center">
  <img src="./assets/Encode.png" alt="Avikal encode screen" width="1000" />
</p>

## What Is Avikal?

Avikal is a desktop and command-line archival security tool. It packages files and folders into `.avk` archives and lets the user choose how those archives should be protected, unlocked, previewed, and recovered.

It is designed for people who want more than a normal compressed file:

- stronger access controls than a plain ZIP workflow
- optional post-quantum protection
- delayed unlock through TimeCapsule mode
- reversible Chess-PGN metadata encoding
- a shared desktop and CLI core for consistent behavior

Avikal is currently Windows-first for packaged desktop releases. The codebase is structured so CLI and future cross-platform packaging can use the same archive core.

Avikal is an open-source, maintainer-led archival security project. External review, issue reports, and focused contributions are welcome, but final design, security, and release decisions remain with the maintainer.

## Features

### File and Folder Archives

- Create `.avk` archives from a single file, many files, or folders.
- Preview decrypted content inside temporary preview sessions.
- Extract only when the user chooses to keep the decoded files.
- Rekey supported archives without rewriting the encrypted payload stream.

### Password and Keyphrase Protection

- Use a normal access password.
- Use a generated 21-word Hindi keyphrase.
- Use both password and keyphrase together for stronger unlock requirements.
- Use romanized typing helpers for the Hindi/Devanagari keyphrase system.

### Chess-PGN Metadata Carrier

Avikal stores protected archive control metadata through a reversible Chess-PGN carrier.

In simple terms:

- the archive metadata is packed into bytes
- protected metadata is encrypted
- the encrypted metadata is encoded as legal chess moves
- the result is stored in `keychain.pgn`

The chess layer is an identity feature of Avikal and a reversible carrier. The actual confidentiality comes from encryption, not from claiming that PGN is mathematically indistinguishable from human chess games.

### Post-Quantum Protection

Avikal supports optional PQC-backed archive protection.

Current PQC workflows include:

- embedded PQC material inside the `.avk`
- external `.avkkey` keyfiles
- optional second-password protection for external `.avkkey` files
- hybrid post-quantum/classical key material handling in the backend core

The practical benefit is separation of access material. For example, an archive can require the normal user secret and matching PQC key material before it opens.

### TimeCapsule

TimeCapsule mode lets an archive stay locked until a release condition is met.

Supported release authorities:

- `drand` for public time-based release
- `Aavrit` for signed external release authority workflows

This is useful when data should exist now but should not become unlockable until a specific time or authority condition is satisfied.

### Aavrit Integration

Avikal can connect to Aavrit from Settings. Aavrit is treated as an external release authority that can be integrated with TimeCapsule workflows.

The Aavrit server is a separate project. This repository contains the Avikal client-side integration.

### Desktop and CLI

Avikal has two surfaces:

| Surface | Best for |
|---|---|
| Desktop app | Interactive archive creation, preview, TimeCapsule, Aavrit connection, and guided workflows |
| CLI | Automation, scripting, diagnostics, server-side workflows, and developer usage |

Both use the same backend archive core.

## How Avikal Protects Files

Avikal separates the user interface from the archive engine.

```text
Desktop UI
-> Electron IPC
-> Avikal core over JSON-RPC/stdin-stdout
-> Python orchestration + Rust native crypto

CLI
-> same Python/Rust archive core
```

The desktop runtime does not use a local HTTP server for normal app communication. Electron launches the Avikal core process and communicates with it through framed JSON-RPC over standard I/O.

Protected archives use:

- AES-256-GCM for authenticated encryption
- Argon2id for password and keyphrase hardening
- HKDF-based key separation
- Rust native crypto for production paths
- strict archive container validation
- path traversal defenses during extraction
- optional OpenSSL-backed PQC primitives

Avikal does not claim protection against malware already running on the same machine, keyloggers, memory scraping, weak passwords, or lost recovery material. Read [SECURITY.md](./SECURITY.md) before relying on Avikal for sensitive use.

## Screenshots

### Encode

<p align="center">
  <img src="./assets/Encode.png" alt="Avikal encode page" width="1000" />
</p>

### Decode

<p align="center">
  <img src="./assets/Decode.png" alt="Avikal decode page" width="1000" />
</p>

### TimeCapsule

<p align="center">
  <img src="./assets/Time.png" alt="Avikal TimeCapsule page" width="1000" />
</p>

## Quick Start

### Desktop Users

Use a published Windows desktop release when available.

For source development, use Windows PowerShell from the repository root:

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
npm run dev
```

### CLI Users

Install locally from a checkout:

```powershell
pip install .\backend
avikal --help
```

Common commands:

```powershell
avikal enc document.pdf --password-prompt
avikal dec locked.avk --output-dir output --password-prompt
avikal info locked.avk
avikal ls locked.avk --password-prompt
avikal rekey locked.avk --old-password-prompt --new-password-prompt
avikal doctor
```

See [CLI_USAGE.md](./CLI_USAGE.md) for the full CLI guide.

## Repository Layout

```text
assets/                    App logo, icons, and screenshots
backend/                   Python package, CLI, archive core, native Rust module
build/                     Windows installer integration files
electron/                  Electron main process and preload bridge
frontend/                  React renderer
packaging/                 Windows and CLI packaging helpers
runtime/                   Runtime support layout
scripts/                   Build and release preparation scripts
```

## Development Commands

```powershell
npm run dev
npm run build:frontend
npm run build:native:quick
npm run package:windows
npm run package:cli
npm run verify:cli
```

More setup details are in [SETUP.md](./SETUP.md).

## Documentation

- [SETUP.md](./SETUP.md) - source setup and build commands
- [CLI_USAGE.md](./CLI_USAGE.md) - CLI usage guide
- [SECURITY.md](./SECURITY.md) - security model and vulnerability reporting
- [CONTRIBUTING.md](./CONTRIBUTING.md) - contribution workflow
- [ROADMAP.md](./ROADMAP.md) - project direction
- [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md) - third-party license notes
- [updates.md](./updates.md) - v1.0.5 update summary

## Project Status

Avikal is in active beta development. Windows desktop packaging is the primary supported production target. CLI and future Linux/macOS packaging are part of the project direction, but they require separate release verification.

## Responsible Use

Avikal is intended for lawful file protection, backup, research, and controlled release workflows. Users are responsible for complying with applicable laws and for protecting their passwords, keyphrases, and `.avkkey` files.

## License

Avikal is licensed under the [Apache License 2.0](./LICENSE).
