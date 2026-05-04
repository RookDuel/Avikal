# RookDuel Avikal CLI Guide

The `avikal` command is the standalone command-line interface for the Avikal archive engine.

It uses the same shared archive core as the desktop app, but it does **not** require:

- Electron
- the React frontend
- the local FastAPI desktop backend

That makes it the right surface for scripting, CI, automation, and direct local archive work.

## What the CLI includes today

The CLI currently supports:

- regular `.avk` archive creation
- regular `.avk` extraction
- archive inspection
- logical contents listing
- archive validation
- credential rotation through `rekey`
- shared-engine time-lock support
- runtime diagnostics through `doctor`

## Important limits today

### PQC

The desktop app bundles its OpenSSL PQC runtime.

The plain CLI package does **not** bundle that runtime today. That means:

- `pip install avikal` gives you the core CLI
- PQC archive operations still require an OpenSSL 3.5+ runtime with the needed algorithms available
- the CLI expects that runtime through `AVIKAL_OPENSSL_EXEC` when PQC is used

### TimeCapsule

Current CLI TimeCapsule position:

- shared-engine time-lock support exists
- drand-style future-unlock behavior is supported through the shared engine
- full Aavrit login / session / commit / reveal workflows are **not** exposed as a first-class CLI experience yet

## Install

### From a local checkout

From the repository root:

```powershell
pip install .\backend
```

For editable development:

```powershell
pip install -e .\backend
```

### From inside `backend/`

```powershell
cd backend
pip install .
```

### From a published package

```powershell
pip install avikal
```

## Entry points

After installation, these entry points work:

```powershell
avikal --help
python -m avikal_backend --help
python -m avikal_backend.cli --help
```

## Command overview

- `encode` / `enc` — create a new `.avk` archive
- `decode` / `dec` / `extract` — recover files from an archive
- `inspect` / `info` — read archive/container details
- `contents` / `ls` / `list` — list logical files in an archive
- `validate` / `check` — verify archive structure and optional metadata access
- `rekey` / `rotate` — rotate password or keyphrase protection without rewriting `payload.enc`
- `doctor` / `diag` — check runtime readiness and optional Aavrit connectivity

## Quick examples

### Create a protected archive

```powershell
avikal enc document.pdf --password-prompt
```

### Create with a Devanagari keyphrase

```powershell
avikal enc document.pdf --keyphrase-file phrase.txt
```

### Create with PQC

```powershell
avikal enc secret.docx --password-prompt --pqc
```

### Create a time-locked archive

```powershell
avikal enc reports --timecapsule -u "2026-05-01 12:00" --password-prompt
```

### Extract an archive

```powershell
avikal dec locked.avk -d output --password-prompt
```

### Extract a PQC-protected archive

```powershell
avikal dec locked.avk -d output --password-prompt --pqc-keyfile locked.avkkey
```

### Inspect before extraction

```powershell
avikal info locked.avk
avikal ls locked.avk --password-prompt
avikal check locked.avk
```

### Rotate archive credentials

```powershell
avikal rekey locked.avk --old-password-prompt --new-password-prompt
```

### Diagnose the local runtime

```powershell
avikal doctor
```

## `encode`

Use `encode` to create a new archive from:

- one file
- several files
- one folder

It supports:

- password protection
- 21-word Devanagari keyphrase protection
- optional PQC `.avkkey` generation
- optional time-lock creation

Helpful options:

- `--output`, `-o` — output `.avk` path
- `--pick-files`, `-F` — choose files visually
- `--pick-folder`, `-D` — choose one folder visually
- `--pick-output`, `-O` — choose output path visually
- `--password-prompt` — safest interactive password flow
- `--password-stdin` — useful for automation
- `--keyphrase-file`, `-K` — read a 21-word keyphrase from file
- `--pqc` — require a companion `.avkkey`
- `--pqc-keyfile-output` — custom `.avkkey` destination
- `--timecapsule` with `--unlock` — create a time-locked archive
- `--json` — machine-readable output

## `decode`

Use `decode` when you want to recover files from an archive.

Helpful options:

- `--output-dir`, `-d` — extraction directory
- `--pick`, `-P` — choose archive visually
- `--pick-output-dir`, `-O` — choose extraction directory visually
- `--password-prompt`
- `--password-stdin`
- `--keyphrase-file`, `-K`
- `--pqc-keyfile`
- `--json`

## `inspect`

Use `inspect` when you want archive details without extracting files.

It can show:

- archive mode
- protection requirements
- TimeCapsule provider
- PQC requirement state
- basic metadata and file summary where available

Helpful options:

- `--skip-timelock` — try metadata inspection before unlock time
- `--json`

## `contents`

Use `contents` when you want the logical file list before extraction.

Helpful options:

- `--pqc-keyfile`
- `--skip-timelock`
- `--json`

## `validate`

Use `validate` for a quick structural and metadata-access check.

Helpful options:

- `--skip-timelock`
- `--json`

## `rekey`

Use `rekey` when you want to rotate the archive's password or keyphrase without rebuilding the whole payload.

What it does:

- opens the current keychain with the old credentials
- re-wraps the payload key with the new credentials
- rewrites `keychain.pgn`
- keeps `payload.enc` byte-for-byte unchanged

Helpful options:

- `--old-password-prompt`
- `--old-keyphrase-file`
- `--new-password-prompt`
- `--new-keyphrase-file`
- `--output`, `-o` — write a new archive instead of rekeying in place
- `--force`
- `--json`

Current limitation:

- regular rekey-capable archives are supported
- PQC rekey is not supported yet
- provider TimeCapsule rekey is not supported yet

## `doctor`

Use `doctor` when you want to verify that the CLI environment is healthy.

It currently checks:

- Python/runtime information
- required imports
- local write access
- PQC runtime readiness
- optional Aavrit endpoint reachability

Examples:

```powershell
avikal doctor
avikal doctor --aavrit-url https://aavrit.example
```

## CLI vs desktop app

### CLI is best for

- scripts
- CI
- automation
- direct local archive operations

### Desktop is best for

- interactive archive creation
- native dialogs
- preview-based decryption
- full Aavrit workflow handling

Both surfaces still use the same shared archive core. There is no second encryption engine.

## JSON mode

Commands that support `--json` are useful for:

- scripts
- CI checks
- wrappers
- automation pipelines

## Help

For the latest command surface:

```powershell
avikal --help
avikal enc --help
avikal dec --help
avikal info --help
avikal ls --help
avikal check --help
avikal rekey --help
avikal doctor --help
```
