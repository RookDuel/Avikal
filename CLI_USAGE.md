# RookDuel Avikal CLI Guide

The `avikal` command is the standalone command-line interface for the Avikal archive engine.

It uses the same Python archive core as the desktop application, but it does not require:

- Electron
- the React frontend
- the local FastAPI server to be running

That makes it the right interface for developers, scripting, CI, and direct local archive work.

## Package scope

The published `avikal` package is intentionally CLI-focused.

It includes:

- the `avikal` command
- the shared archive core
- CLI support modules used for local archive operations

It does not include the desktop application's FastAPI service layer. The Electron app keeps its
own local backend process inside the repository and packaged desktop build, while the PyPI package
ships only what the CLI needs.

## Install

### From a local source checkout

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

If the package is published separately:

```powershell
pip install avikal
```

## Entry points

After installation, all of these work:

```powershell
avikal --help
python -m avikal_backend --help
python -m avikal_backend.cli --help
```

On Windows, `pip` creates the `avikal` command automatically through the package entry point.

## Command overview

| Command | Aliases | Purpose |
| --- | --- | --- |
| `encode` | `enc` | Create a new `.avk` archive |
| `decode` | `dec`, `extract` | Extract an `.avk` archive |
| `inspect` | `info` | Read container and metadata details |
| `contents` | `ls`, `list` | List logical files inside an archive |
| `validate` | `check` | Verify archive structure and optional metadata access |
| `doctor` | `diag` | Check runtime health and optional Aavrit connectivity |

## Quick examples

### Create a protected archive

```powershell
avikal enc document.pdf -p "StrongPass#123"
```

### Create a multi-file archive

```powershell
avikal enc photo.jpg notes.txt reports.xlsx -o bundle.avk -p "StrongPass#123"
```

### Create with a 21-word keyphrase

```powershell
avikal enc document.pdf --keyphrase "word1 word2 word3 ... word21"
avikal enc document.pdf --keyphrase-file phrase.txt
```

### Create with PQC keyfile support

```powershell
avikal enc secret.docx -p "StrongPass#123" --pqc
avikal enc secret.docx -p "StrongPass#123" --pqc --pqc-keyfile-output secret.avkkey
```

### Create a time-locked archive

```powershell
avikal enc reports --timecapsule -u "2026-05-01 12:00" -p "StrongPass#123"
```

The `--unlock` value is interpreted in your local timezone.

### Extract an archive

```powershell
avikal dec locked.avk -d output -p "StrongPass#123"
avikal dec locked.avk -d output --keyphrase-file phrase.txt
avikal dec locked.avk -d output -p "StrongPass#123" --pqc-keyfile locked.avkkey
```

### Inspect before extraction

```powershell
avikal info locked.avk
avikal ls locked.avk -p "StrongPass#123"
avikal check locked.avk
```

## `encode`

Use `encode` when you want to create a new `.avk` archive.

### What it supports

- single-file archives
- multi-file archives
- folder-backed archives
- password protection
- 21-word Hindi keyphrase protection
- optional PQC `.avkkey` generation
- optional TimeCapsule creation

### Main options

| Option | Purpose |
| --- | --- |
| `inputs` | One or more input file or folder paths |
| `--pick-files`, `-F` | Open the system picker for files |
| `--pick-folder`, `-D` | Open the system picker for one folder |
| `--pick-output`, `-O` | Open the save dialog for the destination archive |
| `--output`, `-o` | Explicit output `.avk` path |
| `--password`, `-p` | Password-based protection |
| `--keyphrase` | Direct 21-word keyphrase input |
| `--keyphrase-file`, `-K` | Read the keyphrase from a UTF-8 text file |
| `--pqc` | Generate and require a companion `.avkkey` file |
| `--pqc-keyfile-output` | Custom output path for the generated `.avkkey` |
| `--timecapsule` | Enable time-locked archive creation |
| `--unlock`, `-u` | Unlock time in your local timezone using `YYYY-MM-DD HH:MM` |
| `--force` | Overwrite an existing output archive |
| `--json` | Return machine-readable output |

### Important rules

- Use either `--keyphrase` or `--keyphrase-file`, not both.
- TimeCapsule creation requires both `--timecapsule` and `--unlock`.
- PQC mode is layered protection. It adds a required `.avkkey` file to the normal archive credentials.

## `decode`

Use `decode` when you want to recover files from an archive.

### Main options

| Option | Purpose |
| --- | --- |
| `input` | Source archive path |
| `--pick`, `-P` | Pick the archive visually |
| `--output-dir`, `-d` | Extraction directory |
| `--pick-output-dir`, `-O` | Pick the extraction directory visually |
| `--password`, `-p` | Password for decryption |
| `--keyphrase` | Direct keyphrase input |
| `--keyphrase-file`, `-K` | Keyphrase file path |
| `--pqc-keyfile` | Companion `.avkkey` path |
| `--json` | Return machine-readable output |

## `inspect`

Use `inspect` when you want to read archive/container details without extracting files.

Typical output includes:

- archive mode
- encryption method
- TimeCapsule provider
- PQC requirement state
- manifest and logical file summary where available

Useful examples:

```powershell
avikal info locked.avk
avikal info locked.avk -p "StrongPass#123"
avikal info locked.avk --keyphrase-file phrase.txt
```

## `contents`

Use `contents` when you want the logical file list before extraction.

Useful examples:

```powershell
avikal ls locked.avk -p "StrongPass#123"
avikal ls locked.avk --keyphrase-file phrase.txt
avikal ls locked.avk -p "StrongPass#123" --pqc-keyfile locked.avkkey
```

## `validate`

Use `validate` for a quick structural and metadata-access check.

Useful examples:

```powershell
avikal check locked.avk
avikal check locked.avk -p "StrongPass#123"
avikal check locked.avk --keyphrase-file phrase.txt
```

## `doctor`

Use `doctor` when you want to verify that the CLI environment is healthy.

It checks:

- Python/runtime information
- required CLI package imports
- local filesystem write access
- optional Aavrit endpoint reachability

Examples:

```powershell
avikal diag
avikal diag --aavrit-url https://kvs-aavrit.rookduel.tech
avikal diag --aavrit-url https://kvs-aavrit.rookduel.tech --timeout 5
```

### Important Aavrit note

Current CLI Aavrit support is intentionally limited.

The CLI can probe Aavrit connectivity through `doctor`, but it does not currently handle:

- Aavrit login/session management
- Aavrit-backed archive creation
- Aavrit-backed reveal/unlock workflows

Those workflows are currently handled through the desktop application and its backend API.

## CLI vs desktop app

| Surface | Best for |
| --- | --- |
| CLI | scripting, automation, CI, direct local archive operations |
| Desktop app | interactive archive creation, native dialogs, preview-based decryption, Aavrit session workflows |

The important architectural point is that both surfaces use the same archive core:

```text
CLI -> avikal_backend.archive.*
Desktop backend API -> avikal_backend.archive.*
```

There is no second or separate encryption engine.

## JSON mode

Commands that support `--json` return structured output for:

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
avikal diag --help
```
