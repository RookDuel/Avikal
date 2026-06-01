# Avikal CLI Guide

The `avikal` command is the command-line interface for the shared Avikal archive core. It is useful for scripting, automation, diagnostics, and direct local archive work.

The CLI does not require Electron or the desktop UI.

## Install

From a local checkout:

```powershell
pip install .\backend
```

For editable development:

```powershell
pip install -e .\backend
```

From inside `backend/`:

```powershell
pip install .
```

If a package-index release is available:

```powershell
pip install avikal
```

## Entry Points

```powershell
avikal --help
python -m avikal_backend --help
python -m avikal_backend.cli --help
```

## Commands

- `encode` / `enc`: create an `.avk` archive
- `decode` / `dec` / `extract`: extract an archive
- `inspect` / `info`: inspect archive requirements and metadata
- `contents` / `ls` / `list`: list logical archive contents
- `validate` / `check`: validate archive structure and optional metadata access
- `rekey` / `rotate`: rotate supported archive credentials
- `doctor` / `diag`: check runtime readiness

## Quick Examples

Create a password-protected archive:

```powershell
avikal enc document.pdf --password-prompt
```

Create an archive using a 21-word keyphrase file:

```powershell
avikal enc document.pdf --keyphrase-file phrase.txt
```

Create with PQC keyfile support:

```powershell
avikal enc secret.docx --password-prompt --pqc
```

Create a time-locked archive:

```powershell
avikal enc reports --timecapsule --unlock "2026-05-01 12:00" --password-prompt
```

Extract an archive:

```powershell
avikal dec locked.avk --output-dir output --password-prompt
```

Extract with a PQC keyfile:

```powershell
avikal dec locked.avk --output-dir output --password-prompt --pqc-keyfile locked.avkkey
```

Inspect and list:

```powershell
avikal info locked.avk
avikal ls locked.avk --password-prompt
avikal check locked.avk
```

Rekey:

```powershell
avikal rekey locked.avk --old-password-prompt --new-password-prompt
```

Runtime diagnostics:

```powershell
avikal doctor
```

## Encode Notes

`encode` accepts one file, multiple files, or one folder.

Common options:

- `--output`, `-o`: output `.avk` path
- `--pick-files`, `-F`: choose files visually
- `--pick-folder`, `-D`: choose one folder visually
- `--pick-output`, `-O`: choose output path visually
- `--password-prompt`: interactive password input
- `--password-stdin`: read password from standard input
- `--keyphrase-file`, `-K`: read a 21-word keyphrase from file
- `--pqc`: create an external `.avkkey`
- `--pqc-keyfile-output`: custom `.avkkey` destination
- `--timecapsule` with `--unlock`: create a time-locked archive
- `--json`: machine-readable output

## Decode Notes

`decode` recovers files from an archive.

Common options:

- `--output-dir`, `-d`: extraction directory
- `--pick`, `-P`: choose archive visually
- `--pick-output-dir`, `-O`: choose extraction directory visually
- `--password-prompt`
- `--password-stdin`
- `--keyphrase-file`, `-K`
- `--pqc-keyfile`
- `--json`

## Rekey Notes

`rekey` rotates supported password/keyphrase protection without rewriting the encrypted payload stream.

Current limitations:

- regular rekey-capable archives are supported
- PQC rekey is intentionally rejected
- provider TimeCapsule rekey is intentionally rejected

## PQC Runtime Notes

The Windows desktop package is expected to include its required PQC runtime. Plain CLI installs may require a configured OpenSSL 3.5+ runtime for PQC operations.

Use `avikal doctor` to verify local runtime readiness.

## CLI vs Desktop

Use the CLI for scripts, automation, and direct local operations.

Use the desktop app for native dialogs, preview sessions, settings, Aavrit account flows, and guided archive workflows.

Both surfaces use the same archive core. There is no separate CLI encryption engine.
