# Avikal Python Package

This directory contains the installable Python package for the Avikal CLI and shared archive core.

The published package is intentionally scoped to:

- the `avikal` CLI
- the shared archive engine
- supporting modules used directly by the CLI

The Electron desktop application uses the same package through a supervised stdio JSON-RPC core.
There is no secondary HTTP backend or duplicate archive implementation.

Main entry point:

```powershell
avikal --help
```

The CLI uses the same archive engine as the desktop application without duplicating encryption,
archive, or metadata logic.

Project documentation:

- repository README: `../README.md`
- CLI guide: `../CLI_USAGE.md`
- security model: `../SECURITY.md`
