# Avikal Python Package

This directory contains the installable Python package for the Avikal CLI and shared archive core.

The published package is intentionally scoped to:

- the `avikal` CLI
- the shared archive engine
- supporting modules used directly by the CLI

It does not publish the desktop app API server layer. The FastAPI backend and `api_server.py`
remain part of the repository for the Electron desktop application, but they are excluded from
the PyPI distribution.

Main entry point:

```powershell
avikal --help
```

The CLI uses the same archive engine as the desktop application without duplicating encryption,
archive, or metadata logic.

Project documentation:

- repository README: `../README.md`
- CLI guide: `../CLI_USAGE.md`
- architecture: `../ARCHITECTURE.md`
