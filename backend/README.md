# Avikal Python Package

This directory contains the installable Python package for the Avikal CLI and shared archive core.

The published package is intentionally scoped to:

- the `avikal` CLI
- the shared archive engine
- supporting modules used directly by the CLI

It does not publish the desktop app API server layer. The FastAPI backend and Electron-specific API
modules remain part of the repository for the desktop application, but they are excluded from the
PyPI distribution.

What the package is designed to ship:

- regular `.avk` encode, inspect, list, validate, decode, and rekey flows
- password and Devanagari keyphrase protection
- trusted-time timecapsule checks through the shared archive engine

What requires an external runtime:

- PQC archive operations require an OpenSSL 3.5+ runtime with the PQC algorithms available.
- The desktop app bundles that runtime automatically.
- The standalone CLI package expects it through `AVIKAL_OPENSSL_EXEC` when PQC is used.

Main entry point:

```powershell
avikal --help
```

Project documentation:

- repository README: `../README.md`
- CLI guide: `../CLI_USAGE.md`
- architecture: `../ARCHITECTURE.md`
