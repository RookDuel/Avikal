# Avikal Python Package

This directory contains the installable Python package for the Avikal CLI and shared archive core.

The published package is intentionally scoped to:

- the `avikal` CLI
- the shared archive engine
- supporting modules used directly by the CLI

The Electron desktop application supervises the same package through private stdio JSON-RPC. The
repository has no secondary HTTP backend or duplicate archive implementation.

What the package is designed to ship:

- regular `.avk` encode, inspect, list, validate, decode, and rekey flows
- password and Devanagari keyphrase protection
- trusted-time timecapsule checks through the shared archive engine

What requires an external runtime:

- PQC archive operations require an OpenSSL 3.5+ runtime with the PQC algorithms available.
- The desktop app bundles that runtime automatically.
- The standalone CLI package can either bundle a target-OS OpenSSL PQC runtime under `avikal_backend/runtime/pqc` or discover one through `AVIKAL_OPENSSL_EXEC` / `AVIKAL_PQC_RUNTIME_DIR` when PQC is used.

Main entry point:

```powershell
avikal --help
```

Project documentation:

- repository README: `../README.md`
- CLI guide: `../CLI_USAGE.md`
- security model: `../SECURITY.md`
