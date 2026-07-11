# Changelog

## 1.0.6

- Prepared the repository for public open-source release with maintainer-led contribution boundaries.
- Replaced the desktop HTTP backend flow with the supervised stdio JSON-RPC Avikal core.
- Hardened production runtime verification for native crypto, OpenSSL PQC runtime files, release metadata, and packaged assets.
- Added authenticated archive reports, version compatibility metadata, archive signatures, and assurance evidence for new archives.
- Added indexed payload support for authenticated content listing and selective recovery workflows.
- Improved large-archive streaming, adaptive compression, cancellation behavior, preview cleanup, and progress reporting.
- Added optional dual-password protection for external `.avkkey` files.
- Added PQC suite profiles and supported ML-KEM, ML-DSA, and SLH-DSA parameter selection.
- Added native Rust Chess-PGN codec acceleration and richer Chess-PGN statistics in reports.
- Added Settings-based update checking, diagnostics, runtime status, privacy controls, and help/legal links.
- Added tamper-evident local activity history and audit-chain status reporting.
- Refined Windows packaging for self-contained GUI and CLI NSIS installers with shared-core reuse.

## Earlier Development

Earlier snapshots were internal beta builds and may not match the current archive, packaging, reporting, or runtime-hardening behavior.
