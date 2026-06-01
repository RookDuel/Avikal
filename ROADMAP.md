# Roadmap

Avikal is developed as a Windows-first archival security application with a shared desktop and CLI core. The roadmap below describes current direction, not a guarantee of delivery dates.

## Current Priorities

- Stabilize Windows desktop packaging and clean-machine installation.
- Keep the Rust native crypto path mandatory for production archive operations.
- Maintain compatibility for valid `.avk` archives produced by the current format.
- Improve release hygiene, documentation, and open-source contribution flow.
- Continue performance work for large archives without weakening cryptographic checks.

## Near Term

- Expand Windows release verification and installer smoke tests.
- Improve CLI packaging and verification.
- Refine public documentation for setup, security, and recovery guidance.
- Strengthen activity history and diagnostics without logging sensitive material.
- Continue TimeCapsule reliability work for drand and Aavrit-backed flows.

## Later

- Dedicated Linux CLI packaging.
- Cross-platform shared-core installer strategy.
- Broader automated release verification.
- More complete third-party notice generation.
- Additional expert review of the archive protocol and PQC construction.
