# Security Policy

## Scope

This repository covers:

- the Windows desktop application
- the standalone CLI package
- the shared Python/Rust archive core
- Avikal client-side Aavrit integration

The Aavrit server implementation is a separate project and is not covered by this repository.

## Supported Code

Security fixes target:

- the current default branch
- the latest published desktop release, if available
- the latest published CLI release, if available

Older snapshots may not receive backported fixes.

## Current Security Model

Protected `.avk` archives use:

- AES-256-GCM for authenticated encryption
- Argon2id for password and keyphrase hardening
- HKDF-based key separation
- native Rust-backed crypto for production paths
- strict container validation before deeper decode work
- path traversal defenses during extraction
- bounded decompression and payload streaming checks

Newer protected archives use a random payload data-encryption key wrapped through protected metadata. This allows supported rekey operations without rewriting the encrypted payload stream.

## Password and Keyphrase Handling

Avikal supports:

- password-only protection
- 21-word Hindi keyphrase protection
- password and keyphrase together

Passwords and keyphrases are not intentionally persisted. They still exist temporarily in UI/runtime memory while an operation is active. Avikal does not claim protection against a compromised endpoint, keylogger, debugger, or memory-scraping malware.

## PQC Mode

Optional PQC protection records the exact selected suite. Supported OpenSSL-backed primitives include:

- ML-KEM-768
- ML-KEM-1024
- X25519
- ML-DSA-65
- ML-DSA-87
- SLH-DSA-SHA2-128s
- SLH-DSA-SHA2-192s
- SLH-DSA-SHA2-256s

External `.avkkey` files can optionally be protected by an additional keyfile password. Embedded PQC behavior remains separate.

## TimeCapsule Mode

Avikal supports TimeCapsule workflows through:

- drand for public time-based release
- Aavrit for signed authority-based release

TimeCapsule protection depends on network availability and the integrity of the selected release authority. Aavrit-backed workflows additionally depend on the correct operation and trustworthiness of the Aavrit deployment.

## Desktop Runtime Boundary

The desktop app uses:

- Electron renderer
- Electron IPC
- Electron main process
- Avikal core process over JSON-RPC/stdin-stdout
- shared Python orchestration and Rust native crypto

The desktop runtime does not rely on a local HTTP API for normal app communication.

## Non-Claims

Avikal does not claim protection against:

- malware or spyware on the same machine
- keyloggers
- memory scraping on a compromised host
- weak user passwords
- lost passwords, keyphrases, or `.avkkey` files
- drand or Aavrit outages
- malicious use by the user
- information-theoretic secrecy
- formal steganographic indistinguishability of generated PGN

## Operational Guidance

- Store `.avkkey` files separately from their matching `.avk` archives.
- Back up passwords, keyphrases, and keyfiles carefully.
- Keep system time reliable when using TimeCapsule.
- Treat decrypted preview files as temporary plaintext.
- Use the activity export only after confirming it contains no sensitive operational detail for your environment.
- Use `avikal doctor` to verify CLI runtime readiness.

## Release Integrity

- Production builds must be created from the exact Git tag being released.
- GitHub release metadata is signed with Avikal's offline Ed25519 release key. Installed clients reject unsigned or invalid metadata and do not display its hashes as verified.
- Production packages contain an Ed25519-signed manifest for the backend executable, native crypto module, OpenSSL executable, and OpenSSL crypto library.
- GitHub Actions publishes SHA-256 files, a CycloneDX SBOM, and GitHub artifact provenance attestations.
- GitHub NSIS installers are self-contained but are not Authenticode-trusted unless a future certificate is explicitly added. Users should verify the publisher metadata, SHA-256 value, and GitHub attestation.
- Microsoft Store builds use the separate MSIX workflow and rely on Microsoft Store package signing rather than a repository-owned paid certificate.
- Release signing private keys must never be committed. The workflow reads the key only from the protected `AVIKAL_RELEASE_SIGNING_PRIVATE_KEY_B64` Actions secret.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before public disclosure.

Preferred process:

1. Use GitHub private vulnerability reporting if enabled.
2. If unavailable, contact the maintainer privately.
3. Include:
   - affected version, release, or commit
   - operating system and architecture
   - affected surface: desktop, CLI, archive core, TimeCapsule, Aavrit client, or packaging
   - reproduction steps
   - expected behavior
   - actual behavior
   - proof-of-concept material only when necessary

Do not open a public issue with exploit details before the maintainer has had a reasonable opportunity to reproduce and address the issue.

## High-Value Report Areas

Reports are especially useful for:

- archive encryption and decryption
- `keychain.pgn` parsing and protected metadata handling
- payload streaming and chunk authentication
- payload key wrapping and rekey behavior
- `.avkkey` generation, wrapping, and validation
- TimeCapsule unlock routing and authority verification
- preview-session cleanup and filesystem boundaries
- Electron preload and IPC boundaries
- bundled OpenSSL PQC runtime integration
