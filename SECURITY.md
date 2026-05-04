# Security Policy

## Scope

This repository currently covers three security-relevant surfaces:

- the desktop application
- the standalone CLI package
- the shared Python archive core used by both

`Aavrit` server-side code is **not** part of this repository. Avikal's client-side Aavrit integration is in scope here. The Aavrit authority service itself belongs to that separate project.

## Supported code

Security fixes are handled on:

- the current default branch
- the latest published desktop release, if one exists
- the latest published CLI package release, if one exists

Older snapshots may not receive backported fixes.

## Current security model

### Core archive protection

Protected `.avk` archives currently rely on:

- **AES-256-GCM** for authenticated encryption
- **Argon2id** for password and keyphrase hardening  
  Current default: **256 MiB**, **t=3**, **p=4**
- **HKDF-based key separation** so payload, metadata, and helper keys are not reused directly
- **strict container validation** before deeper decode work begins
- **header-bound authentication** so header and ciphertext cannot be swapped freely

Newer protected archives use a **random payload data-encryption key** wrapped inside `keychain.pgn`. That design enables rekey for supported archives without rewriting `payload.enc`.

### Password and keyphrase protection

Avikal supports:

- password-only protection
- 21-word Devanagari keyphrase protection
- password + keyphrase together

The keyphrase is normalized before derivation, then hardened through the same Argon2id path used for passwords.

### Chess metadata layer

Avikal stores protected archive metadata in `keychain.pgn`.

Important distinction:

- the PGN route hints used for fast checks are **advisory**
- the encrypted metadata inside the chess keychain is **authoritative**

If the public PGN hints are modified, the real decrypt path still depends on the protected metadata and authenticated decrypt checks.

### PQC mode

Optional PQC mode adds a required external `.avkkey` file.

Current PQC implementation uses an OpenSSL 3.5+ provider-backed suite built around:

- **ML-KEM-1024**
- **X25519**
- **ML-DSA-87**
- **SLH-DSA-SHA2-256s**

The desktop app bundles the PQC runtime. The plain CLI package does **not** bundle it today, so CLI PQC requires a configured OpenSSL runtime path.

### TimeCapsule mode

Avikal currently supports two TimeCapsule directions:

- **drand**: public future-unlock path
- **Aavrit**: signed authority path

Current product shape:

- desktop app: full drand flow and the main Aavrit client flow
- CLI: shared-engine time-lock support, but not the full Aavrit session / commit / reveal workflow surface

## Trust model

### Desktop app

The desktop app runs:

- Electron shell
- React frontend
- local FastAPI backend
- shared archive core

The local backend is part of the trusted runtime boundary.

### drand

`drand` is the public TimeCapsule release path.

- unlock depends on external drand round availability
- availability depends on network access
- release timing is external to this repository

### Aavrit

`Aavrit` is the managed authority path.

- Avikal verifies signed authority material locally
- the external Aavrit deployment still matters to the overall guarantee
- misconfiguration or compromise of the Aavrit operator can weaken Aavrit-backed release guarantees independently of the local archive engine

## What this project does not claim to protect against

This project does not claim to protect against:

- malware, spyware, or a compromised host
- keyloggers
- memory scraping on an already-compromised machine
- weak user passwords or careless keyphrase handling
- loss of required secrets or `.avkkey` material
- drand or Aavrit outages
- legal or operational misuse by the user

## Operational guidance

- Treat `.avkkey` files as critical recovery material.
- Store the archive and its `.avkkey` separately.
- Keep system time correct when using TimeCapsule, especially drand.
- Do not depend on Aavrit-backed archives without understanding the trust placed in the Aavrit operator.
- The desktop app may use temporary preview-session directories during decryption before cleanup or export.
- Rekey currently supports regular rekey-capable archives only. PQC and provider time-capsule rekey are intentionally rejected in the current phase.

## Reporting a vulnerability

Please report suspected vulnerabilities privately before public disclosure.

Preferred process:

1. Use GitHub private vulnerability reporting if it is enabled.
2. If that is not available, contact the maintainer through a private channel.
3. Include:
   - affected version, release, or commit
   - operating system and runtime details
   - whether the issue affects the desktop app, CLI, or shared archive core
   - reproduction steps
   - expected behavior and actual behavior
   - proof-of-concept material only when necessary

Please do not open a public issue with exploit details before the maintainer has had a reasonable chance to reproduce and address the problem.

## High-value report areas

Reports are especially useful for:

- archive encryption and decryption
- `keychain.pgn` parsing and protected metadata handling
- payload key wrapping and rekey behavior
- `.avkkey` generation and validation
- TimeCapsule verification and unlock routing
- preview-session handling and local filesystem boundaries
- Electron-to-backend trust boundaries
- bundled runtime and OpenSSL PQC integration
