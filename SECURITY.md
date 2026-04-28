# Security Policy

## Scope

This repository contains three security-relevant surfaces:

- the desktop application
- the standalone CLI package
- the shared Python archive core

This repository does not contain the Aavrit server implementation. Aavrit is a separate project. Security reports about Avikal's Aavrit client integration are in scope here; security reports about the Aavrit server itself belong to that separate project once it is published.

## Supported code

This project is in active development. Security fixes are handled on:

- the current default branch
- the latest published desktop release, if one exists
- the latest published CLI package release, if one exists

Older snapshots may not receive backported fixes.

## Current security model

Protected `.avk` archives currently rely on:

- AES-256-GCM for authenticated encryption
- Argon2id-based secret hardening
- HKDF-based key separation and derivation
- archive structure binding through authenticated metadata and header validation

Optional modes add extra requirements:

- Hindi keyphrase mode uses the same protected archive core with a 21-word mnemonic input
- PQC-assisted mode adds a required external `.avkkey` file
- TimeCapsule mode adds delayed-unlock behavior through either `drand` or `Aavrit`

## TimeCapsule trust model

### drand

`drand` is the public release path.

- unlock depends on public drand round availability
- availability depends on external network access
- release timing is tied to the external drand network, not this repository

### Aavrit

`Aavrit` is the managed release path.

- Avikal stores signed commit metadata inside the archive
- unlock requires a signed reveal from the external Aavrit authority
- Avikal verifies commit and reveal material locally before decrypting
- private Aavrit mode depends on server-side authentication and key management

If an Aavrit deployment is misconfigured or compromised, the guarantees of Aavrit-backed release can be weakened independently of the local archive engine.

## What this project does not protect against

This project does not claim to protect against:

- malware, keyloggers, or host compromise
- memory scraping on a compromised machine
- insecure password or keyphrase handling by the user
- loss of required secrets or `.avkkey` material
- external service outages affecting `drand` or `Aavrit`

## Operational cautions

- Treat `.avkkey` files as critical recovery material.
- Store the archive and its `.avkkey` separately.
- Do not depend on Aavrit-backed archives without understanding the trust placed in the Aavrit operator.
- The desktop app may create temporary preview-session directories during decryption.

## Reporting a vulnerability

Please report suspected vulnerabilities privately before public disclosure.

Preferred process:

1. Use GitHub private vulnerability reporting if it is enabled for the repository.
2. If that is not available, contact the maintainer through a private channel.
3. Include:
   - affected version, release, or commit
   - operating system and runtime details
   - whether the issue affects the desktop app, CLI, or shared archive core
   - reproduction steps
   - expected behavior and actual behavior
   - proof-of-concept material only when necessary to reproduce the issue

Please do not open a public issue with exploit details before the maintainer has had a reasonable chance to reproduce and address the problem.

## High-value report areas

Reports are especially useful for:

- archive encryption and decryption
- authenticated metadata and header handling
- `.avkkey` generation and recovery
- TimeCapsule release verification
- local preview-session handling
- Electron-to-backend trust boundaries
