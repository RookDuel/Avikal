# RookDuel Avikal — Technical White Paper & Backend Architecture

> **Document type:** Technical White Paper / Architecture Reference
> **Project:** RookDuel Avikal — Quantum-Resistant Secure Archive System
> **License:** Apache 2.0 · **Contact:** contact@rookduel.tech · **Web:** avikal.rookduel.tech

---

## Executive Summary

RookDuel Avikal is an open-source secure archiving system that addresses three critical gaps in modern data protection: the absence of cryptographically enforced time-locking, vulnerability to future quantum computers, and the poor usability of existing encryption tools for non-technical users.

Avikal packages files into a proprietary `.avk` container using AES-256-GCM authenticated encryption hardened with Argon2id key derivation (256 MiB memory cost). Its distinguishing feature is a novel cross-disciplinary design: encryption key metadata is encoded as a real, legally valid chess game in PGN format — simultaneously disguising the key material and providing authenticated integrity through GCM binding.

For institutional and time-sensitive use cases, Avikal provides two independent time-lock providers: **drand** (a globally distributed public randomness network) and **Aavrit** (an upcoming self-hostable commit/reveal authority). Post-quantum protection is available via ML-KEM-1024 (NIST standard, formerly Kyber-1024), stored in an external `.avkkey` file that never touches the archive container.

The project ships as a Windows desktop application and a cross-platform Python CLI (`pip install avikal`).

---

## The Problem Statement

### 1. Modern archival systems lack enforceable time-locking

Existing file encryption tools (7-Zip, VeraCrypt, GPG) have no mechanism for time-releasing data. Organizations that need to seal records — legal documents, audit trails, competitive submissions, wills, or scheduled disclosures — have no cryptographic primitive to enforce a future release date. A password shared in advance can always be used early.

### 2. Classical encryption is vulnerable to future quantum computers

RSA and ECC-based key exchange schemes that underpin today's archive tools are theoretically broken by Shor's algorithm running on a sufficiently powerful quantum computer. NIST finalized its post-quantum cryptography standards in 2024 (ML-KEM, ML-DSA). Most archiving tools have not yet adopted these standards.

### 3. Usability is a security barrier

Complex encryption UIs force users toward weak practices: short passwords, reused keys, or skipping encryption entirely. Avikal introduces a **21-word Hindi mnemonic keyphrase** in Devanagari script as a user-friendly alternative to raw keys — providing 224 bits of entropy while remaining writable and speakable.

---

## Use Cases

**What is always present in every `.avk` archive** (not optional, not scenario-specific):

- AES-256-GCM authenticated encryption on the payload (except when no password/keyphrase is provided — `plaintext_archive` mode)
- Chess PGN keychain (`keychain.pgn`) — the metadata is always encoded as a chess game; this is the core key storage mechanism, not an optional feature
- Argon2id key derivation (256 MiB memory cost) whenever a password or keyphrase is used
- SHA-256 integrity checksum on the original file
- zlib compression inside the payload stream

**What varies per scenario** (genuinely optional, user-selected):

| Scenario | Who benefits | Optional features activated |
|:---------|:------------|:----------------------------|
| **Sealed legal records** | Law firms, courts | drand TimeCapsule (cryptographic unlock date) |
| **Sealed competitive submissions** | Hackathons, academic institutes | Aavrit TimeCapsule (operator-controlled release) |
| **Scheduled disclosures** | Journalists, publishers | drand public time-lock (no central operator trust) |
| **Long-term sovereign archiving** | Individuals, institutions | Hindi mnemonic keyphrase (224-bit, Devanagari) |
| **Quantum-resistant institutional archives** | Enterprises, government, NGOs | PQC external keyfile (ML-KEM-1024 `.avkkey`) |
| **Multi-file / folder archiving** | Any user with multiple files | Multi-file pipeline (automatic when > 1 file or folder input) |
| **Scripted / CI archiving** | Developers, DevOps | `pip install avikal` CLI (no desktop, no Electron) |

---

## Digital India & Data Sovereignty

RookDuel Avikal contributes to indigenous data-sovereignty infrastructure for Indian institutions and individuals:

- **Devanagari keyphrase system** — the first BIP-39-style mnemonic standard built on a Hindi wordlist (`avikal-hi-2048-v1`), enabling non-English speakers to hold encryption keys in their own language
- **Self-hostable time authority** — the Aavrit time-lock server is designed to be deployable by any Indian institution without dependency on foreign infrastructure
- **Open-source, Apache 2.0** — full auditability; no vendor lock-in; suitable for government and academic use
- **Post-quantum readiness** — aligns with global migration to NIST PQC standards, positioning Indian data archives for long-term cryptographic resilience

---
# RookDuel Avikal — Backend Architecture

This document is a deep technical reference for the Avikal backend system. Every claim here is verified directly from source code. Technical language is used throughout; for a user-facing overview, see `README.md`.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [AVK Container Format](#2-avk-container-format)
3. [Metadata Binary Protocol](#3-metadata-binary-protocol)
4. [Cryptographic Engine](#4-cryptographic-engine)
5. [Hindi Mnemonic Keyphrase System](#5-hindi-mnemonic-keyphrase-system)
6. [Chess PGN Key Encoding](#6-chess-pgn-key-encoding)
7. [Payload Streaming Pipeline](#7-payload-streaming-pipeline)
8. [Encode Pipeline (Full Flow)](#8-encode-pipeline-full-flow)
9. [Decode Pipeline (Full Flow)](#9-decode-pipeline-full-flow)
10. [TimeCapsule System](#10-timecapsule-system)
11. [drand Integration](#11-drand-integration)
12. [Aavrit Integration](#12-aavrit-integration)
13. [Post-Quantum Cryptography (PQC)](#13-post-quantum-cryptography-pqc)
14. [FastAPI Backend Layer](#14-fastapi-backend-layer)
15. [CLI Layer](#15-cli-layer)
16. [Python Package Boundary](#16-python-package-boundary)
17. [Security Design Notes](#17-security-design-notes)

---

## 1. System Overview

Avikal is a layered archive system with two independent user-facing surfaces — a Windows desktop application and a cross-platform Python CLI — sharing one shared Python archive core. The two surfaces have identical cryptographic behavior; what differs is the execution environment and the UX layer around it.

The desktop app bundles an Electron shell that supervises a local FastAPI/Python backend process. The React frontend communicates with this backend over HTTP on `127.0.0.1:5000`. The backend coordinates Aavrit and drand provider flows, manages preview sessions, and delegates all cryptographic work to the shared archive core.

The CLI bypasses the HTTP layer entirely, importing the archive pipeline modules directly. There is no FastAPI process involved in CLI operations.

Both paths converge on the same `archive/pipeline/encoder.py` and `archive/pipeline/decoder.py` modules, which in turn use `archive/security/crypto.py` for all cryptographic primitives. This single-engine design ensures that a `.avk` file created by the CLI can be opened by the desktop app and vice versa.

**See Appendix A for the full component diagram.**

```
┌─────────────────────────────────────────────────────────────────┐
│                        Desktop App                              │
│                                                                 │
│  ┌───────────────┐    ┌──────────────────┐    ┌─────────────┐  │
│  │ Electron Main │───▶│ Preload Bridge   │───▶│ React UI    │  │
│  │ (supervisor)  │    │ (window.electron)│    │ (Vite/TS)   │  │
│  └──────┬────────┘    └──────────────────┘    └──────┬──────┘  │
│         │                                            │ HTTP     │
│         ▼                                            ▼          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │            FastAPI Backend  (127.0.0.1:5000)            │   │
│  │  api/server.py · api/routes.py · preview sessions       │   │
│  └─────────────────────────┬────────────────────────────────┘   │
└────────────────────────────│────────────────────────────────────┘
                             │
                   ┌─────────▼──────────┐
                   │  Shared Archive    │
                   │       Core         │
                   │  archive/pipeline  │
                   │  archive/format    │
                   │  archive/security  │
                   │  chess_metadata    │
                   │  mnemonic          │
                   └─────────┬──────────┘
                             │
              ┌──────────────┘
              │
┌─────────────▼──────────┐
│     CLI (avikal cmd)   │
│   cli/parser.py        │
│   cli/commands/        │
└────────────────────────┘
```

### Key architectural facts (verified from code)

| Fact | Source |
|:---|:---|
| Desktop backend binds to `127.0.0.1:5000` | `api/server.py` — `uvicorn` start |
| CLI does **not** start FastAPI | `cli/main.py` imports `archive.*` directly |
| Both surfaces call the same `archive/pipeline/encoder.py` | Verified in `server.py` and `cli/commands/` |
| `avikal_backend.api.*` is **excluded** from the PyPI package | `pyproject.toml` package includes |
| A global `threading.Lock()` serializes all crypto operations | `server.py` line 79: `_crypto_lock = threading.Lock()` |
| Preview session files live in a process-level directory | `server.py` → `PreviewSessionStore(_PREVIEW_SESSION_ROOT)` |


---

## 2. AVK Container Format

Source: `archive/format/container.py`, `archive/format/header.py`

A `.avk` file is a **ZIP archive** containing exactly three members. Strict member validation is enforced before any decryption is attempted.

### 2.1 Container structure

```
my_archive.avk  (ZIP container)
├── header.bin      ← 8 bytes, binary control plane
├── keychain.pgn    ← Chess PGN text, encrypted metadata
└── payload.enc     ← Streaming AES-256-GCM encrypted payload
```

The validation rule (from `container.py::_validate_avk_zip`):

```python
REQUIRED_AVK_MEMBERS = {"header.bin", "keychain.pgn", "payload.enc"}
MAX_KEYCHAIN_BYTES = 256 * 1024   # 256 KB hard cap
```

- Duplicate member names → rejected immediately
- Any extra or missing member → rejected
- `header.bin` must be exactly `HEADER_SIZE = 8` bytes
- `keychain.pgn` must decode as valid UTF-8
- `payload.enc` must be non-empty

### 2.2 header.bin binary layout

Source: `archive/format/header.py::build_header_bytes` / `parse_header_bytes`

```
struct format: >4sBBBB   (big-endian)

Offset  Size  Field             Values
──────  ────  ───────────────   ──────────────────────────────────
0       4 B   magic             b"AVK2"  (HEADER_MAGIC)
4       1 B   format_version    0x01    (HEADER_FORMAT_VERSION)
5       1 B   archive_mode      0x01 = single-file, 0x02 = multi-file
6       1 B   structure_id      0x01    (always HEADER_STRUCTURE_ID)
7       1 B   provider_id       0x00 = none, 0x02 = drand, 0x03 = aavrit
```

Total: **8 bytes exactly**.

The `header_bytes` are also passed as **AAD (Additional Authenticated Data)** into every AES-256-GCM call, cryptographically binding the header to the ciphertext. If the header is tampered with, GCM authentication fails.

### 2.3 Provider ID mapping

```python
PROVIDER_ID_NONE   = 0x00   # regular archive or NTP time-lock
PROVIDER_ID_DRAND  = 0x02   # drand public randomness network
PROVIDER_ID_AAVRIT = 0x03   # Aavrit commit/reveal authority
```

### 2.4 Container validation cross-check

After decrypting `keychain.pgn`, the backend calls `validate_metadata_against_header()` which cross-checks:

- `archive_mode` in header == `archive_type` in metadata (`single_file` / `multi_file`)
- `provider_id` in header == `timecapsule_provider` in metadata

Any disagreement raises `ValueError` and decryption halts.


---

## 3. Metadata Binary Protocol

Source: `archive/format/metadata_pack.py` · `archive/format/metadata_unpack.py`

The binary metadata packet is the archive's control record. It is packed into bytes, then encrypted and encoded as Chess PGN into `keychain.pgn`. Maximum size: **10 KB** (enforced in `pack_cascade_metadata`).

### 3.1 Metadata version table

The version byte determines which optional fields are present in the binary stream:

| Version | Hex  | Triggered by |
|:--------|:-----|:-------------|
| 4       | 0x04 | Standard archive (convenience timelock) |
| 5       | 0x05 | Standard archive (secure timelock mode) |
| 7       | 0x07 | TimeCapsule with external provider |
| 8       | 0x08 | PQC external keyfile required |
| 9       | 0x09 | Multi-file archive with manifest binding |
| 10      | 0x0A | Keyphrase-protected archive |
| 11      | 0x0B | Keyphrase + multi-file manifest |
| 12      | 0x0C | Aavrit TimeCapsule (requires manifest binding) |

### 3.2 Binary field layout (sequential, big-endian)

```
Field                       Size        Present in version
──────────────────────────  ──────────  ──────────────────────────
version                     1 B         all
flags                       1 B         all  (bit0=keyphrase_protected)
method_len                  1 B         all
encryption_method           variable    all  (e.g. "aes256gcm_stream")
payload_salt                32 B        all  (Argon2id salt)
chess_salt                  32 B        all  (chess key derivation salt)
pqc_ciphertext_len          4 B (>I)    all
pqc_ciphertext              variable    all  (empty if PQC disabled)
pqc_private_key_len         4 B (>I)    all  (always 0 — key is external)
pqc_private_key             variable    all  (always empty)
unlock_timestamp            4 B (>I)    all  (Unix UTC timestamp)
checksum                    32 B        all  (SHA-256 of original file)
filename_len                1 B         all
filename                    variable    all  (UTF-8, max 255 bytes)
── version >= 0x05 ───────────────────────────────────────────────
timelock_mode_len           1 B         >= 0x05
timelock_mode               variable    >= 0x05  ("convenience"/"secure")
file_id_len                 1 B         >= 0x05
file_id                     variable    >= 0x05  (provider commit ID)
server_url_len              2 B (>H)    >= 0x05
server_url                  variable    >= 0x05  (provider endpoint)
has_time_key_hash           1 B         >= 0x05  (0 or 1)
time_key_hash               32 B        >= 0x05  (SHA-256 of Key B)
── version >= 0x07 ───────────────────────────────────────────────
timecapsule_provider_len    1 B         >= 0x07
timecapsule_provider        variable    >= 0x07  ("drand"/"aavrit")
has_drand_round             1 B         >= 0x07
drand_round                 8 B (>Q)    >= 0x07  (if present)
drand_chain_hash_len        1 B         >= 0x07
drand_chain_hash            variable    >= 0x07
drand_chain_url_len         2 B (>H)    >= 0x07
drand_chain_url             variable    >= 0x07
drand_ciphertext_len        2 B (>H)    >= 0x07
drand_ciphertext            variable    >= 0x07  (tlock ciphertext)
drand_beacon_id_len         1 B         >= 0x07
drand_beacon_id             variable    >= 0x07
── version >= 0x08 ───────────────────────────────────────────────
pqc_required                1 B         >= 0x08  (0 or 1)
pqc_algorithm_len           1 B         >= 0x08
pqc_algorithm               variable    >= 0x08  ("ml-kem-1024")
pqc_key_id_len              1 B         >= 0x08
pqc_key_id                  variable    >= 0x08  (SHA-256 hex binding ID)
── version in {0x09, 0x0B, 0x0C} ────────────────────────────────
archive_type_len            1 B         manifest versions
archive_type                variable    manifest versions
entry_count                 4 B (>I)    manifest versions
total_original_size         8 B (>Q)    manifest versions
manifest_hash               32 B        manifest versions
── version in {0x0A, 0x0B, 0x0C} ────────────────────────────────
keyphrase_format_version    1 B         keyphrase versions  (=1)
keyphrase_wordlist_id_len   1 B         keyphrase versions
keyphrase_wordlist_id       variable    keyphrase versions  ("avikal-hi-2048-v1")
── version >= 0x0C ───────────────────────────────────────────────
aavrit_data_hash_len        1 B         0x0C
aavrit_data_hash            variable    0x0C  (max 128 bytes)
aavrit_commit_hash_len      1 B         0x0C
aavrit_commit_hash          variable    0x0C  (max 128 bytes)
aavrit_server_key_id_len    1 B         0x0C
aavrit_server_key_id        variable    0x0C  (max 128 bytes)
aavrit_commit_sig_len       2 B (>H)    0x0C
aavrit_commit_signature     variable    0x0C  (max 1024 bytes, Ed25519)
```

### 3.3 Key invariants enforced by pack_cascade_metadata

- `pqc_private_key` must always be empty (`b""`). PQC private keys are **never** embedded in the archive; they live in the external `.avkkey` file.
- Version `0x0C` always requires manifest binding fields — an Aavrit archive without `archive_type`, `entry_count`, `total_original_size`, and `manifest_hash` is invalid.
- Keyphrase wordlist must always be `"avikal-hi-2048-v1"` — hardcoded binding to the Hindi wordlist.


---

## 4. Cryptographic Engine

Source: `archive/security/crypto.py`

Library: `cryptography` (PyCA — Python Cryptographic Authority)

### 4.1 Argon2id key derivation

All password/keyphrase material is processed through Argon2id before touching AES:

```
Parameters (from crypto.py constants):
  ARGON2_SALT_BYTES      = 32
  ARGON2_OUTPUT_BYTES    = 32
  ARGON2_ITERATIONS      = 3
  ARGON2_LANES           = 4
  ARGON2_MEMORY_COST_KIB = 262144   ← 256 MiB
```

The `_normalize_secret_input()` function combines password and keyphrase into a single canonical byte string:

```
combined = password + "|" + " ".join(canonical_keyphrase_words)
```

This is fed as the input to Argon2id, producing a **32-byte master key**.

### 4.2 Hierarchical key expansion (HKDF)

From `derive_hierarchical_keys()`:

```
master_key, salt = Argon2id(combined_secret, salt, 256MiB)
                         │
            ┌────────────┴────────────┐
            ▼                         ▼
HKDF(master_key, info="avikal_payload_v3")   HKDF(master_key, info="avikal_chess_v3")
            │                         │
     payload_key (32B)         chess_key (32B)
```

- `payload_key` encrypts `payload.enc`
- `chess_key` encrypts the metadata inside `keychain.pgn`
- Both are derived from the same Argon2id master but with distinct HKDF `info` labels, ensuring key separation

### 4.3 AES-256-GCM encryption

```python
def encrypt_payload(data, key, aad):
    nonce = secrets.token_bytes(12)          # fresh 12-byte random nonce per call
    aesgcm = AESGCM(key)                     # from cryptography.hazmat
    ciphertext = aesgcm.encrypt(nonce, data, associated_data=aad)
    return nonce + ciphertext                # [12B nonce][ciphertext+16B GCM tag]
```

- GCM tag (16 B) provides authenticated integrity — any bit-flip in ciphertext or AAD causes `InvalidTag`
- `header_bytes` is always passed as AAD, cryptographically binding the header to the payload

### 4.4 Split-key architecture for TimeCapsule

TimeCapsule archives use a two-key split:

```
Key A = derive_hierarchical_keys(password, keyphrase, salt)[1]  ← user holds
Key B = provider_held_time_key (32 random bytes)                 ← provider holds

combined = HKDF(Key_A + Key_B, info="avikal_split_key_v1", length=64)
payload_key = combined[:32]
```

- Neither key alone can decrypt the payload
- `SHA-256(Key_B)` is stored in metadata as `time_key_hash` to verify the provider returns the correct key

### 4.5 Time-only TimeCapsule (no user password)

```python
def derive_time_only_payload_key(time_key: bytes, salt: bytes) -> bytes:
    return HKDF(time_key, info="avikal_time_only_payload_v1", length=32)
```

Used when `encryption_method == "aes256gcm_stream_timekey"` — the provider holds the only key.

### 4.6 PQC hybrid key derivation

When PQC is enabled, the `payload_key` is further derived:

```python
def derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt):
    return HKDF(payload_key + pqc_shared_secret, info="avikal_payload_pqc_v1", length=32)
```

This means decryption requires both the password-derived key **and** the ML-KEM shared secret from the `.avkkey` file.

### 4.7 Memory zeroing

After every crypto operation, all sensitive key material is overwritten:

```python
def secure_zero(data):
    if isinstance(data, bytearray):
        for i in range(len(data)): data[i] = 0   # in-place zero
    else:
        ctypes.memset(id(data) + 32, 0, len(data))  # best-effort for immutable bytes
    gc.collect()
```

This is explicitly called on `master_key`, `payload_key`, `pqc_shared_secret`, `pqc_private_key`, and `password.encode()` in both the encoder and decoder pipelines.

### 4.8 Password validation

Source: `archive/security/password_validator.py`

Rules enforced before archive creation:
- Minimum 12 characters
- Must contain lowercase, uppercase, digit, and symbol
- Blocked against a common-password set (hardcoded top ~40 passwords)
- Keyboard patterns (`qwerty`, `asdfgh`, `123456`, etc.) are rejected
- Sequential number runs of 3+ are rejected
- Repeated characters (3+ same in a row) are rejected

Entropy is calculated as `len(password) * log2(charset_size)` with penalties applied for patterns and common passwords, returning a 0–100 strength score for the UI.


---

## 5. Hindi Mnemonic Keyphrase System

Source: `mnemonic/generator.py` · `mnemonic/wordlist.py`

### 5.1 Wordlist and entropy

| Property | Value |
|:---------|:------|
| Wordlist ID | `avikal-hi-2048-v1` |
| Wordlist size | 2048 Hindi words (Devanagari) |
| Supported lengths | 12, 15, 18, 21, 24 words |
| Default length | 21 words |
| Entropy at 21 words | 224 bits (21 × ~10.67 bits per word) |
| Bits per word | 11 bits (2^11 = 2048) |

### 5.2 Generation algorithm

```
1. entropy = secrets.token_bytes(224 // 8)       ← 28 bytes of CSPRNG entropy
2. checksum_bits = SHA-256(entropy)[:7]           ← 7 bits (224/32)
3. full_bits = bits(entropy) + checksum_bits      ← 231 bits
4. indices = [full_bits[i:i+11] for i in 0,11,22...] ← 21 indices
5. words = [wordlist[idx] for idx in indices]
```

This is structurally identical to BIP-39 but uses a Hindi Devanagari wordlist instead of English.

### 5.3 Validation

`validate_or_raise()` performs:
1. Normalize all words via `normalize_hindi_word()` (Unicode NFC + strip)
2. Verify each word exists in the 2048-word list
3. Reconstruct bit sequence from word indices
4. Re-derive checksum from entropy portion
5. Compare stored checksum to re-derived — mismatch → `ValueError("Checksum mismatch")`

### 5.4 Key conversion

```python
def to_seed(mnemonic, salt):
    mnemonic_str = " ".join(canonical_words)
    return Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=262144).derive(mnemonic_str)
```

The same Argon2id parameters as the password path are used, ensuring equivalent brute-force resistance.

---

## 6. Chess PGN Key Encoding

Source: `archive/chess_metadata.py` · `chess/board.py` · `chess_codec/`

### 6.1 What it does

The binary metadata packet (~100–500 bytes) is serialized as a **real, legally valid chess game in PGN format**. The game is stored as `keychain.pgn` inside the `.avk` ZIP.

This is not steganography in the traditional sense — the PGN contains the data deterministically encoded into the sequence of legal chess moves.

### 6.2 Encoding pipeline

```
metadata_bytes (binary)
       │
       ▼
1. Prepend marker: b'TMCPSULE' (TimeCapsule) or b'AVKLFILE' (regular)
2. Prepend 4-byte unlock timestamp (struct.pack('>I', ts))
3. tc_payload = marker + timestamp + metadata_bytes
       │
       ▼ (if password/keyphrase provided)
4. chess_salt = secrets.token_bytes(32)
5. chess_key = Argon2id(password+keyphrase, chess_salt, 256MiB)
6. nonce1 = secrets.token_bytes(12)
7. encrypted_payload = AES-256-GCM(chess_key).encrypt(nonce1, tc_payload, aad=header_bytes)
8. final_payload = chess_salt + nonce1 + encrypted_payload
       │
       ▼
9. format_byte = b'\x02' (encrypted) or b'\x03' (plaintext)
10. num = int.from_bytes(format_byte + final_payload, 'big')
11. pgn_string = ChessGenerator(variations_per_round=5).encode_to_pgn(num)
```

### 6.3 Chess engine (board.py)

The project contains a **full chess rules engine** (`chess/board.py`, 602 lines):

- Complete legal move generation for all piece types (pawns, knights, bishops, rooks, queens, kings)
- En passant, castling, promotion
- Check, checkmate, stalemate detection
- FEN parsing and generation
- SAN (Standard Algebraic Notation) encoding with disambiguation

The `ChessGenerator` uses the legal move list at each position to encode bits into move choices. With `variations_per_round=5`, each position offers up to 5 encoded choices, carrying `log2(5) ≈ 2.32` bits per move.

### 6.4 Decoding pipeline

```
pgn_string
    │
    ▼
1. PGNDecoder.decode_from_pgn(pgn_string) → integer
2. num_bytes = num.to_bytes(...)
3. format_byte = num_bytes[0]
   - 0x02: encrypted path → extract chess_salt (32B) + nonce (12B) + ciphertext
   - 0x03: plaintext path → tc_payload = num_bytes[1:]
       │
       ▼ (0x02 path)
4. chess_key = Argon2id(password+keyphrase, chess_salt)
5. tc_payload = AES-256-GCM(chess_key).decrypt(nonce, ciphertext, aad=header_bytes)
       │
       ▼
6. marker = tc_payload[0:8]
   - b'TMCPSULE' → TimeCapsule: check unlock_timestamp against trusted NTP
   - b'AVKLFILE' → regular archive
7. metadata_bytes = tc_payload[12:]
8. unpack_cascade_metadata(metadata_bytes) → dict
```

### 6.5 Why chess?

The chess PGN layer provides:
- **Structural disguise**: `keychain.pgn` is a valid, playable chess game
- **Authenticated encryption**: AES-256-GCM with `header_bytes` as AAD means tampering with the header also breaks `keychain.pgn` decryption
- **Independent key**: The chess key is derived with its own `chess_salt` separate from the payload key, even though both come from the same Argon2id master


---

## 7. Payload Streaming Pipeline

Source: `archive/pipeline/payload_streaming.py`

### 7.1 payload.enc internal format

```
struct format: >4sBBH12s16s    (PAYLOAD_HEADER_STRUCT, 36 bytes)

Offset  Size  Field        Notes
──────  ────  ───────────  ──────────────────────────────────────
0       4 B   magic        b"AVP2"
4       1 B   version      0x01
5       1 B   flags        bit0=COMPRESSED_ZLIB, bit1=ENCRYPTED_AESGCM
6       2 B   reserved     always 0x0000
8       12 B  nonce        AES-GCM nonce (zeroed if not encrypted)
20      16 B  gcm_tag      AES-GCM authentication tag (zeroed if not encrypted)
36+     var   ciphertext   zlib-compressed, then AES-GCM encrypted data
```

### 7.2 Write path (stream_file_to_payload)

The encoder streams the file in **10 MB chunks** (DEFAULT_STREAM_CHUNK_SIZE):

```
source file (disk)
    │ 10MB chunks
    ▼
zlib.compressobj(level=6) ← compress chunk
    │
    ▼
AES-256-GCM encryptor.update(compressed_chunk) ← encrypt chunk (if key provided)
    │
    ▼
write to temp payload file (.avikal-payload-XXXX.payload)
    │
    ▼ (after all chunks)
encryptor.finalize() → GCM tag
rewrite header: seek(0), write tag into header offset 20
```

SHA-256 checksum is computed over the **original plaintext** (pre-compression) during streaming and stored in metadata for integrity verification on decode.

### 7.3 Read path (stream_payload_to_file)

```
payload.enc stream
    │
    ▼
parse_payload_header() → flags, nonce, gcm_tag
    │
    ▼
AES-256-GCM decryptor(nonce, tag) with AAD=header_bytes
    │ 10MB chunks
    ▼
decryptor.update(chunk) → plaintext compressed chunk
    │
    ▼
zlib.decompressobj().decompress(plaintext_chunk)
    │
    ▼
write to temp file (.avikal-dec-XXXX.tmp)
    │
    ▼ (after all chunks)
decryptor.finalize() → raises InvalidTag if authentication fails
SHA-256(decompressed) == stored_checksum? → os.replace(tmp, output)
```

Atomic replace (`os.replace`) means partial output is never visible if decryption fails.

### 7.4 Compression strategy

Source: `archive/compression.py`

Adaptive Brotli quality selection based on file extension and size:

| Condition | Brotli quality |
|:----------|:--------------|
| Known incompressible extension (`.jpg`, `.mp4`, `.zip`, etc.) | 1 (fastest) |
| File >= 128 MB | 2 |
| File >= 32 MB | 3 |
| File >= 8 MB | 4 |
| File >= 1 MB | 6 |
| Small files | 8 (best ratio) |

Decompression bomb protection: max decompressed size = **2 GiB**, max ratio = **100,000:1**.

Note: The streaming pipeline uses `zlib` (not Brotli) for the payload stream for compatibility. Brotli is available for other compression contexts.

---

## 8. Encode Pipeline (Full Flow)

Source: `archive/pipeline/encoder.py::create_avk_file_enhanced`

```
Input: file path, password, keyphrase, options

Step 1: Validate keyphrase (normalize_mnemonic_words)
Step 2: Validate PQC constraints (PQC requires user secret)
Step 3: Validate TimeCapsule (unlock_datetime must be future, NTP verified)
Step 4: Generate random salt (32 bytes, secrets.token_bytes)
Step 5: Build header_bytes (build_header_bytes → 8B, big-endian)

Step 6: Key derivation
   if user_secret:
       master_key, payload_key, chess_key, _ = derive_hierarchical_keys(pw, kp, salt)
       if timecapsule and time_key (Key B):
           combined = combine_split_keys(payload_key, time_key, salt)
           payload_key = combined[:32]
       if pqc_enabled:
           payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)
   elif timecapsule (no password):
       payload_key = derive_time_only_payload_key(time_key, salt)
   else:
       payload_key = None  (plaintext_archive)

Step 7: PQC keypair (if enabled)
   public_key, private_key = ml_kem_1024.generate_keypair()
   pqc_ciphertext, pqc_shared_secret = ml_kem_1024.encrypt(public_key)
   pqc_key_id = SHA-256(public_key + pqc_ciphertext).hexdigest()

Step 8: stream_file_to_payload → temp file (.avikal-payload-*.payload)
   zlib compress + AES-256-GCM encrypt, 10MB chunks
   returns: original_checksum (SHA-256), compressed_size

Step 9: pack_cascade_metadata(salt, pqc_ciphertext, None, unlock_timestamp,
         filename, checksum, encryption_method, keyphrase_protected,
         all provider fields...)

Step 10: encode_metadata_to_chess_enhanced(metadata_bytes, password, keyphrase,
          variations_per_round=5, use_timecapsule, aad=header_bytes)
       → keychain_pgn (string)

Step 11: Write ZIP container to temp file (.avikal-archive-*.avk)
   zf.writestr("header.bin",    header_bytes,  ZIP_DEFLATED)
   zf.writestr("keychain.pgn",  keychain_pgn,  ZIP_DEFLATED)
   zf.write(temp_payload_path, "payload.enc",  ZIP_STORED)
   ↑ payload.enc is ZIP_STORED (no double compression — already compressed inside)

Step 12: If PQC: write_pqc_keyfile(path, password, keyphrase, private_key, ...)

Step 13: os.replace(temp_archive, output_filepath)  ← atomic rename

Step 14: secure_zero(master_key, payload_key, pqc_shared_secret, pqc_private_key, ...)
```

### 8.1 Encryption method strings

| Method string | Meaning |
|:---|:---|
| `"aes256gcm_stream"` | Password/keyphrase protected |
| `"aes256gcm_stream_timekey"` | Time-key only (no user secret) |
| `"plaintext_archive"` | No encryption |


---

## 9. Decode Pipeline (Full Flow)

Source: `archive/pipeline/decoder.py` · `api/server.py::decrypt_timecapsule_with_key`

```
Input: .avk file path, password, keyphrase, pqc_keyfile (optional)

Step 1: read_avk_container(avk_filepath)
   → structural validation (exactly 3 members, sizes, magic)
   → header_bytes (8B), keychain_pgn (UTF-8 text), encrypted_payload (bytes)

Step 2: parse_header_bytes(header_bytes)
   → magic, format_version, archive_mode, provider_id, aad

Step 3: decode_chess_to_metadata_enhanced(keychain_pgn, password, keyphrase,
          skip_timelock=False, aad=header_bytes)
   → PGN decode → integer → bytes → AES-GCM decrypt chess layer
   → unpack_cascade_metadata → metadata dict

Step 4: validate_metadata_against_header(header_info, metadata)
   → cross-check archive_mode and provider match

Step 5: Provider routing
   if provider == "drand":  → drand unlock path
   if provider == "aavrit": → aavrit unlock path
   else:                    → direct decrypt path

Step 6 (direct): Key re-derivation
   master_key, payload_key, _, salt = derive_hierarchical_keys(pw, kp, metadata["salt"])
   if pqc_required:
       pqc_bundle = read_pqc_keyfile(keyfile, password, keyphrase, expected_key_id)
       pqc_shared_secret = ml_kem_1024.decrypt(pqc_bundle.private_key, pqc_ciphertext)
       payload_key = derive_pqc_hybrid_payload_key(payload_key, pqc_shared_secret, salt)

Step 7: stream_payload_to_file(payload_stream, output_path, aad=header_bytes,
          decrypt_key=payload_key, expected_checksum=metadata["checksum"])
   → AES-256-GCM streaming decrypt + zlib decompress + SHA-256 verify

Step 8: secure_zero all key material
```

---

## 10. TimeCapsule System

Source: `archive/security/time_lock.py` · `services/ntp_service.py`

### 10.1 Trusted time acquisition

System clock is **never** used as a trust source for TimeCapsule validation. The priority order:

```
1. UDP NTP → time.google.com:123
   - raw NTP packet (48 bytes), LI=0, VN=3, Mode=3 (client)
   - extracts transmit timestamp from response bytes 40–47
   - converts from NTP epoch (1900) to Unix epoch (-2208988800)
   - 10-second socket timeout

2. HTTPS Date-header fallback → backend NTP service
   - GET request to a trusted HTTPS endpoint
   - parses the HTTP Date: response header
   - used only if UDP NTP fails

3. Failure → ConnectionError (no system time fallback)
```

### 10.2 Lock validation (decode side)

```python
def validate_unlock_time(unlock_timestamp: int) -> bool:
    current_time = get_trusted_now_ntp()
    unlock_time = datetime.fromtimestamp(unlock_timestamp, tz=UTC)
    return current_time >= unlock_time
```

If NTP is unreachable during decode, `ConnectionError` is raised — the archive cannot be opened even if the system clock shows the time has passed.

### 10.3 Unlock datetime constraints (API layer)

```
- unlock_datetime must be in the future (verified against NTP)
- Maximum lock duration: 5 years from current NTP time
- Clock skew warning logged if detected
```

---

## 11. drand Integration

Source: `api/drand.py` · `scripts/drand_timelock_helper.mjs`

### 11.1 What drand is

drand (Distributed Randomness) is a decentralized network that produces publicly verifiable, unbiasable random beacons on a fixed schedule. Each beacon has a **round number**. Future beacons are cryptographically unpredictable.

The drand **tlock** scheme encrypts data to a future round's beacon — the data cannot be decrypted until the network reaches that round.

### 11.2 Seal flow (encrypt)

```
api/server.py::create_timecapsule_via_drand

1. key_b = generate_key_b()               ← 32 random bytes (Key B)
2. unlock_timestamp = int(unlock_dt.timestamp())
3. drand_helper({"action": "seal",
                 "unlock_timestamp": unlock_timestamp,
                 "key_b_base64": base64(key_b)})
   → runs scripts/drand_timelock_helper.mjs via subprocess
   → mjs script calculates target drand round for timestamp
   → tlock-encrypts key_b to that round
   → returns: round, chain_hash, chain_url, ciphertext, beacon_id

4. All drand fields stored in metadata (version >= 0x07)
5. key_b used as time_key in create_avk_file_enhanced()
```

### 11.3 Unseal flow (decrypt)

```
1. drand_helper({"action": "unseal", "drand_ciphertext": ..., "round": ...})
   → mjs requests current beacon from drand network
   → if round not reached: returns {"status": "locked", "unlock_iso": ...}
   → if reached: decrypts key_b from tlock ciphertext

2. key_b verified: SHA-256(key_b) == metadata["time_key_hash"]

3. payload_key re-derived from key_b + user password (combine_split_keys)
4. payload decrypted normally
```

### 11.4 Node.js subprocess boundary

The drand integration uses the `drand-client` npm library which has no Python equivalent. The Python backend invokes `node scripts/drand_timelock_helper.mjs` as a subprocess with JSON piped to stdin and reads JSON from stdout. Timeout: **60 seconds**.

---

## 12. Aavrit Integration

Source: `api/aavrit_client.py` · `api/aavrit_crypto.py` · `api/server.py`

### 12.1 What Aavrit is

Aavrit is an upcoming RookDuel project — a self-hostable time-release authority based on a signed commit/reveal model. It is **not** in this repository.

Avikal implements the client side only.

### 12.2 Aavrit API endpoints used

| Endpoint | Method | Purpose |
|:---------|:-------|:--------|
| `GET /config` | GET | Detect public vs private mode |
| `GET /public-key` | GET | Fetch Ed25519 signing key |
| `POST /commit` | POST | Register a time-lock commitment |
| `POST /reveal` | POST | Request unlock (after time passes) |
| `POST /auth/login` | POST | Private mode authentication |
| `POST /auth/verify` | POST | Verify session token |
| `POST /auth/logout` | POST | Invalidate session |

### 12.3 Commit flow (encrypt)

```
1. validate unlock_datetime against NTP
2. GET /config → mode ("public" or "private")
3. if private: require valid session token (X-Aavrit-Session header)
4. data_hash = create_aavrit_data_hash()    ← random UUID-based hash
5. POST /commit {data_hash, unlock_timestamp} → signed commit response
6. GET /public-key → Ed25519 public key PEM
7. verify_aavrit_signature(commit_payload, commit_signature, public_key_pem)
   ← local Ed25519 verification, no trust in unsigned responses
8. Verify: commit_payload.data_hash == data_hash (round-trip check)
9. Verify: commit_payload.unlock_timestamp == requested timestamp
10. key_b = derive_aavrit_time_key(commit_payload, commit_signature)
    ← HKDF over commit JSON + signature bytes
11. Embed all Aavrit fields in archive metadata (version 0x0C)
```

### 12.4 Reveal flow (decrypt)

```
1. Read metadata from archive (skip_timelock=True for metadata-only read)
2. Reconstruct commit_payload dict from archive metadata
3. GET /public-key from stored server_url
4. verify_aavrit_signature(commit_payload, stored_commit_signature, public_key)
5. POST /reveal {commit_id} → signed reveal response
6. verify_aavrit_signature(reveal_payload, reveal_signature, public_key)
7. Cross-verify: reveal_payload.commit_id == metadata.commit_id
8. Cross-verify: reveal_payload.data_hash == metadata.aavrit_data_hash
9. Cross-verify: reveal_payload.commit_hash == metadata.aavrit_commit_hash
10. Cross-verify: reveal_payload.unlock_timestamp == metadata.unlock_timestamp
11. key_b = derive_aavrit_time_key(commit_payload, commit_signature)
    ← same deterministic derivation as during commit
12. Proceed with split-key decryption
```

### 12.5 Aavrit session state

The Aavrit session token is stored in **process-global Python variables** in `server.py`:

```python
current_aavrit_session_token = None
current_aavrit_server_url = None
current_aavrit_mode = None
```

This means session state is lost on backend restart. The frontend must re-authenticate or pass the session via `X-Aavrit-Session` header.

### 12.6 Signature verification (local)

Source: `api/aavrit_crypto.py`

All Aavrit responses are verified locally using Ed25519 before any key material is derived:

```python
def verify_aavrit_signature(payload: dict, signature: str, public_key_pem: str):
    public_key = load_pem_public_key(public_key_pem)   # Ed25519PublicKey
    payload_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
    sig_bytes = base64.b64decode(signature)
    public_key.verify(sig_bytes, payload_bytes)         # raises InvalidSignature if wrong
```

Avikal never decrypts or derives keys from an unsigned Aavrit response.

---

## 13. Post-Quantum Cryptography (PQC)

Source: `archive/security/crypto.py` · `archive/security/pqc_keyfile.py`

Library: `pqcrypto==0.4.0` (ML-KEM-1024 / Kyber-1024)

### 13.1 Algorithm

ML-KEM-1024 (Module Lattice-based Key Encapsulation Mechanism) is the NIST-standardized post-quantum KEM algorithm, formerly known as Kyber-1024.

### 13.2 External keyfile design

The PQC private key **is never stored inside the `.avk` container**. Instead:

```
archive.avk          → contains: pqc_ciphertext, pqc_key_id, pqc_algorithm
archive.avkkey       → contains: AES-GCM encrypted { private_key, public_key }
```

The `.avkkey` file format (JSON):

```json
{
  "format": "avikal-pqc-keyfile",
  "version": 1,
  "algorithm": "ml-kem-1024",
  "key_id": "<SHA-256(public_key + pqc_ciphertext).hexdigest()>",
  "salt": "<base64 32B>",
  "nonce": "<base64 12B>",
  "ciphertext": "<base64 AES-GCM encrypted inner payload>"
}
```

The inner payload (after AES-GCM decryption) is JSON containing `private_key` and `public_key` as base64.

### 13.3 Keyfile encryption

```
keyfile_key = HKDF(Argon2id(password+keyphrase, salt), info="avikal_pqc_keyfile_v1")
ciphertext = AES-256-GCM(keyfile_key).encrypt(nonce, inner_payload_json, aad=format|version|algorithm|key_id)
```

The AAD binds the outer document fields to the ciphertext — changing the `key_id` or `algorithm` in the outer JSON invalidates the inner decryption.

### 13.4 Key ID binding

```python
def compute_pqc_key_id(public_key, pqc_ciphertext):
    return hashlib.sha256(public_key + pqc_ciphertext).hexdigest()
```

This ID is stored in both the `.avk` metadata and the `.avkkey` file. On decryption, `expected_key_id` from the archive metadata is matched against the keyfile `key_id` — a mismatch raises `ValueError("PQC keyfile does not match this archive")`.


---

## 14. FastAPI Backend Layer

Source: `api/server.py` · `api/routes.py` · `api/preview_sessions.py`

### 14.1 Server startup

`backend/api_server.py` → imports `avikal_backend.api.server` → `uvicorn.run(app, host="127.0.0.1", port=5000)`

CORS is configured to allow only specific origins (localhost dev origins). Credentials are allowed for Aavrit session cookie propagation.

### 14.2 Concurrency model

A single `threading.Lock()` (`_crypto_lock`) serializes all encryption and decryption operations to prevent file-level race conditions. FastAPI is run with a single Uvicorn worker.

### 14.3 Key API routes

| Route | Method | What it does |
|:------|:-------|:-------------|
| `GET /health` | GET | Electron polls this to detect backend readiness |
| `POST /api/encrypt` | POST | Route to regular, drand, or Aavrit encrypt path |
| `POST /api/decrypt` | POST | Route to regular, drand, or Aavrit decrypt path |
| `POST /api/archive/inspect` | POST | Read metadata without full decrypt (skip_timelock=True) |
| `POST /api/mnemonic/generate` | POST | Generate Hindi keyphrase |
| `POST /api/aavrit/login` | POST | Authenticate to private Aavrit server |
| `POST /api/aavrit/verify-session` | POST | Verify session token |
| `POST /api/aavrit/logout` | POST | Clear session state |
| `POST /api/aavrit/check-server` | POST | Probe Aavrit server capabilities |
| `DELETE /api/preview/:session_id` | DELETE | Clean up preview session |

### 14.4 Preview session system

Source: `api/preview_sessions.py`

When the desktop app decrypts a file, output goes into a **preview session directory** under `_PREVIEW_SESSION_ROOT`. Files are not written to the user's chosen output directory until they explicitly trigger extraction.

```
_PREVIEW_SESSION_ROOT/
└── <uuid4>/             ← one per decrypt operation
    └── decrypted files
```

Stale sessions are cleaned up on backend startup (`cleanup_stale_preview_sessions()`).

### 14.5 Encrypt request routing logic

```python
if request.use_timecapsule:
    provider = resolve_timecapsule_provider(request)  # "aavrit" or "drand"
    if provider == "aavrit":
        return create_timecapsule_via_aavrit(request, session_token, unlock_dt)
    elif provider == "drand":
        return create_timecapsule_via_drand(request, unlock_dt)
else:
    return create_regular_encryption(request, unlock_dt)
```

Multi-file vs single-file routing:

```python
def _should_use_multi_file_archive(input_files):
    if len(input_files) > 1:
        return True
    if len(input_files) == 1 and os.path.isdir(input_files[0]):
        return True
    return False
```

---

## 15. CLI Layer

Source: `cli/parser.py` · `cli/commands/` · `cli/main.py`

### 15.1 Entry points

```
avikal          → avikal_backend.cli.main:main
python -m avikal_backend     → cli/__main__.py → main()
python -m avikal_backend.cli → cli/__main__.py → main()
```

### 15.2 Command table

| Command | Aliases | Archive operation |
|:--------|:--------|:------------------|
| `encode` | `enc` | Create `.avk` archive |
| `decode` | `dec`, `extract` | Decrypt and extract `.avk` |
| `inspect` | `info` | Read and display archive metadata |
| `contents` | `ls`, `list` | List files inside archive |
| `validate` | `check` | Verify archive structure and checksum |
| `doctor` | `diag` | Check runtime dependencies and Aavrit connectivity |

### 15.3 CLI architecture

The CLI calls `archive/pipeline/encoder.py` and `archive/pipeline/decoder.py` directly — no HTTP, no FastAPI. This means the CLI has identical cryptographic behavior to the desktop app but without the preview session layer or Aavrit session management.

### 15.4 CLI vs API behavioral differences

| Capability | Desktop API | CLI |
|:-----------|:------------|:----|
| Aavrit TimeCapsule creation | ✅ Full flow | ❌ Not supported |
| drand TimeCapsule creation | ✅ Full flow | ✅ Supported |
| Preview sessions | ✅ Desktop-specific | ❌ Direct file output |
| Progress tracking | ✅ SSE / polling | ✅ Terminal progress |
| PQC keyfile | ✅ | ✅ |

---

## 16. Python Package Boundary

Source: `backend/pyproject.toml`

The PyPI `avikal` package includes:

```
avikal_backend.archive.*
avikal_backend.cli.*
avikal_backend.mnemonic.*
avikal_backend.chess.*
avikal_backend.chess_codec.*
avikal_backend.wordlists.*
avikal_backend.services.*
avikal_backend.audit.*
```

Explicitly excluded from the published package:

```
avikal_backend.api.*        ← FastAPI layer (desktop-only)
backend/api_server.py       ← desktop launch script
```

This keeps the pip-installed CLI self-contained and free of FastAPI, Uvicorn, and Aavrit HTTP dependencies.

---

## 17. Security Design Notes

### Security Guarantees at a Glance

| Property | Guarantee | Implementation |
|:---------|:----------|:---------------|
| **Confidentiality** | AES-256-GCM (when password or keyphrase is provided) | `cryptography` (PyCA), 32-byte key, 12-byte random nonce; `plaintext_archive` mode is used when no secret is supplied |
| **Integrity** | GCM authentication tag (16 B) | Bit-flip in ciphertext → `InvalidTag` on decrypt |
| **Header binding** | AAD = `header_bytes` | Swapping payload across containers fails GCM auth |
| **Password hardening** | Argon2id, 256 MiB, 3 iterations | GPU brute-force cost: ~seconds per attempt per GPU |
| **Key separation** | HKDF with distinct `info` labels | Payload key ≠ chess key ≠ PQC keyfile key |
| **Quantum resistance** | ML-KEM-1024 (NIST PQC standard) | `pqcrypto==0.4.0`, external `.avkkey` file |
| **Time-lock (decentralized)** | drand tlock | Future beacon unpredictable; key does not exist until target round |
| **Time-lock (institutional)** | Aavrit Ed25519 commit/reveal | Signed commitment; local signature verification before any key derivation |
| **Time verification** | Google NTP (UDP + HTTPS fallback) | System clock never trusted for TimeCapsule |
| **Private key isolation** | PQC key never in `.avk` container | Enforced by assertion in `pack_cascade_metadata` |
| **Memory hygiene** | `secure_zero()` after every operation | `ctypes.memset` for bytes; in-place zero for bytearray |
| **No recovery oracle** | No backdoor, no key escrow | Loss of password + keyphrase = permanent data loss |
| **Key usability** | 21-word Hindi mnemonic (optional, user-selected) | 224-bit entropy via Argon2id; checksum-validated; Devanagari wordlist `avikal-hi-2048-v1` |


### 17.1 AAD as cryptographic binding

Every AES-256-GCM call uses `header_bytes` (the 8-byte binary header) as AAD. This means:
- Header and ciphertext are cryptographically bound
- Swapping a `payload.enc` from one `.avk` into another `.avk` with a different header will fail GCM authentication

### 17.2 No private key in container

PQC private keys are **never** written into `payload.enc`, `keychain.pgn`, or any part of the `.avk` ZIP. The `pqc_private_key` field in `pack_cascade_metadata` always receives `None` (enforced by assertion: `if pqc_required and pqc_private_key: raise ValueError`).

### 17.3 Key separation

| Key | Derivation | Used for |
|:----|:-----------|:---------|
| `master_key` | Argon2id(password+keyphrase, salt) | HKDF input only, never used directly |
| `payload_key` | HKDF(master, info="avikal_payload_v3") | payload.enc AES-256-GCM |
| `chess_key` | HKDF(master, info="avikal_chess_v3") | keychain.pgn AES-256-GCM |
| `pqc_keyfile_key` | HKDF(master, info="avikal_pqc_keyfile_v1") | .avkkey AES-256-GCM |

All keys are HKDF-separated from the same Argon2id master. Compromise of one does not expose others.

### 17.4 No oracle

There is no "forgot password" path. The unlock key material is derived deterministically from the user's secret. If the secret is lost:
- Regular archive: unrecoverable
- drand TimeCapsule: unrecoverable (Key B is tlock-encrypted to drand round; Key A is from password)
- Aavrit TimeCapsule: unrecoverable (Aavrit reveal provides Key B, but Key A is still needed for split-key mode)
- PQC archive: unrecoverable if `.avkkey` is lost

### 17.5 Temp file hygiene

All intermediate files use `tempfile.NamedTemporaryFile` with `delete=False` + manual cleanup in `finally` blocks. Partial output is never committed to the final path — `os.replace()` is used atomically after successful verification.




---

## Appendix A — Component Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        Desktop App                              │
│                                                                 │
│  ┌───────────────┐    ┌──────────────────┐    ┌─────────────┐  │
│  │ Electron Main │───▶│ Preload Bridge   │───▶│ React UI    │  │
│  │ (supervisor)  │    │ (window.electron)│    │ (Vite/TS)   │  │
│  └──────┬────────┘    └──────────────────┘    └──────┬──────┘  │
│         │                                            │ HTTP     │
│         ▼                                            ▼          │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │            FastAPI Backend  (127.0.0.1:5000)            │   │
│  │  api/server.py · api/routes.py · preview sessions       │   │
│  └─────────────────────────┬────────────────────────────────┘   │
└────────────────────────────│────────────────────────────────────┘
                             │
                   ┌─────────▼──────────┐
                   │  Shared Archive    │
                   │       Core         │
                   │  archive/pipeline  │
                   │  archive/format    │
                   │  archive/security  │
                   │  chess_metadata    │
                   │  mnemonic          │
                   └─────────┬──────────┘
                             │
              ┌──────────────┘
              │
┌─────────────▼──────────┐
│     CLI (avikal cmd)   │
│   cli/parser.py        │
│   cli/commands/        │
└────────────────────────┘
```

## Appendix B — Key Architecture Facts (Code-Verified)

| Fact | Source |
|:---|:---|
| Desktop backend binds to `127.0.0.1:5000` | `api/server.py` — uvicorn start |
| CLI does **not** start FastAPI | `cli/main.py` imports `archive.*` directly |
| Both surfaces call the same `archive/pipeline/encoder.py` | Verified in `server.py` and `cli/commands/` |
| `avikal_backend.api.*` is excluded from PyPI | `pyproject.toml` package includes |
| A global `threading.Lock()` serializes all crypto ops | `server.py` line 79: `_crypto_lock = threading.Lock()` |
| Preview session files live in a process-level directory | `server.py` → `PreviewSessionStore(_PREVIEW_SESSION_ROOT)` |
| PQC private key never written into `.avk` container | `metadata_pack.py` assertion: `if pqc_required and pqc_private_key: raise ValueError` |
| All AES-GCM calls use `header_bytes` as AAD | `encoder.py`, `chess_metadata.py`, `payload_streaming.py` |
| Maximum metadata size: 10 KB | `metadata_pack.py`: `max_metadata_size = 10 * 1024` |
| Maximum `keychain.pgn` size: 256 KB | `container.py`: `MAX_KEYCHAIN_BYTES = 256 * 1024` |
| Decompression bomb limit: 2 GiB / ratio 100,000:1 | `compression.py`: `FIXED_MAX_DECOMPRESSED_SIZE` |




