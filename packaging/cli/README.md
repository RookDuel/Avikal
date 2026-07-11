# Avikal CLI Packaging

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.

The CLI package is source-shared across operating systems, but release artifacts must be built per OS.

Required per target:

- Python wheel containing the Rust native extension for that OS (`_native.pyd` on Windows, `_native.so` on Linux).
- OpenSSL 3.5+ PQC runtime for that OS when PQC support is part of the artifact.
- `avikal doctor --json` verification after install.
- Encode/decode regression tests for password, keyphrase, external PQC, embedded PQC, and TimeCapsule.

PQC runtime discovery order:

- `AVIKAL_OPENSSL_EXEC` points directly to the target OpenSSL executable.
- `AVIKAL_PQC_RUNTIME_DIR` points to a runtime root containing `bin/openssl.exe` on Windows or `bin/openssl` on Linux.
- Packaged runtime under `avikal_backend/runtime/pqc`.

For a full production wheel, set `AVIKAL_REQUIRE_BUNDLED_PQC_RUNTIME=1` in the build job so a missing PQC runtime fails the build. Lightweight wheels may omit the bundled PQC runtime, but PQC commands will fail closed until a compatible runtime is supplied.
