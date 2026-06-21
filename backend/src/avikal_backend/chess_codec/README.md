# Avikal Chess-PGN Codec

This package maps metadata integers to reversible Chess-PGN text and back.

Runtime behavior:

- `encoder.py` and `decoder.py` keep the public Python API used by archive code.
- `native_bridge.py` routes default production codec work to `avikal_backend._native` when the Rust codec is available.
- The Python implementation remains as a reference path for tests, diagnostics, and compatibility checks.

This is not a legacy crypto fallback. It is the specification-facing implementation used to prove that the Rust accelerated codec preserves the same integer-to-PGN mapping.
