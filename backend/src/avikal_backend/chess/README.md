# Avikal Chess Core

This package is Avikal's internal Python chess model used by the PGN metadata codec.

It provides:

- legal move generation
- SAN parsing and writing
- PGN tree parsing/export support
- a readable reference model for codec tests

The production metadata codec can use the Rust native implementation for speed, but this Python package remains the protocol reference and test oracle. Do not remove it unless the Rust codec has a complete independent conformance suite and the Python tests are replaced with an equivalent specification-level test harness.
