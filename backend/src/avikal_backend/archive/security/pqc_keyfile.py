"""
Encrypted external PQC keyfile support for Avikal.

Version 1 stores the private side of the OpenSSL hybrid PQC fixed suite outside
the .avk container. The .avk metadata keeps only the public binding information
and KEM ciphertext needed to match the archive to this keyfile.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..security.crypto import derive_argon2id_key
from ..security.pqc_provider import (
    PQC_SUITE,
    PQC_SUITE_ID,
    compute_pqc_key_id,
)


PQC_KEYFILE_FORMAT = "avikal-pqc-keyfile"
PQC_KEYFILE_VERSION = 1
PQC_KEYFILE_ALGORITHM = PQC_SUITE_ID
PQC_KEYFILE_EXTENSION = ".avkkey"
PQC_KEYFILE_MAX_BYTES = 4 * 1024 * 1024


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(data, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid PQC keyfile: malformed {field_name}") from exc


def _require_secret(password: str | None, keyphrase: list | None) -> None:
    if password:
        return
    if keyphrase and isinstance(keyphrase, list) and any(str(word).strip() for word in keyphrase):
        return
    raise ValueError(
        "PQC keyfile protection requires a password or keyphrase. "
        "Enable PQC only when archive secrets are configured."
    )


def _derive_keyfile_encryption_key(password: str | None, keyphrase: list | None, salt: bytes) -> bytes:
    """Derive a domain-separated AES key for the external PQC keyfile."""
    _require_secret(password, keyphrase)
    master_key, _ = derive_argon2id_key(password=password, keyphrase=keyphrase, salt=salt)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"avikal_pqc_keyfile_v1",
    )
    return hkdf.derive(master_key)


def _canonical_json_size(document: dict[str, Any]) -> int:
    return len(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def default_keyfile_path_for_archive(output_filepath: str) -> str:
    """Generate a sibling .avkkey path next to an .avk archive."""
    path = Path(output_filepath)
    if path.suffix:
        return str(path.with_suffix(PQC_KEYFILE_EXTENSION))
    return str(path.with_name(path.name + PQC_KEYFILE_EXTENSION))


def write_pqc_keyfile(
    output_path: str,
    *,
    password: str | None,
    keyphrase: list | None,
    private_bundle: dict[str, Any],
    public_bundle: dict[str, Any],
    pqc_ciphertext: bytes,
    archive_filename: str,
    algorithm: str = PQC_KEYFILE_ALGORITHM,
) -> dict[str, Any]:
    """
    Create an encrypted external PQC keyfile.

    The private bundle never appears in the .avk container. It is AES-GCM
    protected with a key derived from the same user secret that unlocks the
    archive.
    """
    if algorithm != PQC_KEYFILE_ALGORITHM:
        raise ValueError("Unsupported PQC keyfile algorithm")
    if not isinstance(private_bundle, dict) or not private_bundle:
        raise ValueError("PQC private bundle is missing")
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("PQC public bundle is missing")
    if not pqc_ciphertext:
        raise ValueError("PQC ciphertext is missing")

    output_path = os.path.abspath(output_path)
    if os.path.exists(output_path):
        raise ValueError(
            f"PQC keyfile already exists: {output_path}. "
            "Choose a different path or remove the existing keyfile first."
        )

    salt = os.urandom(32)
    nonce = os.urandom(12)
    key_id = compute_pqc_key_id(public_bundle, pqc_ciphertext)
    keyfile_key = _derive_keyfile_encryption_key(password, keyphrase, salt)

    inner_payload = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "suite": PQC_SUITE,
        "key_id": key_id,
        "archive_filename": archive_filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
    }
    if _canonical_json_size(inner_payload) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("PQC keyfile payload is too large")

    plaintext = json.dumps(inner_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    aad = f"{PQC_KEYFILE_FORMAT}|{PQC_KEYFILE_VERSION}|{algorithm}|{key_id}".encode("utf-8")
    ciphertext = AESGCM(keyfile_key).encrypt(nonce, plaintext, associated_data=aad)

    outer_document = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "key_id": key_id,
        "suite": PQC_SUITE,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }
    if _canonical_json_size(outer_document) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("PQC keyfile document is too large")

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(outer_document, f, indent=2, sort_keys=True)

    return {
        "key_id": key_id,
        "algorithm": algorithm,
        "path": output_path,
    }


def read_pqc_keyfile(
    keyfile_path: str,
    *,
    password: str | None,
    keyphrase: list | None,
    expected_key_id: str | None = None,
    expected_algorithm: str = PQC_KEYFILE_ALGORITHM,
) -> dict[str, Any]:
    """Read and decrypt an external PQC keyfile."""
    if not keyfile_path:
        raise ValueError(
            "This archive requires an external PQC keyfile. "
            "Please provide the .avkkey file created during encryption."
        )

    keyfile_path = os.path.abspath(keyfile_path)
    if not os.path.exists(keyfile_path):
        raise ValueError(f"PQC keyfile not found: {keyfile_path}")
    if os.path.getsize(keyfile_path) > PQC_KEYFILE_MAX_BYTES:
        raise ValueError("Invalid PQC keyfile: file is too large")

    try:
        with open(keyfile_path, "r", encoding="utf-8") as f:
            document = json.load(f)
    except Exception as exc:
        raise ValueError("Invalid PQC keyfile: unable to read JSON document") from exc

    if not isinstance(document, dict):
        raise ValueError("Invalid PQC keyfile: top-level document must be an object")
    if document.get("format") != PQC_KEYFILE_FORMAT:
        raise ValueError("Invalid PQC keyfile: unexpected file format")
    if document.get("version") != PQC_KEYFILE_VERSION:
        raise ValueError("Invalid PQC keyfile: unsupported version")

    algorithm = document.get("algorithm")
    key_id = document.get("key_id")
    if algorithm != expected_algorithm or algorithm != PQC_KEYFILE_ALGORITHM:
        raise ValueError("Invalid PQC keyfile: unsupported algorithm")
    if expected_key_id and key_id != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    salt = _b64decode(document.get("salt", ""), "salt")
    nonce = _b64decode(document.get("nonce", ""), "nonce")
    ciphertext = _b64decode(document.get("ciphertext", ""), "ciphertext")
    if len(salt) != 32 or len(nonce) != 12:
        raise ValueError("Invalid PQC keyfile: malformed encryption parameters")

    keyfile_key = _derive_keyfile_encryption_key(password, keyphrase, salt)
    aad = f"{PQC_KEYFILE_FORMAT}|{PQC_KEYFILE_VERSION}|{algorithm}|{key_id}".encode("utf-8")
    try:
        plaintext = AESGCM(keyfile_key).decrypt(nonce, ciphertext, associated_data=aad)
    except Exception as exc:
        raise ValueError(
            "Failed to decrypt the PQC keyfile. Check the password/keyphrase and keyfile."
        ) from exc

    try:
        inner_payload = json.loads(plaintext.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid PQC keyfile: decrypted payload is malformed") from exc

    if not isinstance(inner_payload, dict):
        raise ValueError("Invalid PQC keyfile: decrypted payload must be an object")
    if inner_payload.get("version") != PQC_KEYFILE_VERSION:
        raise ValueError("Invalid PQC keyfile: decrypted payload version mismatch")
    if inner_payload.get("algorithm") != expected_algorithm:
        raise ValueError("Invalid PQC keyfile: algorithm mismatch")
    if expected_key_id and inner_payload.get("key_id") != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    private_bundle = inner_payload.get("private_bundle")
    public_bundle = inner_payload.get("public_bundle")
    if not isinstance(private_bundle, dict) or not private_bundle:
        raise ValueError("Invalid PQC keyfile: private bundle is empty")
    if not isinstance(public_bundle, dict) or not public_bundle:
        raise ValueError("Invalid PQC keyfile: public bundle is empty")

    return {
        "key_id": inner_payload.get("key_id"),
        "algorithm": inner_payload.get("algorithm"),
        "suite": inner_payload.get("suite"),
        "private_bundle": private_bundle,
        "public_bundle": public_bundle,
        "archive_filename": inner_payload.get("archive_filename"),
        "created_at": inner_payload.get("created_at"),
        "path": keyfile_path,
    }
