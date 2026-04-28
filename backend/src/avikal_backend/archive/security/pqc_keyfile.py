"""
Protected external PQC keyfile support for Avikal.
Stores archive-specific KEM private keys outside the .avk container.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..security.crypto import derive_argon2id_key


PQC_KEYFILE_FORMAT = "avikal-pqc-keyfile"
PQC_KEYFILE_VERSION = 1
PQC_KEYFILE_ALGORITHM = "ml-kem-1024"
PQC_KEYFILE_EXTENSION = ".avkkey"


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(data)
    except Exception as exc:
        raise ValueError(f"Invalid PQC keyfile: malformed {field_name}") from exc


def _require_secret(password: str | None, keyphrase: list | None) -> None:
    if password:
        return
    if keyphrase and isinstance(keyphrase, list) and len(keyphrase) > 0:
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


def default_keyfile_path_for_archive(output_filepath: str) -> str:
    """Generate a sibling .avkkey path next to an .avk archive."""
    path = Path(output_filepath)
    if path.suffix:
        return str(path.with_suffix(PQC_KEYFILE_EXTENSION))
    return str(path.with_name(path.name + PQC_KEYFILE_EXTENSION))


def compute_pqc_key_id(public_key: bytes, pqc_ciphertext: bytes) -> str:
    """Stable archive-specific key identifier used to bind .avk and .avkkey."""
    digest = hashlib.sha256(public_key + pqc_ciphertext).hexdigest()
    return digest


def write_pqc_keyfile(
    output_path: str,
    *,
    password: str | None,
    keyphrase: list | None,
    private_key: bytes,
    public_key: bytes,
    pqc_ciphertext: bytes,
    archive_filename: str,
    algorithm: str = PQC_KEYFILE_ALGORITHM,
) -> dict:
    """
    Create an encrypted external PQC keyfile.

    The private key never appears in the .avk container. Instead it is written
    into an AES-GCM protected keyfile that is bound to the archive via key_id.
    """
    if not private_key:
        raise ValueError("PQC private key is missing")
    if not public_key:
        raise ValueError("PQC public key is missing")
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
    key_id = compute_pqc_key_id(public_key, pqc_ciphertext)
    keyfile_key = _derive_keyfile_encryption_key(password, keyphrase, salt)

    inner_payload = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "key_id": key_id,
        "archive_filename": archive_filename,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "private_key": _b64encode(private_key),
        "public_key": _b64encode(public_key),
    }
    plaintext = json.dumps(inner_payload, separators=(",", ":")).encode("utf-8")

    aad = f"{PQC_KEYFILE_FORMAT}|{PQC_KEYFILE_VERSION}|{algorithm}|{key_id}".encode("utf-8")
    ciphertext = AESGCM(keyfile_key).encrypt(nonce, plaintext, associated_data=aad)

    outer_document = {
        "format": PQC_KEYFILE_FORMAT,
        "version": PQC_KEYFILE_VERSION,
        "algorithm": algorithm,
        "key_id": key_id,
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(outer_document, f, indent=2)

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
) -> dict:
    """Read and decrypt an external PQC keyfile."""
    if not keyfile_path:
        raise ValueError(
            "This archive requires an external PQC keyfile. "
            "Please provide the .avkkey file created during encryption."
        )

    keyfile_path = os.path.abspath(keyfile_path)
    if not os.path.exists(keyfile_path):
        raise ValueError(f"PQC keyfile not found: {keyfile_path}")

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
    if algorithm != expected_algorithm:
        raise ValueError("Invalid PQC keyfile: unsupported algorithm")
    if expected_key_id and key_id != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    salt = _b64decode(document.get("salt", ""), "salt")
    nonce = _b64decode(document.get("nonce", ""), "nonce")
    ciphertext = _b64decode(document.get("ciphertext", ""), "ciphertext")

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
    if inner_payload.get("algorithm") != expected_algorithm:
        raise ValueError("Invalid PQC keyfile: algorithm mismatch")
    if expected_key_id and inner_payload.get("key_id") != expected_key_id:
        raise ValueError("PQC keyfile does not match this archive.")

    private_key = _b64decode(inner_payload.get("private_key", ""), "private_key")
    public_key = _b64decode(inner_payload.get("public_key", ""), "public_key")
    if not private_key:
        raise ValueError("Invalid PQC keyfile: private key is empty")
    if not public_key:
        raise ValueError("Invalid PQC keyfile: public key is empty")

    return {
        "key_id": inner_payload.get("key_id"),
        "algorithm": inner_payload.get("algorithm"),
        "private_key": private_key,
        "public_key": public_key,
        "archive_filename": inner_payload.get("archive_filename"),
        "created_at": inner_payload.get("created_at"),
        "path": keyfile_path,
    }
