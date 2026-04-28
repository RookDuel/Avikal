"""Aavrit commit/reveal cryptographic helpers."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

from fastapi import HTTPException


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(data: str) -> bytes:
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


def canonical_json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def build_aavrit_commit_hash(*, commit_id: str, data_hash: str, unlock_timestamp: int, reveal_value: str) -> str:
    return b64url_encode(
        hashlib.sha256(
            canonical_json_bytes(
                {
                    "version": 1,
                    "commit_id": commit_id,
                    "data_hash": data_hash,
                    "unlock_timestamp": unlock_timestamp,
                    "reveal_value": reveal_value,
                }
            )
        ).digest()
    )


def verify_aavrit_signature(payload: dict, signature: str, public_key_pem: str) -> None:
    from cryptography.hazmat.primitives import serialization

    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
        public_key.verify(b64url_decode(signature), canonical_json_bytes(payload))
    except Exception as exc:
        raise HTTPException(status_code=400, detail="Aavrit signature verification failed.") from exc


def derive_aavrit_time_key(commit_payload: dict, commit_signature: str) -> bytes:
    return hashlib.sha256(
        canonical_json_bytes(
            {
                "payload": commit_payload,
                "signature": commit_signature,
            }
        )
    ).digest()


def create_aavrit_data_hash() -> str:
    return b64url_encode(secrets.token_bytes(32))


def extract_aavrit_metadata(metadata: dict) -> dict:
    commit_id = metadata.get("file_id")
    server_url = metadata.get("server_url")
    data_hash = metadata.get("aavrit_data_hash")
    commit_hash = metadata.get("aavrit_commit_hash")
    server_key_id = metadata.get("aavrit_server_key_id")
    commit_signature = metadata.get("aavrit_commit_signature")

    for field_name, field_value in (
        ("file_id", commit_id),
        ("server_url", server_url),
        ("aavrit_data_hash", data_hash),
        ("aavrit_commit_hash", commit_hash),
        ("aavrit_server_key_id", server_key_id),
        ("aavrit_commit_signature", commit_signature),
    ):
        if not isinstance(field_value, str) or not field_value:
            raise HTTPException(status_code=400, detail=f"Invalid Aavrit archive metadata: missing {field_name}")

    return {
        "commit_id": commit_id,
        "server_url": server_url,
        "data_hash": data_hash,
        "commit_hash": commit_hash,
        "server_key_id": server_key_id,
        "commit_signature": commit_signature,
    }
