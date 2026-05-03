"""
Rekey support for wrapped-DEK Avikal archives.

This operation rewrites keychain.pgn only. The encrypted payload.enc bytes are
copied unchanged so large archives do not need payload decryption/re-encryption.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import secrets
import tempfile
import zipfile
from pathlib import Path

from ...mnemonic.generator import MNEMONIC_FORMAT_VERSION, normalize_mnemonic_words
from ...mnemonic.wordlist import WORDLIST_ID
from ..chess_metadata import decode_chess_to_metadata_enhanced, encode_metadata_to_chess_enhanced
from ..format.container import open_avk_payload_stream
from ..format.header import attach_header_to_keychain_pgn
from ..format.metadata import METADATA_FORMAT_VERSION, pack_cascade_metadata
from ..security.crypto import derive_hierarchical_keys, has_user_secret, secure_zero
from ..security.key_wrap import PAYLOAD_KEY_WRAP_ALGORITHM, unwrap_payload_key, wrap_payload_key


def rekey_avk_archive(
    avk_filepath: str,
    *,
    old_password: str | None = None,
    old_keyphrase: list[str] | None = None,
    new_password: str | None = None,
    new_keyphrase: list[str] | None = None,
    output_filepath: str | None = None,
    variations_per_round: int = 5,
    force: bool = False,
) -> dict:
    """
    Rotate archive user credentials without rewriting payload.enc.

    Phase one intentionally supports regular wrapped-DEK archives only. PQC and
    provider time-capsule archives are rejected until their external-key update
    flows are implemented end to end.
    """
    source_path = Path(avk_filepath).expanduser().resolve()
    if not source_path.exists():
        raise ValueError(f"Input archive not found: {source_path}")

    if not has_user_secret(old_password, old_keyphrase):
        raise ValueError("Old password or keyphrase is required to unlock the current keychain")
    if not has_user_secret(new_password, new_keyphrase):
        raise ValueError("New password or keyphrase is required for rekey")

    old_keyphrase = normalize_mnemonic_words(old_keyphrase) if old_keyphrase else None
    new_keyphrase = normalize_mnemonic_words(new_keyphrase) if new_keyphrase else None

    destination_path = Path(output_filepath).expanduser().resolve() if output_filepath else source_path
    if destination_path.exists() and destination_path != source_path and not force:
        raise ValueError(f"Output file already exists: {destination_path}. Use --force to overwrite.")
    destination_path.parent.mkdir(parents=True, exist_ok=True)

    old_master_key = None
    old_access_key = None
    new_master_key = None
    new_access_key = None
    payload_key = None
    new_salt = None
    temp_archive_path = None

    try:
        with open_avk_payload_stream(str(source_path)) as (header_bytes, keychain_pgn, _payload_stream):
            metadata = decode_chess_to_metadata_enhanced(
                keychain_pgn,
                old_password,
                old_keyphrase,
                skip_timelock=True,
                aad=header_bytes,
            )

        if metadata.get("encryption_method") == "plaintext_archive":
            raise ValueError("Plaintext archives do not need rekey.")
        if metadata.get("timecapsule_provider") is not None:
            raise ValueError("Time-capsule rekey is not supported in this phase.")
        if metadata.get("pqc_required"):
            raise ValueError("PQC keyfile rekey is not supported in this phase.")
        if not metadata.get("wrapped_payload_key"):
            raise ValueError(
                "This archive was created before rekey support. Decrypt and create a new archive to enable rekey."
            )

        old_master_key, old_access_key, _old_chess_key, _old_salt = derive_hierarchical_keys(
            old_password,
            old_keyphrase,
            metadata["salt"],
        )
        payload_key = unwrap_payload_key(metadata["wrapped_payload_key"], old_access_key, header_bytes)

        new_salt = secrets.token_bytes(32)
        new_master_key, new_access_key, _new_chess_key, _new_salt = derive_hierarchical_keys(
            new_password,
            new_keyphrase,
            new_salt,
        )
        new_wrapped_payload_key = wrap_payload_key(payload_key, new_access_key, header_bytes)
        new_keyphrase_protected = bool(new_keyphrase)

        rebuilt_metadata = pack_cascade_metadata(
            new_salt,
            metadata.get("pqc_ciphertext"),
            None,
            metadata["unlock_timestamp"],
            metadata["filename"],
            metadata["checksum"],
            metadata["encryption_method"],
            new_keyphrase_protected,
            chess_salt=metadata.get("chess_salt"),
            timelock_mode=metadata.get("timelock_mode", "convenience"),
            file_id=metadata.get("file_id"),
            server_url=metadata.get("server_url"),
            time_key_hash=metadata.get("time_key_hash"),
            timecapsule_provider=metadata.get("timecapsule_provider"),
            aavrit_data_hash=metadata.get("aavrit_data_hash"),
            aavrit_commit_hash=metadata.get("aavrit_commit_hash"),
            aavrit_server_key_id=metadata.get("aavrit_server_key_id"),
            aavrit_commit_signature=metadata.get("aavrit_commit_signature"),
            drand_round=metadata.get("drand_round"),
            drand_chain_hash=metadata.get("drand_chain_hash"),
            drand_chain_url=metadata.get("drand_chain_url"),
            drand_ciphertext=metadata.get("drand_ciphertext"),
            drand_beacon_id=metadata.get("drand_beacon_id"),
            pqc_required=False,
            pqc_algorithm=None,
            pqc_key_id=None,
            keyphrase_format_version=MNEMONIC_FORMAT_VERSION if new_keyphrase_protected else 0,
            keyphrase_wordlist_id=WORDLIST_ID if new_keyphrase_protected else "",
            archive_type=metadata.get("archive_type"),
            entry_count=metadata.get("entry_count"),
            total_original_size=metadata.get("total_original_size"),
            manifest_hash=metadata.get("manifest_hash"),
            payload_key_wrap_algorithm=PAYLOAD_KEY_WRAP_ALGORITHM,
            wrapped_payload_key=new_wrapped_payload_key,
        )
        rebuilt_keychain = encode_metadata_to_chess_enhanced(
            rebuilt_metadata,
            new_password,
            new_keyphrase,
            variations_per_round=variations_per_round,
            use_timecapsule=False,
            aad=header_bytes,
        )
        rebuilt_keychain = attach_header_to_keychain_pgn(rebuilt_keychain, header_bytes)

        temp_archive = tempfile.NamedTemporaryFile(
            suffix=".avk",
            prefix=".avikal-rekey-",
            delete=False,
            dir=str(destination_path.parent),
        )
        temp_archive_path = temp_archive.name
        temp_archive.close()

        with zipfile.ZipFile(str(source_path), "r") as source_zip, zipfile.ZipFile(temp_archive_path, "w") as output_zip:
            output_zip.writestr("keychain.pgn", rebuilt_keychain, compress_type=zipfile.ZIP_DEFLATED)
            with source_zip.open("payload.enc", "r") as source_payload, output_zip.open("payload.enc", "w", force_zip64=True) as target_payload:
                while True:
                    chunk = source_payload.read(1024 * 1024)
                    if not chunk:
                        break
                    target_payload.write(chunk)

        os.replace(temp_archive_path, str(destination_path))
        temp_archive_path = None

        return {
            "ok": True,
            "mode": "rekey",
            "input_file": str(source_path),
            "output_file": str(destination_path),
            "in_place": destination_path == source_path,
            "payload_rewritten": False,
            "metadata_version": METADATA_FORMAT_VERSION,
        }
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            os.remove(temp_archive_path)
        for secret in (old_master_key, old_access_key, new_master_key, new_access_key, payload_key, new_salt):
            if secret:
                secure_zero(secret)
        if old_password:
            secure_zero(old_password.encode("utf-8"))
        if new_password:
            secure_zero(new_password.encode("utf-8"))
