"""Rekey support for wrapped-DEK Avikal archives.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import tempfile
import time
import zipfile
from pathlib import Path

from avikal_backend.core.secure_delete import secure_remove_file
from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from ...mnemonic.generator import MNEMONIC_FORMAT_VERSION, normalize_mnemonic_words
from ...mnemonic.wordlist import WORDLIST_ID
from avikal_backend.version import __version__

from ..chess_metadata import encode_metadata_to_chess_enhanced
from ..format.container import open_avk_payload_stream, read_avk_header_and_keychain
from ..format.header import attach_header_to_keychain_pgn, attach_public_route_tags_to_keychain_pgn
from ..format.metadata import METADATA_FORMAT_VERSION_ASSURED, pack_cascade_metadata
from ..format.metadata_pack import FEATURE_ASSURED_REPORTS, FEATURE_MANDATORY_SIGNATURE
from ..pipeline.keychain_security import read_archive_keychain_metadata
from ..security.archive_signature import (
    HashingWriter,
    build_archive_signature_manifest,
    build_timestamp_statement,
    sign_and_attach_archive_manifest,
)
from ..security.crypto import derive_hierarchical_keys, has_user_secret, secure_zero
from ..security.key_wrap import PAYLOAD_KEY_WRAP_ALGORITHM, unwrap_payload_key, wrap_payload_key
from ..security.pqc_provider import create_archive_signing_identity, validate_archive_signing_identity
from ..security.trusted_timestamp import request_rfc3161_timestamp


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
    creator_signing_identity: dict | None = None,
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
        source_keychain = read_archive_keychain_metadata(
            str(source_path),
            password=old_password,
            keyphrase=old_keyphrase,
            skip_timelock=True,
        )
        metadata = source_keychain.metadata
        if not source_keychain.archive_signature_verified or source_keychain.expected_payload_sha256 is None:
            raise ValueError("Legacy unsigned archives must be decrypted and recreated before rekeying.")
        with open_avk_payload_stream(str(source_path)) as (header_bytes, _keychain_pgn, _payload_stream, embedded_pqc_blob):
            pass

        if metadata.get("encryption_method") == "plaintext_archive":
            raise ValueError("Plaintext archives do not need rekey.")
        if metadata.get("timecapsule_provider") is not None:
            raise ValueError("Time-capsule rekey is not supported in this phase.")
        if metadata.get("pqc_required") or embedded_pqc_blob is not None:
            raise ValueError("PQC rekey is not supported in this phase.")
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

        source_integrity = metadata.get("archive_integrity") or {}
        source_identity_kind = source_integrity.get("identity_kind")
        source_identity_id = source_integrity.get("identity_id")
        if creator_signing_identity is not None:
            signing_identity = validate_archive_signing_identity(creator_signing_identity, require_private=True)
            signing_identity_kind = "creator"
            if source_identity_kind == "creator" and signing_identity["identity_id"] != source_identity_id:
                raise ValueError("Rekey requires the creator identity that originally signed this archive.")
        else:
            if source_identity_kind == "creator":
                raise ValueError("Rekey requires the creator identity that originally signed this archive.")
            signing_identity = create_archive_signing_identity(label="Per-archive rekey identity", persistent=False)
            signing_identity_kind = "archive"
        signing_private_bundle = signing_identity["private_bundle"]
        signing_public_bundle = signing_identity["public_bundle"]
        signing_identity_id = signing_identity["identity_id"]

        temp_archive = tempfile.NamedTemporaryFile(
            suffix=".avk",
            prefix=".avikal-rekey-",
            delete=False,
            dir=str(destination_path.parent),
        )
        temp_archive_path = temp_archive.name
        temp_archive.close()
        register_temp_artifact(temp_archive_path)

        payload_digest = None
        payload_size = 0
        with zipfile.ZipFile(str(source_path), "r") as source_zip, zipfile.ZipFile(temp_archive_path, "w") as output_zip:
            with source_zip.open("payload.enc", "r") as source_payload, output_zip.open("payload.enc", "w", force_zip64=True) as target_payload:
                hashing_target = HashingWriter(target_payload)
                while True:
                    chunk = source_payload.read(4 * 1024 * 1024)
                    if not chunk:
                        break
                    hashing_target.write(chunk)
                payload_digest = hashing_target.hexdigest()
                payload_size = hashing_target.bytes_written
        if not secrets.compare_digest(payload_digest, source_keychain.expected_payload_sha256.hex()):
            raise ValueError("Source archive payload does not match its signed commitment.")

        required_features = int(metadata.get("required_features") or 0) | FEATURE_ASSURED_REPORTS | FEATURE_MANDATORY_SIGNATURE
        content_index_hash = bytes(metadata.get("content_index_hash") or source_keychain.expected_payload_sha256)
        payload_merkle_root = bytes(metadata.get("payload_merkle_root") or source_keychain.expected_payload_sha256)

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
            created_with_version=__version__,
            minimum_reader_version=__version__,
            required_features=required_features,
            sender_message=metadata.get("sender_message") or "",
            folder_count=int(metadata.get("folder_count") or 0),
            content_index_hash=content_index_hash,
            payload_merkle_root=payload_merkle_root,
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
        rebuilt_keychain = attach_public_route_tags_to_keychain_pgn(
            rebuilt_keychain,
            requires_password=bool(new_password),
            requires_keyphrase=bool(new_keyphrase),
            requires_pqc=False,
            keyphrase_wordlist_id=WORDLIST_ID if new_keyphrase_protected else None,
        )

        archive_id = str(source_integrity.get("archive_id") or secrets.token_hex(16))
        archive_created_at = int(source_integrity.get("created_at_utc") or time.time())
        timestamp_statement = build_timestamp_statement(
            archive_id=archive_id,
            created_at=archive_created_at,
            payload_sha256=payload_digest,
            keychain_core_pgn=rebuilt_keychain,
            content_index_sha256=content_index_hash.hex(),
            canonical_manifest_sha256=bytes(metadata["manifest_hash"]).hex(),
            payload_merkle_root=payload_merkle_root.hex(),
        )
        timestamp_evidence = request_rfc3161_timestamp(timestamp_statement)
        signature_manifest = build_archive_signature_manifest(
            header_bytes=header_bytes,
            keychain_core_pgn=rebuilt_keychain,
            payload_sha256=payload_digest,
            payload_size=payload_size,
            embedded_pqc_blob=None,
            pqc_algorithm=None,
            pqc_key_id=None,
            pqc_storage_mode=None,
            archive_id=archive_id,
            created_at=archive_created_at,
            created_with_version=__version__,
            minimum_reader_version=__version__,
            required_features=required_features,
            content_index_sha256=content_index_hash.hex(),
            canonical_manifest_sha256=bytes(metadata["manifest_hash"]).hex(),
            payload_merkle_root=payload_merkle_root.hex(),
            signing_identity_id=signing_identity_id,
            timestamp_statement=timestamp_statement,
            timestamp_evidence=timestamp_evidence,
        )
        rebuilt_keychain = sign_and_attach_archive_manifest(
            rebuilt_keychain,
            manifest=signature_manifest,
            private_bundle=signing_private_bundle,
            public_bundle=signing_public_bundle,
            identity_kind=signing_identity_kind,
        )

        with zipfile.ZipFile(temp_archive_path, "a") as output_zip:
            output_zip.writestr("keychain.pgn", rebuilt_keychain, compress_type=zipfile.ZIP_DEFLATED)

        read_avk_header_and_keychain(temp_archive_path)
        verified = read_archive_keychain_metadata(
            temp_archive_path,
            password=new_password,
            keyphrase=new_keyphrase,
            skip_timelock=True,
        )
        if not verified.archive_signature_verified or verified.expected_payload_sha256 != source_keychain.expected_payload_sha256:
            raise ValueError("Rekeyed archive failed post-build integrity verification.")

        os.replace(temp_archive_path, str(destination_path))
        unregister_temp_artifact(temp_archive_path)
        temp_archive_path = None

        return {
            "ok": True,
            "mode": "rekey",
            "input_file": str(source_path),
            "output_file": str(destination_path),
            "in_place": destination_path == source_path,
            "payload_rewritten": False,
            "metadata_version": METADATA_FORMAT_VERSION_ASSURED,
            "archive_integrity": {
                "status": "verified",
                "identity_id": signing_identity_id,
                "identity_kind": signing_identity_kind,
                "credentials_rotated": True,
            },
        }
    finally:
        if temp_archive_path and os.path.exists(temp_archive_path):
            secure_remove_file(temp_archive_path)
            unregister_temp_artifact(temp_archive_path)
        for secret in (old_master_key, old_access_key, new_master_key, new_access_key, payload_key, new_salt):
            if secret:
                secure_zero(secret)
        if old_password:
            secure_zero(old_password.encode("utf-8"))
        if new_password:
            secure_zero(new_password.encode("utf-8"))
