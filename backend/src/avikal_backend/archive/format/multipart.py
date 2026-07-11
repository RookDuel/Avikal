"""Cryptographically committed transport volumes for complete Avikal archives.

Multipart volumes are an opt-in transport layer around an already completed,
dual-signed ``.avk``. They do not change AVI1 or permit partial archive use.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from typing import BinaryIO, Callable

from avikal_backend.core.secure_delete import secure_remove_file, secure_remove_tree
from avikal_backend.core.temp_janitor import register_temp_artifact, unregister_temp_artifact

from .container import open_avk_payload_stream, read_avk_header_and_keychain
from ..security.archive_signature import (
    build_archive_signature_evidence,
    extract_archive_signature,
    verify_archive_signature_evidence,
)


MULTIPART_FORMAT = "avikal-multipart-volume-set"
MULTIPART_VERSION = 1
MULTIPART_MANIFEST_NAME = "manifest.json"
MIN_VOLUME_SIZE = 64 * 1024 * 1024
MAX_VOLUME_SIZE = 4 * 1024 * 1024 * 1024 * 1024
MAX_VOLUME_COUNT = 100_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
IO_CHUNK_SIZE = 4 * 1024 * 1024
_HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_json(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _write_all(target: BinaryIO, data: bytes) -> None:
    written = target.write(data)
    if written is not None and written != len(data):
        raise OSError("Short write while creating an Avikal multipart volume")


def _snapshot_regular_file(path: Path) -> tuple[int, int, int, int]:
    info = path.stat(follow_symlinks=False)
    if path.is_symlink() or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Multipart source is not a regular file: {path.name}")
    return int(info.st_size), int(info.st_mtime_ns), int(info.st_dev), int(info.st_ino)


def _volume_chain(previous: bytes, *, index: int, offset: int, size: int, digest: bytes) -> bytes:
    return hashlib.sha256(
        b"AvikalMultipartVolumeV1\x00"
        + previous
        + int(index).to_bytes(8, "big")
        + int(offset).to_bytes(8, "big")
        + int(size).to_bytes(8, "big")
        + digest
    ).digest()


def _verify_signed_archive(path: Path) -> dict:
    header, keychain = read_avk_header_and_keychain(str(path))
    signature = extract_archive_signature(keychain, required=True)
    if signature is None:
        raise ValueError("Multipart volumes require a signed Avikal archive")
    document = verify_archive_signature_evidence(build_archive_signature_evidence(signature))
    if document.get("header") != base64.b64encode(header).decode("ascii"):
        raise ValueError("Archive header does not match its signed commitment")
    if document.get("keychain_core_sha256") != hashlib.sha256(
        signature["keychain_core_pgn"].encode("utf-8")
    ).hexdigest():
        raise ValueError("Archive keychain does not match its signed commitment")

    payload_digest = hashlib.sha256()
    payload_size = 0
    with open_avk_payload_stream(str(path)) as (_header, _keychain, payload, embedded_pqc):
        while True:
            chunk = payload.read(IO_CHUNK_SIZE)
            if not chunk:
                break
            payload_digest.update(chunk)
            payload_size += len(chunk)
    if document.get("payload_sha256") != payload_digest.hexdigest() or document.get("payload_size") != payload_size:
        raise ValueError("Archive payload does not match its signed commitment")
    embedded_digest = hashlib.sha256(embedded_pqc).hexdigest() if embedded_pqc is not None else None
    embedded_size = len(embedded_pqc) if embedded_pqc is not None else 0
    if (
        document.get("embedded_pqc_sha256") != embedded_digest
        or document.get("embedded_pqc_size") != embedded_size
    ):
        raise ValueError("Embedded PQC member does not match its signed commitment")
    return {
        "archive_id": document.get("archive_id"),
        "created_with_version": document.get("created_with_version"),
        "minimum_reader_version": document.get("minimum_reader_version"),
        "signature_manifest_sha256": hashlib.sha256(signature["manifest"]).hexdigest(),
        "signing_identity_id": document.get("signing_identity_id"),
    }


def split_archive_to_volumes(
    input_archive: str,
    *,
    output_dir: str | None = None,
    volume_size: int = 2 * 1024 * 1024 * 1024,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict:
    """Split one signed ``.avk`` into an atomically published volume-set directory."""
    from ..pipeline.progress import check_cancelled

    source = Path(input_archive).resolve()
    initial_snapshot = _snapshot_regular_file(source)
    archive_size = initial_snapshot[0]
    if source.suffix.lower() != ".avk":
        raise ValueError("Multipart source must be an .avk archive")
    if not isinstance(volume_size, int) or not MIN_VOLUME_SIZE <= volume_size <= MAX_VOLUME_SIZE:
        raise ValueError("Multipart volume size is outside the supported range")
    volume_count = max(1, (archive_size + volume_size - 1) // volume_size)
    if volume_count > MAX_VOLUME_COUNT:
        raise ValueError("Multipart archive would exceed the supported volume count")

    signature_binding = _verify_signed_archive(source)
    parent = Path(output_dir).resolve() if output_dir else source.parent
    if not parent.is_dir():
        raise ValueError(f"Multipart destination directory does not exist: {parent}")
    required_space = archive_size + min(MAX_MANIFEST_BYTES, 4096 + volume_count * 384)
    if shutil.disk_usage(parent).free < required_space:
        raise OSError("Insufficient free space for the multipart volume set")

    final_dir = parent / f"{source.name}.parts"
    if os.path.lexists(final_dir):
        raise ValueError(f"Refusing to overwrite an existing multipart volume set: {final_dir}")
    temp_dir = Path(tempfile.mkdtemp(prefix="avikal-volumes-", dir=parent))
    register_temp_artifact(temp_dir, kind="dir")

    archive_digest = hashlib.sha256()
    previous_chain = b"\x00" * 32
    volumes: list[dict] = []
    processed = 0
    try:
        with source.open("rb") as source_handle:
            for index in range(1, volume_count + 1):
                check_cancelled()
                filename = f"{source.name}.{index:05d}"
                volume_path = temp_dir / filename
                remaining = min(volume_size, archive_size - processed)
                volume_digest = hashlib.sha256()
                volume_written = 0
                with volume_path.open("xb") as volume_handle:
                    while volume_written < remaining:
                        check_cancelled()
                        chunk = source_handle.read(min(IO_CHUNK_SIZE, remaining - volume_written))
                        if not chunk:
                            raise OSError("Archive ended before the multipart volume set was complete")
                        _write_all(volume_handle, chunk)
                        archive_digest.update(chunk)
                        volume_digest.update(chunk)
                        volume_written += len(chunk)
                        processed += len(chunk)
                        if progress_callback:
                            progress_callback(processed, archive_size)
                    volume_handle.flush()
                    os.fsync(volume_handle.fileno())
                digest = volume_digest.digest()
                previous_chain = _volume_chain(
                    previous_chain,
                    index=index,
                    offset=processed - volume_written,
                    size=volume_written,
                    digest=digest,
                )
                volumes.append(
                    {
                        "chain_sha256": previous_chain.hex(),
                        "filename": filename,
                        "index": index,
                        "offset": processed - volume_written,
                        "sha256": digest.hex(),
                        "size": volume_written,
                    }
                )
            if source_handle.read(1):
                raise ValueError("Archive changed while multipart volumes were being created")

        if _snapshot_regular_file(source) != initial_snapshot:
            raise ValueError("Archive changed while multipart volumes were being created")
        core = {
            "archive_filename": source.name,
            "archive_sha256": archive_digest.hexdigest(),
            "archive_size": archive_size,
            "format": MULTIPART_FORMAT,
            "signature_binding": signature_binding,
            "volume_count": volume_count,
            "volume_size": volume_size,
            "volumes": volumes,
            "version": MULTIPART_VERSION,
        }
        manifest = dict(core)
        manifest["commitment_sha256"] = hashlib.sha256(_canonical_json(core)).hexdigest()
        manifest_bytes = _canonical_json(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("Multipart manifest exceeds the supported size")
        manifest_path = temp_dir / MULTIPART_MANIFEST_NAME
        with manifest_path.open("xb") as manifest_handle:
            _write_all(manifest_handle, manifest_bytes)
            manifest_handle.flush()
            os.fsync(manifest_handle.fileno())

        os.replace(temp_dir, final_dir)
        unregister_temp_artifact(temp_dir)
        temp_dir = None
        if progress_callback:
            progress_callback(archive_size, archive_size)
        return {
            "archive_sha256": core["archive_sha256"],
            "archive_size": archive_size,
            "commitment_sha256": manifest["commitment_sha256"],
            "path": str(final_dir),
            "volume_count": volume_count,
            "volume_size": volume_size,
        }
    finally:
        if temp_dir is not None:
            secure_remove_tree(temp_dir)
            unregister_temp_artifact(temp_dir)


def _load_manifest(volume_set_dir: Path) -> dict:
    manifest_path = volume_set_dir / MULTIPART_MANIFEST_NAME
    snapshot = _snapshot_regular_file(manifest_path)
    if snapshot[0] <= 0 or snapshot[0] > MAX_MANIFEST_BYTES:
        raise ValueError("Multipart manifest size is invalid")
    raw = manifest_path.read_bytes()
    if _snapshot_regular_file(manifest_path) != snapshot:
        raise ValueError("Multipart manifest changed while it was being read")
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Multipart manifest is malformed") from exc
    if not isinstance(document, dict) or _canonical_json(document) != raw:
        raise ValueError("Multipart manifest is not canonical")
    commitment = document.pop("commitment_sha256", None)
    if not isinstance(commitment, str) or not _HEX_SHA256.fullmatch(commitment):
        raise ValueError("Multipart manifest commitment is invalid")
    if hashlib.sha256(_canonical_json(document)).hexdigest() != commitment:
        raise ValueError("Multipart manifest commitment verification failed")
    document["commitment_sha256"] = commitment
    return document


def join_archive_volumes(
    volume_set_dir: str,
    *,
    output_archive: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict:
    """Verify and atomically reassemble one multipart set into its signed ``.avk``."""
    from ..pipeline.progress import check_cancelled

    source_dir = Path(volume_set_dir).resolve()
    if not source_dir.is_dir() or source_dir.is_symlink():
        raise ValueError("Multipart volume-set path must be a regular directory")
    manifest = _load_manifest(source_dir)
    if manifest.get("format") != MULTIPART_FORMAT or manifest.get("version") != MULTIPART_VERSION:
        raise ValueError("Unsupported multipart volume-set format")
    archive_filename = manifest.get("archive_filename")
    archive_size = manifest.get("archive_size")
    archive_sha256 = manifest.get("archive_sha256")
    volume_count = manifest.get("volume_count")
    volumes = manifest.get("volumes")
    if (
        not isinstance(archive_filename, str)
        or Path(archive_filename).name != archive_filename
        or not archive_filename.lower().endswith(".avk")
        or not isinstance(archive_size, int)
        or archive_size < 0
        or not isinstance(archive_sha256, str)
        or not _HEX_SHA256.fullmatch(archive_sha256)
        or not isinstance(volume_count, int)
        or not 1 <= volume_count <= MAX_VOLUME_COUNT
        or not isinstance(volumes, list)
        or len(volumes) != volume_count
    ):
        raise ValueError("Multipart manifest fields are invalid")

    destination = Path(output_archive).resolve()
    if destination.suffix.lower() != ".avk":
        raise ValueError("Multipart output must use the .avk extension")
    if not destination.parent.is_dir():
        raise ValueError(f"Archive destination directory does not exist: {destination.parent}")
    if os.path.lexists(destination):
        raise ValueError(f"Refusing to overwrite an existing archive: {destination}")
    if shutil.disk_usage(destination.parent).free < archive_size + 16 * 1024 * 1024:
        raise OSError("Insufficient free space to reassemble the multipart archive")

    temp = tempfile.NamedTemporaryFile(
        mode="w+b",
        prefix=".avikal-archive-",
        suffix=".avk",
        dir=destination.parent,
        delete=False,
    )
    temp_path = Path(temp.name)
    temp.close()
    register_temp_artifact(temp_path)
    archive_digest = hashlib.sha256()
    previous_chain = b"\x00" * 32
    processed = 0
    try:
        with temp_path.open("r+b") as output:
            for expected_index, record in enumerate(volumes, start=1):
                check_cancelled()
                if not isinstance(record, dict):
                    raise ValueError("Multipart volume record is malformed")
                filename = record.get("filename")
                expected_filename = f"{archive_filename}.{expected_index:05d}"
                expected_size = record.get("size")
                expected_offset = record.get("offset")
                expected_digest = record.get("sha256")
                expected_chain = record.get("chain_sha256")
                if (
                    record.get("index") != expected_index
                    or filename != expected_filename
                    or not isinstance(expected_size, int)
                    or expected_size < 0
                    or expected_offset != processed
                    or not isinstance(expected_digest, str)
                    or not _HEX_SHA256.fullmatch(expected_digest)
                    or not isinstance(expected_chain, str)
                    or not _HEX_SHA256.fullmatch(expected_chain)
                ):
                    raise ValueError("Multipart volume record is invalid")
                volume_path = source_dir / filename
                snapshot = _snapshot_regular_file(volume_path)
                if snapshot[0] != expected_size:
                    raise ValueError(f"Multipart volume size verification failed: {filename}")
                volume_digest = hashlib.sha256()
                volume_read = 0
                with volume_path.open("rb") as volume:
                    while True:
                        check_cancelled()
                        chunk = volume.read(IO_CHUNK_SIZE)
                        if not chunk:
                            break
                        _write_all(output, chunk)
                        archive_digest.update(chunk)
                        volume_digest.update(chunk)
                        volume_read += len(chunk)
                        processed += len(chunk)
                        if progress_callback:
                            progress_callback(processed, archive_size)
                if _snapshot_regular_file(volume_path) != snapshot:
                    raise ValueError(f"Multipart volume changed while it was being read: {filename}")
                digest = volume_digest.digest()
                if volume_read != expected_size or digest.hex() != expected_digest:
                    raise ValueError(f"Multipart volume digest verification failed: {filename}")
                previous_chain = _volume_chain(
                    previous_chain,
                    index=expected_index,
                    offset=expected_offset,
                    size=expected_size,
                    digest=digest,
                )
                if previous_chain.hex() != expected_chain:
                    raise ValueError(f"Multipart volume chain verification failed: {filename}")
            output.flush()
            os.fsync(output.fileno())

        if processed != archive_size or archive_digest.hexdigest() != archive_sha256:
            raise ValueError("Reassembled archive commitment verification failed")
        signature_binding = _verify_signed_archive(temp_path)
        if signature_binding != manifest.get("signature_binding"):
            raise ValueError("Reassembled archive signature binding does not match the multipart manifest")
        if os.path.lexists(destination):
            raise ValueError(f"Refusing to overwrite an existing archive: {destination}")
        os.replace(temp_path, destination)
        unregister_temp_artifact(temp_path)
        temp_path = None
        if progress_callback:
            progress_callback(archive_size, archive_size)
        return {
            "archive_sha256": archive_sha256,
            "archive_size": archive_size,
            "commitment_sha256": manifest["commitment_sha256"],
            "path": str(destination),
            "volume_count": volume_count,
        }
    finally:
        if temp_path is not None and temp_path.exists():
            secure_remove_file(temp_path)
            unregister_temp_artifact(temp_path)
