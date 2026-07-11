from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from avikal_backend.archive.format import multipart
from avikal_backend.archive.pipeline.progress import CancellationToken, OperationCancelled, bind_cancellation_token


_BINDING = {
    "archive_id": "11" * 16,
    "created_with_version": "1.0.6",
    "minimum_reader_version": "1.0.6",
    "signature_manifest_sha256": "22" * 32,
    "signing_identity_id": "33" * 32,
}


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(multipart, "MIN_VOLUME_SIZE", 1024)
    monkeypatch.setattr(multipart, "_verify_signed_archive", lambda _path: dict(_BINDING))


def test_multipart_roundtrip_preserves_complete_archive(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prepare(monkeypatch)
    source = tmp_path / "sample.avk"
    original = (b"avikal-volume-test\x00" * 400) + bytes(range(256))
    source.write_bytes(original)

    split = multipart.split_archive_to_volumes(str(source), volume_size=2048)
    volume_dir = Path(split["path"])
    manifest = json.loads((volume_dir / multipart.MULTIPART_MANIFEST_NAME).read_text(encoding="utf-8"))
    assert split["volume_count"] > 1
    assert manifest["signature_binding"] == _BINDING
    assert manifest["archive_sha256"] == hashlib.sha256(original).hexdigest()

    output = tmp_path / "restored.avk"
    joined = multipart.join_archive_volumes(str(volume_dir), output_archive=str(output))
    assert output.read_bytes() == original
    assert joined["commitment_sha256"] == split["commitment_sha256"]


def test_multipart_tamper_fails_before_publication(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prepare(monkeypatch)
    source = tmp_path / "tamper.avk"
    source.write_bytes(b"A" * 7000)
    split = multipart.split_archive_to_volumes(str(source), volume_size=2048)
    volume_dir = Path(split["path"])
    first_part = sorted(volume_dir.glob("*.avk.*"))[0]
    altered = bytearray(first_part.read_bytes())
    altered[0] ^= 0x01
    first_part.write_bytes(altered)

    output = tmp_path / "must-not-exist.avk"
    with pytest.raises(ValueError, match="digest verification failed"):
        multipart.join_archive_volumes(str(volume_dir), output_archive=str(output))
    assert not output.exists()


def test_multipart_manifest_commitment_tamper_is_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _prepare(monkeypatch)
    source = tmp_path / "manifest.avk"
    source.write_bytes(b"B" * 5000)
    split = multipart.split_archive_to_volumes(str(source), volume_size=2048)
    manifest_path = Path(split["path"]) / multipart.MULTIPART_MANIFEST_NAME
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    document["archive_size"] += 1
    manifest_path.write_text(
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="commitment verification failed"):
        multipart.join_archive_volumes(
            str(Path(split["path"])),
            output_archive=str(tmp_path / "invalid.avk"),
        )


def test_multipart_cancellation_removes_unpublished_temp_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    source = tmp_path / "cancel.avk"
    source.write_bytes(b"C" * 5000)
    token = CancellationToken()
    token.cancel()
    with bind_cancellation_token(token), pytest.raises(OperationCancelled):
        multipart.split_archive_to_volumes(str(source), volume_size=2048)
    assert not (tmp_path / "cancel.avk.parts").exists()
    assert not list(tmp_path.glob("avikal-volumes-*"))
