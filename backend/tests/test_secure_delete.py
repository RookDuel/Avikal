from pathlib import Path

from avikal_backend.core.secure_delete import secure_remove_file, secure_remove_tree


def test_secure_remove_file_deletes_file(tmp_path: Path) -> None:
    target = tmp_path / "secret.bin"
    target.write_bytes(b"secret-data" * 128)

    assert secure_remove_file(target) is True
    assert not target.exists()


def test_secure_remove_tree_deletes_nested_files(tmp_path: Path) -> None:
    root = tmp_path / "preview"
    nested = root / "folder"
    nested.mkdir(parents=True)
    (nested / "document.txt").write_text("plaintext", encoding="utf-8")
    (root / "empty.bin").write_bytes(b"")

    assert secure_remove_tree(root) is True
    assert not root.exists()
