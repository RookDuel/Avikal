from __future__ import annotations

import ast
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _import_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_packaged_desktop_spec_collects_only_existing_backend_modules():
    spec = REPO_ROOT / "backend" / "pyinstaller-backend.spec"
    text = spec.read_text(encoding="utf-8")

    assert 'collect_submodules("avikal_backend")' in text
    assert not (REPO_ROOT / "backend" / "src" / "avikal_backend" / "api").exists()


def test_stdio_core_entrypoints_do_not_import_http_runtime():
    forbidden = {"fastapi", "uvicorn"}
    entrypoints = [
        REPO_ROOT / "backend" / "core_server.py",
        REPO_ROOT / "backend" / "src" / "avikal_backend" / "core" / "services.py",
        REPO_ROOT / "backend" / "src" / "avikal_backend" / "core_main.py",
    ]

    for entrypoint in entrypoints:
        imports = _import_names(entrypoint)
        assert imports.isdisjoint(forbidden), f"{entrypoint} imports legacy HTTP runtime: {imports & forbidden}"


def test_packaged_electron_ignores_development_and_update_overrides():
    main_source = (REPO_ROOT / "electron" / "main.js").read_text(encoding="utf-8")

    assert "const sourceDevMode = !packagedApp" in main_source
    assert "const devServerUrl = packagedApp ? null" in main_source
    assert "const UPDATE_REPO_OWNER = 'RookDuel'" in main_source
    assert "const UPDATE_REPO_NAME = 'Avikal'" in main_source
    assert "delete pythonEnv[key]" in main_source


def test_release_and_runtime_metadata_require_ed25519_signatures():
    main_source = (REPO_ROOT / "electron" / "main.js").read_text(encoding="utf-8")
    package = (REPO_ROOT / "package.json").read_text(encoding="utf-8")

    assert "readVerifiedReleaseMetadataAsset" in main_source
    assert "Release metadata signature verification failed" in main_source
    assert "verifySignedRuntimeManifest" in main_source
    assert "Bundled Avikal core failed publisher manifest verification" in main_source
    assert '"sign:runtime"' in package


def test_private_workspace_windows_acl_is_fail_closed():
    source = (REPO_ROOT / "backend" / "src" / "avikal_backend" / "core" / "private_workspace.py").read_text(encoding="utf-8")

    assert '"icacls.exe"' in source
    assert '"/inheritance:r"' in source
    assert "Unable to secure the private workspace" in source
