#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import shutil
from importlib import metadata
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
VENV_ROOT = BACKEND_ROOT / "venv"
PYVENV_CFG = VENV_ROOT / "pyvenv.cfg"
REQUIREMENTS_FILE = BACKEND_ROOT / "requirements.txt"
OUTPUT_ROOT = PROJECT_ROOT / ".app-build" / "backend-runtime"
BACKEND_OUTPUT_ROOT = PROJECT_ROOT / ".app-build" / "backend"
PQC_RUNTIME_ROOT = PROJECT_ROOT / "runtime" / "pqc"

NAME_RE = re.compile(r"^\s*([A-Za-z0-9_.-]+)")
SITE_PACKAGES_NAME = "site-packages"
BLOCKED_DISTRIBUTIONS = {
    "pip",
    "setuptools",
    "wheel",
    "pytest",
    "_pytest",
    "hypothesis",
    "pyqt6",
    "pyqt6-qt6",
    "pyqt6-sip",
    "python-chess",
    "chess",
}
EXCLUDED_STDLIB_DIRS = {
    "__pycache__",
    SITE_PACKAGES_NAME,
    "ensurepip",
    "idlelib",
    "test",
    "tests",
    "tkinter",
    "turtledemo",
    "venv",
}
EXCLUDED_BACKEND_DIRS = {
    ".pytest_cache",
    ".tmp_pip",
    ".tmp_test_runs",
    "__pycache__",
    "build",
    "delete-backend",
    "dist",
    "docs",
    "logs",
    "new-backend",
    "tests",
    "venv",
}
EXCLUDED_BACKEND_FILES = {
    "avikal.cmd",
    "avikal.py",
    "cli.py",
    "CLI_REFERENCE.md",
    "CLI_USAGE.md",
    "MANIFEST.in",
    "pyproject.toml",
    "README_PACKAGE.md",
    "requirements-cli.txt",
}


def normalize_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def extract_requirement_name(spec: str) -> str | None:
    match = NAME_RE.match(spec.strip())
    if not match:
        return None
    return normalize_name(match.group(1))


def read_base_python_home() -> Path:
    if not PYVENV_CFG.exists():
        raise FileNotFoundError(f"Missing pyvenv.cfg at {PYVENV_CFG}")

    for line in PYVENV_CFG.read_text(encoding="utf-8").splitlines():
        if line.lower().startswith("home ="):
            home = line.split("=", 1)[1].strip()
            base_home = Path(home)
            if base_home.exists():
                return base_home
            raise FileNotFoundError(f"Configured Python home does not exist: {base_home}")

    raise RuntimeError("Could not find 'home =' in pyvenv.cfg")


def get_venv_site_packages() -> Path:
    if not VENV_ROOT.exists():
        raise FileNotFoundError(f"Backend venv not found: {VENV_ROOT}")

    if (VENV_ROOT / "Lib" / SITE_PACKAGES_NAME).exists():
        return VENV_ROOT / "Lib" / SITE_PACKAGES_NAME

    for site_packages in VENV_ROOT.glob("lib/python*/site-packages"):
        if site_packages.exists():
            return site_packages

    raise FileNotFoundError("Could not locate venv site-packages")


def parse_root_distributions() -> list[str]:
    names: list[str] = []
    for raw_line in REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        name = extract_requirement_name(line)
        if name:
            names.append(name)
    return names


def build_distribution_map(site_packages: Path) -> dict[str, metadata.Distribution]:
    dist_map: dict[str, metadata.Distribution] = {}
    for dist in metadata.distributions(path=[str(site_packages)]):
        normalized = normalize_name(dist.metadata["Name"])
        dist_map[normalized] = dist
    return dist_map


def resolve_distribution_closure(dist_map: dict[str, metadata.Distribution], roots: list[str]) -> list[metadata.Distribution]:
    ordered: list[metadata.Distribution] = []
    visited: set[str] = set()
    queue = list(roots)

    while queue:
        dist_name = normalize_name(queue.pop(0))
        if dist_name in visited or dist_name in BLOCKED_DISTRIBUTIONS:
            continue

        dist = dist_map.get(dist_name)
        if dist is None:
            continue

        visited.add(dist_name)
        ordered.append(dist)

        for requirement in dist.requires or []:
            dependency_name = extract_requirement_name(requirement)
            if dependency_name and dependency_name not in visited and dependency_name not in BLOCKED_DISTRIBUTIONS:
                queue.append(dependency_name)

    return ordered


def copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def ignore_stdlib(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lower_name = name.lower()
        if lower_name in EXCLUDED_STDLIB_DIRS:
            ignored.add(name)
            continue
        if lower_name.endswith((".pyc", ".pyo")):
            ignored.add(name)
    return ignored


def ignore_backend_source(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        lower_name = name.lower()
        if (
            lower_name in EXCLUDED_BACKEND_DIRS
            or name in EXCLUDED_BACKEND_FILES
            or lower_name.startswith("pytest-cache-files-")
            or lower_name.endswith((".pyc", ".pyo"))
        ):
            ignored.add(name)
    return ignored


def copy_base_runtime(base_home: Path) -> None:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)

    for file_name in ("python.exe", "pythonw.exe", "python3.dll", "LICENSE.txt"):
        src = base_home / file_name
        if src.exists():
            copy_file(src, OUTPUT_ROOT / file_name)

    for dll_path in base_home.glob("python*.dll"):
        copy_file(dll_path, OUTPUT_ROOT / dll_path.name)

    for dll_path in base_home.glob("vcruntime*.dll"):
        copy_file(dll_path, OUTPUT_ROOT / dll_path.name)

    dlls_dir = base_home / "DLLs"
    if dlls_dir.exists():
        shutil.copytree(dlls_dir, OUTPUT_ROOT / "DLLs", dirs_exist_ok=True, ignore=ignore_stdlib)

    stdlib_dir = base_home / "Lib"
    if not stdlib_dir.exists():
        raise FileNotFoundError(f"Python stdlib not found: {stdlib_dir}")

    shutil.copytree(stdlib_dir, OUTPUT_ROOT / "Lib", dirs_exist_ok=True, ignore=ignore_stdlib)
    (OUTPUT_ROOT / "Lib" / SITE_PACKAGES_NAME).mkdir(parents=True, exist_ok=True)


def copy_backend_source() -> None:
    shutil.copytree(BACKEND_ROOT, BACKEND_OUTPUT_ROOT, dirs_exist_ok=True, ignore=ignore_backend_source)


def copy_selected_distributions(site_packages: Path, selected: list[metadata.Distribution]) -> list[str]:
    target_site_packages = OUTPUT_ROOT / "Lib" / SITE_PACKAGES_NAME
    copied_names: list[str] = []

    for dist in selected:
        dist_name = dist.metadata["Name"]
        copied_names.append(dist_name)
        for relative_path in dist.files or []:
            relative_parts = Path(relative_path).parts
            if ".." in relative_parts or "__pycache__" in relative_parts:
                continue
            source_path = Path(dist.locate_file(relative_path))
            if site_packages not in source_path.parents and source_path != site_packages:
                continue
            if source_path.is_dir():
                continue
            if source_path.suffix.lower() in {".pyc", ".pyo"}:
                continue
            destination_path = target_site_packages / relative_path
            copy_file(source_path, destination_path)

    return sorted(copied_names, key=str.lower)


def copy_pqc_runtime() -> None:
    """Copy the bundled OpenSSL PQC runtime when it has been built."""
    if PQC_RUNTIME_ROOT.exists():
        shutil.copytree(PQC_RUNTIME_ROOT, OUTPUT_ROOT / "pqc", dirs_exist_ok=True)


def write_manifest(base_home: Path, distributions: list[str]) -> None:
    manifest = {
        "python_home": str(base_home),
        "runtime_root": str(OUTPUT_ROOT),
        "distributions": distributions,
    }
    manifest_path = OUTPUT_ROOT / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    base_home = read_base_python_home()
    site_packages = get_venv_site_packages()

    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)
    if BACKEND_OUTPUT_ROOT.exists():
        shutil.rmtree(BACKEND_OUTPUT_ROOT)

    copy_backend_source()
    copy_base_runtime(base_home)

    dist_map = build_distribution_map(site_packages)
    root_distributions = parse_root_distributions()
    selected_distributions = resolve_distribution_closure(dist_map, root_distributions)
    copied_names = copy_selected_distributions(site_packages, selected_distributions)
    copy_pqc_runtime()
    write_manifest(base_home, copied_names)

    print(f"Prepared production backend runtime at {OUTPUT_ROOT}")
    print(f"Prepared production backend source at {BACKEND_OUTPUT_ROOT}")
    print(f"Copied {len(copied_names)} Python distributions")


if __name__ == "__main__":
    main()
