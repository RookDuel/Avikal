#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from importlib import metadata
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
OUTPUT_ROOT = PROJECT_ROOT / ".app-build" / "backend-runtime"
BACKEND_OUTPUT_ROOT = PROJECT_ROOT / ".app-build" / "backend"
PQC_RUNTIME_ROOT = PROJECT_ROOT / "runtime" / "pqc"
PYINSTALLER_SPEC = BACKEND_ROOT / "pyinstaller-backend.spec"
PYINSTALLER_TMP_ROOT = PROJECT_ROOT / ".tmp_build" / "pyinstaller-backend"
NATIVE_BUILD_SCRIPT = BACKEND_ROOT / "scripts" / "build_native_extension.py"


def copy_pqc_runtime() -> bool:
    if not PQC_RUNTIME_ROOT.exists():
        return False
    shutil.copytree(PQC_RUNTIME_ROOT, OUTPUT_ROOT / "pqc", dirs_exist_ok=True)
    return True


def build_backend_bundle() -> Path:
    if not PYINSTALLER_SPEC.exists():
        raise FileNotFoundError(f"Missing PyInstaller spec: {PYINSTALLER_SPEC}")

    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        str(PYINSTALLER_SPEC),
        "--distpath",
        str(PROJECT_ROOT / ".app-build"),
        "--workpath",
        str(PYINSTALLER_TMP_ROOT / "work"),
    ]
    subprocess.run(command, cwd=str(BACKEND_ROOT), check=True)

    if not BACKEND_OUTPUT_ROOT.exists():
        raise FileNotFoundError(f"PyInstaller did not create backend bundle: {BACKEND_OUTPUT_ROOT}")

    executable_name = "avikal-backend.exe" if sys.platform.startswith("win") else "avikal-backend"
    executable_path = BACKEND_OUTPUT_ROOT / executable_name
    if not executable_path.exists():
        raise FileNotFoundError(f"Backend executable missing after bundle build: {executable_path}")
    return executable_path


def build_native_extension() -> None:
    if not NATIVE_BUILD_SCRIPT.exists():
        raise FileNotFoundError(f"Missing native build script: {NATIVE_BUILD_SCRIPT}")
    subprocess.run([sys.executable, str(NATIVE_BUILD_SCRIPT)], cwd=str(PROJECT_ROOT), check=True)


def verify_packaged_backend_native_runtime(backend_executable: Path) -> None:
    subprocess.run([str(backend_executable), "--verify-native-runtime"], cwd=str(BACKEND_OUTPUT_ROOT), check=True)


def write_manifest(*, backend_executable: Path, pqc_runtime_present: bool) -> None:
    manifest = {
        "runtime_root": str(OUTPUT_ROOT),
        "backend_bundle_root": str(BACKEND_OUTPUT_ROOT),
        "backend_executable": str(backend_executable),
        "backend_bundle_format": "pyinstaller-onedir",
        "pyinstaller_version": metadata.version("pyinstaller"),
        "pqc_runtime_present": pqc_runtime_present,
    }
    manifest_path = OUTPUT_ROOT / "runtime-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def main() -> None:
    if OUTPUT_ROOT.exists():
        shutil.rmtree(OUTPUT_ROOT)
    if BACKEND_OUTPUT_ROOT.exists():
        shutil.rmtree(BACKEND_OUTPUT_ROOT)
    if PYINSTALLER_TMP_ROOT.exists():
        shutil.rmtree(PYINSTALLER_TMP_ROOT)

    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    build_native_extension()
    pqc_runtime_present = copy_pqc_runtime()
    backend_executable = build_backend_bundle()
    verify_packaged_backend_native_runtime(backend_executable)
    write_manifest(backend_executable=backend_executable, pqc_runtime_present=pqc_runtime_present)

    print(f"Prepared production backend bundle at {BACKEND_OUTPUT_ROOT}")
    print(f"Prepared production backend runtime at {OUTPUT_ROOT}")


if __name__ == "__main__":
    main()
