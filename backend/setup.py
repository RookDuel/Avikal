"""
Backend package setup entrypoint for Avikal.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import os
from pathlib import Path
import shutil

from setuptools import setup
from setuptools.command.build_py import build_py as build_py_orig
from setuptools_rust import Binding, RustExtension


PROJECT_ROOT = Path(__file__).resolve().parent
CARGO_BIN_DIR = Path.home() / ".cargo" / "bin"
DEFAULT_PQC_RUNTIME_ROOT = PROJECT_ROOT.parent / "runtime" / "pqc"
PACKAGE_PQC_RUNTIME_RELATIVE = Path("avikal_backend") / "runtime" / "pqc"


if CARGO_BIN_DIR.exists():
    os.environ["PATH"] = str(CARGO_BIN_DIR) + os.pathsep + os.environ.get("PATH", "")


class build_py(build_py_orig):
    def run(self):
        super().run()
        self._copy_pqc_runtime()

    def _copy_pqc_runtime(self) -> None:
        configured_runtime = os.environ.get("AVIKAL_PQC_RUNTIME_DIR")
        runtime_root = Path(configured_runtime) if configured_runtime else DEFAULT_PQC_RUNTIME_ROOT
        require_bundle = os.environ.get("AVIKAL_REQUIRE_BUNDLED_PQC_RUNTIME") == "1"
        target_root = Path(self.build_lib) / PACKAGE_PQC_RUNTIME_RELATIVE

        if not runtime_root.exists():
            if require_bundle:
                raise FileNotFoundError(f"Missing PQC runtime for bundled wheel: {runtime_root}")
            if target_root.exists():
                shutil.rmtree(target_root)
            self._avikal_pqc_outputs = []
            return

        if target_root.exists():
            shutil.rmtree(target_root)
        shutil.copytree(runtime_root, target_root)
        self._avikal_pqc_outputs = [str(path) for path in target_root.rglob("*") if path.is_file()]

    def get_outputs(self, include_bytecode=1):
        outputs = super().get_outputs(include_bytecode=include_bytecode)
        return outputs + getattr(self, "_avikal_pqc_outputs", [])


setup(
    cmdclass={"build_py": build_py},
    rust_extensions=[
        RustExtension(
            "avikal_backend._native",
            path=str(PROJECT_ROOT / "native" / "avikal_backend_native" / "Cargo.toml"),
            binding=Binding.PyO3,
            py_limited_api="cp311",
            debug=False,
            features=[],
        )
    ],
    options={"bdist_wheel": {"py_limited_api": "cp311"}},
)
