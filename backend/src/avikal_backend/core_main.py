"""
Unified Avikal core entrypoint for CLI and desktop stdio RPC.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import sys


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    from avikal_backend.runtime_requirements import harden_process_runtime

    harden_process_runtime("Avikal core")

    from avikal_backend.core.temp_janitor import cleanup_startup_temp_artifacts

    cleanup_startup_temp_artifacts()
    if "--gui-mode" in args:
        os.environ["AVIKAL_STDIO_RPC"] = "1"
        from avikal_backend.core.rpc_stdio import run_stdio_rpc

        return run_stdio_rpc()

    if "--verify-runtime" in args or "--verify-native-runtime" in args:
        from avikal_backend.archive.security.pqc_provider import provider_status
        from avikal_backend.runtime_requirements import ensure_native_crypto_runtime, verify_publisher_runtime_manifest

        try:
            ensure_native_crypto_runtime("Avikal core")
            if "--verify-runtime" in args:
                verify_publisher_runtime_manifest()
            status = provider_status(verify_runtime_integrity="--verify-runtime" in args)
            if not status.get("available"):
                raise RuntimeError(status.get("error") or "PQC runtime unavailable")
        except Exception as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0

    from avikal_backend.cli.main import main as cli_main

    return cli_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
