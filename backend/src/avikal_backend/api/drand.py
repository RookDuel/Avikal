"""drand timelock helper integration."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import shutil
import subprocess

from fastapi import HTTPException

from .errors import friendly_error


log = logging.getLogger("avikal.api")


def drand_helper_path() -> str:
    project_root = Path(__file__).resolve().parents[3]
    return str(project_root / "scripts" / "drand_timelock_helper.mjs")


def run_drand_helper(payload: dict) -> dict:
    node_binary = shutil.which("node")
    if not node_binary:
        raise HTTPException(status_code=500, detail="drand helper runtime is unavailable on this system.")

    helper_path = drand_helper_path()
    if not os.path.exists(helper_path):
        raise HTTPException(status_code=500, detail="drand helper script is missing.")

    try:
        completed = subprocess.run(
            [node_binary, helper_path],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
            timeout=60,
            cwd=str(Path(helper_path).parent),
        )
    except subprocess.TimeoutExpired as exc:
        log.error("drand helper timed out: %s", exc)
        raise HTTPException(status_code=504, detail="drand network request timed out. Please try again.")
    except Exception as exc:
        log.error("drand helper execution failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail="drand helper execution failed.")

    raw_output = (completed.stdout or "").strip()
    if not raw_output:
        raw_output = (completed.stderr or "").strip()

    try:
        helper_result = json.loads(raw_output)
    except json.JSONDecodeError:
        log.error("Invalid drand helper response: stdout=%r stderr=%r", completed.stdout, completed.stderr)
        raise HTTPException(status_code=500, detail="drand helper returned an invalid response.")

    if completed.returncode != 0 or not helper_result.get("success"):
        error_message = helper_result.get("error") or helper_result.get("message") or "drand operation failed."
        if helper_result.get("status") == "locked":
            available_at = helper_result.get("unlock_iso")
            if available_at:
                raise HTTPException(
                    status_code=403,
                    detail=f"This capsule is still locked. drand unlock becomes available at {available_at}.",
                )
            raise HTTPException(status_code=403, detail="This capsule is still locked.")
        raise HTTPException(status_code=503, detail=friendly_error(error_message))

    return helper_result
