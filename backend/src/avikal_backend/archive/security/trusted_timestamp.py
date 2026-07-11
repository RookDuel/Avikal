"""Optional RFC 3161 timestamp evidence using the bundled OpenSSL runtime."""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

import requests

from .pqc_provider import resolve_openssl_executable


def _timestamp_configuration() -> tuple[str, str]:
    if os.environ.get("AVIKAL_PACKAGED_RUNTIME") == "1":
        policy_value = os.environ.get("AVIKAL_SECURITY_POLICY_FILE", "").strip()
        if not policy_value:
            return "", ""
        try:
            policy_path = Path(policy_value).resolve(strict=True)
            document = json.loads(policy_path.read_text(encoding="utf-8"))
            if document.get("format") != "avikal-build-security-policy" or document.get("version") != 1:
                return "", ""
            timestamp = document.get("rfc3161")
            if not isinstance(timestamp, dict):
                return "", ""
            url = timestamp.get("url")
            ca_file = timestamp.get("ca_file")
            if not isinstance(url, str) or not url.startswith("https://") or not isinstance(ca_file, str):
                return "", ""
            ca_path = (policy_path.parent / ca_file).resolve(strict=True)
            if not ca_path.is_file() or policy_path.parent not in ca_path.parents:
                return "", ""
            return url, str(ca_path)
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            return "", ""
    return (
        os.environ.get("AVIKAL_TSA_URL", "").strip(),
        os.environ.get("AVIKAL_TSA_CA_FILE", "").strip(),
    )


def request_rfc3161_timestamp(statement: bytes) -> dict:
    url, ca_file = _timestamp_configuration()
    imprint = hashlib.sha256(bytes(statement)).hexdigest()
    if not url or not ca_file:
        return {"status": "unavailable", "imprint_sha256": imprint}
    ca_path = Path(ca_file).expanduser().resolve()
    openssl = resolve_openssl_executable()
    if openssl is None or not ca_path.is_file():
        return {"status": "unavailable", "imprint_sha256": imprint}
    try:
        with tempfile.TemporaryDirectory(prefix="avikal-tsa-") as work:
            query = Path(work) / "request.tsq"
            response_path = Path(work) / "response.tsr"
            subprocess.run(
                [str(openssl), "ts", "-query", "-digest", imprint, "-sha256", "-cert", "-out", str(query)],
                check=True,
                capture_output=True,
                timeout=15,
            )
            response = requests.post(
                url,
                data=query.read_bytes(),
                headers={"Content-Type": "application/timestamp-query", "Accept": "application/timestamp-reply"},
                timeout=15,
            )
            response.raise_for_status()
            if len(response.content) == 0 or len(response.content) > 32 * 1024:
                raise ValueError("RFC 3161 response size is invalid")
            response_path.write_bytes(response.content)
            subprocess.run(
                [str(openssl), "ts", "-verify", "-queryfile", str(query), "-in", str(response_path), "-CAfile", str(ca_path)],
                check=True,
                capture_output=True,
                timeout=15,
            )
            return {
                "status": "verified",
                "imprint_sha256": imprint,
                "token": base64.b64encode(response.content).decode("ascii"),
                "tsa_url": url,
            }
    except Exception:
        return {"status": "unavailable", "imprint_sha256": imprint}


def verify_rfc3161_timestamp(statement: bytes, evidence: dict | None) -> str:
    if not isinstance(evidence, dict) or evidence.get("status") != "verified":
        return "signed_local_time"
    expected_imprint = hashlib.sha256(bytes(statement)).hexdigest()
    if evidence.get("imprint_sha256") != expected_imprint:
        raise ValueError("RFC 3161 timestamp imprint does not match the archive statement")
    _url, ca_file = _timestamp_configuration()
    openssl = resolve_openssl_executable()
    if not ca_file or openssl is None:
        return "timestamp_present_unverified"
    try:
        token = base64.b64decode(str(evidence.get("token") or ""), validate=True)
    except Exception as exc:
        raise ValueError("RFC 3161 timestamp token is malformed") from exc
    if not token or len(token) > 32 * 1024:
        raise ValueError("RFC 3161 timestamp token size is invalid")
    with tempfile.TemporaryDirectory(prefix="avikal-tsa-verify-") as work:
        data_path = Path(work) / "statement.bin"
        token_path = Path(work) / "response.tsr"
        data_path.write_bytes(bytes(statement))
        token_path.write_bytes(token)
        try:
            subprocess.run(
                [str(openssl), "ts", "-verify", "-data", str(data_path), "-in", str(token_path), "-CAfile", str(Path(ca_file).resolve())],
                check=True,
                capture_output=True,
                timeout=15,
            )
        except Exception as exc:
            raise ValueError("RFC 3161 timestamp verification failed") from exc
    return "trusted_timestamp_verified"
