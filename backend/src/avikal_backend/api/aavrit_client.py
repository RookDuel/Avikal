"""Aavrit server HTTP client helpers."""

from __future__ import annotations

import os

from fastapi import HTTPException
import requests

from .errors import handle_requests_error


def normalize_aavrit_server_url(raw_url: str) -> str:
    url = (raw_url or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="Aavrit server URL is required.")
    local_http_hosts = ("localhost", "127.0.0.1")
    if not url.startswith(("http://", "https://")):
        if url.startswith(local_http_hosts):
            url = f"http://{url}"
        else:
            url = f"https://{url}"
    if url.startswith("http://"):
        normalized_host = url[len("http://"):].split("/", 1)[0].split(":", 1)[0].lower()
        if normalized_host in local_http_hosts:
            return url.rstrip("/")
        allow_insecure_aavrit = (
            (os.getenv("NODE_ENV") or "").lower() == "development"
            and os.getenv("AVIKAL_ALLOW_INSECURE_AAVRIT") == "1"
        )
        if not allow_insecure_aavrit:
            raise HTTPException(status_code=400, detail="Aavrit server URL must use HTTPS.")
    return url.rstrip("/")


def fetch_aavrit_capabilities(aavrit_url: str) -> dict:
    normalized_url = normalize_aavrit_server_url(aavrit_url)
    response = requests.get(f"{normalized_url}/config", timeout=20)
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Aavrit server validation failed.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid config response.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid config response.")

    mode = payload.get("mode")
    if mode not in {"public", "private"}:
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid mode.")

    return {"mode": mode}


def fetch_aavrit_public_key(aavrit_url: str, session_token: str | None = None) -> dict:
    headers = {}
    if session_token:
        headers["Authorization"] = f"Bearer {session_token}"

    response = requests.get(f"{normalize_aavrit_server_url(aavrit_url)}/public-key", headers=headers, timeout=30)
    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if response.status_code != 200:
        raise HTTPException(status_code=502, detail="Aavrit server public key fetch failed.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid public key response.") from exc

    if not isinstance(payload, dict) or not payload.get("success"):
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid public key response.")

    key_id = payload.get("key_id")
    sig_alg = payload.get("sig_alg")
    public_key_pem = payload.get("public_key_pem")
    if not isinstance(key_id, str) or not key_id:
        raise HTTPException(status_code=502, detail="Aavrit server public key response is missing key_id.")
    if sig_alg != "Ed25519":
        raise HTTPException(status_code=502, detail="Aavrit server uses an unsupported signature algorithm.")
    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise HTTPException(status_code=502, detail="Aavrit server public key response is missing the public key.")

    return {
        "key_id": key_id,
        "sig_alg": sig_alg,
        "public_key_pem": public_key_pem,
    }


def request_aavrit_commit(aavrit_url: str, *, data_hash: str, unlock_timestamp: int, session_token: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers["Authorization"] = f"Bearer {session_token}"

    try:
        response = requests.post(
            f"{aavrit_url}/commit",
            json={
                "data_hash": data_hash,
                "unlock_timestamp": unlock_timestamp,
            },
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise handle_requests_error(exc, "Aavrit server")

    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="Aavrit rate limit exceeded. Please try again later.")
    if response.status_code != 201:
        detail = response.text.strip() or "Aavrit commit failed."
        raise HTTPException(status_code=502, detail=detail)

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid commit response.") from exc

    if not isinstance(payload, dict) or not isinstance(payload.get("payload"), dict) or not isinstance(payload.get("signature"), str):
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid commit response.")
    return payload


def request_aavrit_reveal(aavrit_url: str, *, commit_id: str, session_token: str | None) -> dict:
    headers = {"Content-Type": "application/json"}
    if session_token:
        headers["Authorization"] = f"Bearer {session_token}"

    try:
        response = requests.post(
            f"{aavrit_url}/reveal",
            json={"commit_id": commit_id},
            headers=headers,
            timeout=30,
        )
    except requests.RequestException as exc:
        raise handle_requests_error(exc, "Aavrit server")

    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    if response.status_code == 404:
        raise HTTPException(status_code=404, detail="Aavrit commit not found.")
    if response.status_code == 429:
        raise HTTPException(status_code=429, detail="Aavrit rate limit exceeded. Please try again later.")
    if response.status_code != 200:
        detail = response.text.strip() or "Aavrit reveal failed."
        raise HTTPException(status_code=502, detail=detail)

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid reveal response.") from exc

    if not isinstance(payload, dict):
        raise HTTPException(status_code=502, detail="Aavrit server returned an invalid reveal response.")
    return payload
