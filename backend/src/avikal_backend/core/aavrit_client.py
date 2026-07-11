"""Strict client for the Aavrit escrow and release protocol."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from urllib.parse import urlsplit
from dataclasses import dataclass
from typing import Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from avikal_backend.archive.security.native_bridge import (
    openssl_kem_encapsulate,
    openssl_verify_signature,
)
from avikal_backend.archive.security.pqc_provider import require_libcrypto


AAVRIT_PROTOCOL = "aavrit"
AAVRIT_AUTHORITY_SUITE = "ML-KEM-1024+X25519/HKDF-SHA3-256/AES-256-GCM"
AAVRIT_SIGNATURE_SUITE = "Ed25519+ML-DSA-87+SLH-DSA-SHA2-256s"
RELEASE_KEY_DOMAIN = b"AavritReleaseKeyCommitment\0"
HYBRID_INFO = b"AavritHybridReleaseEnvelope"
MAX_RESPONSE_BYTES = 256 * 1024
HTTP_TIMEOUT = (10, 30)


class AavritClientError(RuntimeError):
    def __init__(self, message: str, *, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


@dataclass(frozen=True)
class AavritEscrow:
    time_key: bytes
    protected_metadata: dict[str, Any]
    public_route: dict[str, Any]


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str, *, field: str, expected: int | None = None, maximum: int = 65_536) -> bytes:
    if not isinstance(value, str) or not value or len(value) > maximum * 2:
        raise AavritClientError(f"Aavrit {field} is invalid", status_code=400)
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except Exception as exc:
        raise AavritClientError(f"Aavrit {field} is malformed", status_code=400) from exc
    if len(decoded) > maximum or (expected is not None and len(decoded) != expected):
        raise AavritClientError(f"Aavrit {field} has an invalid size", status_code=400)
    if b64url_encode(decoded) != value:
        raise AavritClientError(f"Aavrit {field} is not canonical", status_code=400)
    return decoded


def release_key_commitment(time_key: bytes) -> str:
    if not isinstance(time_key, bytes) or len(time_key) != 32:
        raise ValueError("Aavrit release key must be exactly 32 bytes")
    return b64url_encode(hashlib.sha256(RELEASE_KEY_DOMAIN + time_key).digest())


def random_commitment() -> str:
    return b64url_encode(secrets.token_bytes(32))


def normalize_authority_url(value: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 2048:
        raise AavritClientError("Aavrit authority URL is invalid", status_code=400)
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.hostname or parsed.username or parsed.password:
        raise AavritClientError("Aavrit authority URL is invalid", status_code=400)
    if parsed.query or parsed.fragment or parsed.path not in {"", "/"}:
        raise AavritClientError("Aavrit authority URL must be an origin without a path, query, or fragment", status_code=400)
    localhost = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not localhost:
        raise AavritClientError("Aavrit authority requires HTTPS", status_code=400)
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")


def fetch_authority(server_url: str) -> dict[str, Any]:
    server_url = normalize_authority_url(server_url)
    response = _request("GET", f"{server_url}/.well-known/aavrit-authority.json")
    authority = response.get("authority") if response.get("success") is True else None
    return validate_authority(authority)


def validate_authority(envelope: Any) -> dict[str, Any]:
    _exact(envelope, {"payload", "signatures"}, "authority envelope")
    payload = validate_authority_payload(envelope["payload"])
    signatures = envelope["signatures"]
    verify_authority_signatures(payload, signatures, payload)
    return {"payload": payload, "signatures": signatures}


def validate_authority_payload(payload: Any) -> dict[str, Any]:
    _exact(payload, {"protocol", "authority_id", "encryption_suite", "signature_suite", "key_ids", "public_keys"}, "authority bundle")
    _exact(payload["key_ids"], {"ed25519", "ml_dsa", "slh_dsa", "ml_kem", "x25519"}, "authority key identifiers")
    _exact(payload["public_keys"], {"ed25519", "ml_dsa", "slh_dsa", "ml_kem", "x25519"}, "authority public keys")
    if payload["protocol"] != AAVRIT_PROTOCOL or payload["encryption_suite"] != AAVRIT_AUTHORITY_SUITE:
        raise AavritClientError("Aavrit authority uses an unsupported encryption protocol", status_code=400)
    if payload["signature_suite"] != AAVRIT_SIGNATURE_SUITE:
        raise AavritClientError("Aavrit authority uses an unsupported signature protocol", status_code=400)
    expected_id = b64url_encode(hashlib.sha256(canonical_json_bytes({
        "protocol": payload["protocol"], "key_ids": payload["key_ids"], "public_keys": payload["public_keys"],
    })).digest())
    if not secrets.compare_digest(str(payload["authority_id"]), expected_id):
        raise AavritClientError("Aavrit authority identifier verification failed", status_code=400)
    return payload


def verify_authority_signatures(payload: Any, signatures: Any, authority_payload: dict[str, Any]) -> None:
    _exact(signatures, {"ed25519", "ml_dsa", "slh_dsa"}, "authority signatures")
    message = canonical_json_bytes(payload)
    keys = authority_payload["public_keys"]
    try:
        ed_key = serialization.load_pem_public_key(keys["ed25519"].encode("ascii"))
        if not isinstance(ed_key, ed25519.Ed25519PublicKey):
            raise ValueError("not Ed25519")
        ed_key.verify(b64url_decode(signatures["ed25519"], field="Ed25519 signature"), message)
        library = str(require_libcrypto())
        if not openssl_verify_signature(library, keys["ml_dsa"], message, b64url_decode(signatures["ml_dsa"], field="ML-DSA signature")):
            raise ValueError("ML-DSA verification failed")
        if not openssl_verify_signature(library, keys["slh_dsa"], message, b64url_decode(signatures["slh_dsa"], field="SLH-DSA signature")):
            raise ValueError("SLH-DSA verification failed")
    except AavritClientError:
        raise
    except Exception as exc:
        raise AavritClientError("Aavrit authority signature verification failed", status_code=400) from exc


def create_escrow(
    server_url: str,
    *,
    unlock_timestamp: int,
    session_token: str | None,
    data_commitment: str | None = None,
) -> AavritEscrow:
    server_url = normalize_authority_url(server_url)
    authority = fetch_authority(server_url)
    authority_payload = authority["payload"]
    time_key = secrets.token_bytes(32)
    data_commitment = data_commitment or random_commitment()
    commitment = release_key_commitment(time_key)
    context = {
        "dataCommitment": data_commitment,
        "releaseKeyCommitment": commitment,
        "unlockTimestamp": int(unlock_timestamp),
    }
    wrapped = _wrap_release_key(time_key, authority_payload, context)
    request_body = {
        "protocol": AAVRIT_PROTOCOL,
        "data_commitment": data_commitment,
        "release_key_commitment": commitment,
        "unlock_timestamp": int(unlock_timestamp),
        "access_policy": "capability_after_release",
        "wrapped_release": wrapped,
    }
    headers = {"Authorization": f"Bearer {session_token}"} if session_token else None
    response = _request("POST", f"{server_url}/escrow", json_body=request_body, headers=headers)
    if response.get("success") is not True:
        raise AavritClientError("Aavrit rejected the escrow request")
    receipt = response.get("receipt")
    capability = response.get("capability")
    _verify_receipt(receipt, authority_payload, request_body)
    b64url_decode(capability, field="release capability", expected=32)
    receipt_digest = b64url_encode(hashlib.sha256(canonical_json_bytes(receipt)).digest())
    protected_metadata = {
        "protocol": AAVRIT_PROTOCOL,
        "escrow_id": receipt["payload"]["escrow_id"],
        "data_commitment": data_commitment,
        "release_key_commitment": commitment,
        "authority_id": authority_payload["authority_id"],
        "receipt_sha256": receipt_digest,
    }
    public_route = {
        "protocol": AAVRIT_PROTOCOL,
        "server_url": server_url,
        "escrow_id": receipt["payload"]["escrow_id"],
        "capability": capability,
        "authority": authority_payload,
    }
    return AavritEscrow(time_key=time_key, protected_metadata=protected_metadata, public_route=public_route)


def release_escrow(public_route: dict[str, Any], *, expected_unlock_timestamp: int | None = None) -> tuple[bytes, dict[str, Any]]:
    _exact(public_route, {"protocol", "server_url", "escrow_id", "capability", "authority"}, "Aavrit public route")
    if public_route["protocol"] != AAVRIT_PROTOCOL:
        raise AavritClientError("Unsupported Aavrit archive route", status_code=400)
    server_url = normalize_authority_url(public_route["server_url"])
    if server_url != public_route["server_url"]:
        raise AavritClientError("Aavrit archive route URL is not canonical", status_code=400)
    authority_payload = validate_authority_payload(public_route["authority"])
    live = fetch_authority(server_url)
    if not secrets.compare_digest(live["payload"]["authority_id"], authority_payload["authority_id"]):
        raise AavritClientError("Aavrit authority identity changed; this archive cannot trust the active endpoint", status_code=400)
    body = {"protocol": AAVRIT_PROTOCOL, "escrow_id": public_route["escrow_id"], "capability": public_route["capability"]}
    response = _request("POST", f"{server_url}/release", json_body=body)
    release = response.get("release") if response.get("success") is True else None
    _exact(release, {"payload", "signatures"}, "release envelope")
    payload = release["payload"]
    required = {"protocol", "type", "escrow_id", "receipt_sha256", "data_commitment", "release_key_commitment", "release_key", "unlock_timestamp", "eligible_at", "first_served_at", "served_at", "authority_id", "authority_key_ids", "signature_suite"}
    _exact(payload, required, "release statement")
    verify_authority_signatures(payload, release["signatures"], authority_payload)
    if payload["protocol"] != AAVRIT_PROTOCOL or payload["type"] != "release_statement":
        raise AavritClientError("Aavrit release statement is invalid", status_code=400)
    if payload["escrow_id"] != public_route["escrow_id"] or payload["authority_id"] != authority_payload["authority_id"]:
        raise AavritClientError("Aavrit release statement does not match this archive", status_code=400)
    if expected_unlock_timestamp is not None and payload["unlock_timestamp"] != int(expected_unlock_timestamp):
        raise AavritClientError("Aavrit release timestamp does not match the archive route", status_code=400)
    time_key = b64url_decode(payload["release_key"], field="release key", expected=32)
    if not secrets.compare_digest(release_key_commitment(time_key), payload["release_key_commitment"]):
        raise AavritClientError("Aavrit release key commitment verification failed", status_code=400)
    return time_key, release


def verify_protected_receipt(protected_metadata: dict[str, Any], public_route: dict[str, Any], release: dict[str, Any]) -> None:
    required = {"protocol", "escrow_id", "data_commitment", "release_key_commitment", "authority_id", "receipt_sha256"}
    _exact(protected_metadata, required, "protected Aavrit metadata")
    release_payload = release["payload"]
    if not secrets.compare_digest(protected_metadata["receipt_sha256"], release_payload["receipt_sha256"]):
        raise AavritClientError("Aavrit release does not match the signed escrow receipt", status_code=400)
    for field in ("escrow_id", "data_commitment", "release_key_commitment", "unlock_timestamp", "authority_id"):
        if field == "unlock_timestamp":
            continue
        if protected_metadata.get(field) != release_payload.get(field):
            raise AavritClientError(f"Aavrit {field} binding verification failed", status_code=400)


def _wrap_release_key(time_key: bytes, authority: dict[str, Any], context: dict[str, Any]) -> dict[str, str]:
    library = str(require_libcrypto())
    ml_ciphertext, ml_secret = openssl_kem_encapsulate(library, authority["public_keys"]["ml_kem"])
    x_public = serialization.load_pem_public_key(authority["public_keys"]["x25519"].encode("ascii"))
    if not isinstance(x_public, x25519.X25519PublicKey):
        raise AavritClientError("Aavrit X25519 authority key is invalid", status_code=400)
    ephemeral = x25519.X25519PrivateKey.generate()
    x_secret = ephemeral.exchange(x_public)
    ephemeral_der = ephemeral.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    salt = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    key = HKDF(algorithm=hashes.SHA3_256(), length=32, salt=salt, info=HYBRID_INFO).derive(ml_secret + x_secret)
    aad = canonical_json_bytes({
        "protocol": AAVRIT_PROTOCOL,
        "suite": AAVRIT_AUTHORITY_SUITE,
        "data_commitment": context["dataCommitment"],
        "release_key_commitment": context["releaseKeyCommitment"],
        "unlock_timestamp": context["unlockTimestamp"],
        "authority_id": authority["authority_id"],
        "ml_kem_key_id": authority["key_ids"]["ml_kem"],
        "x25519_key_id": authority["key_ids"]["x25519"],
    })
    ciphertext = AESGCM(key).encrypt(nonce, time_key, aad)
    return {
        "suite": AAVRIT_AUTHORITY_SUITE,
        "authority_id": authority["authority_id"],
        "ml_kem_key_id": authority["key_ids"]["ml_kem"],
        "x25519_key_id": authority["key_ids"]["x25519"],
        "salt": b64url_encode(salt),
        "nonce": b64url_encode(nonce),
        "ml_kem_ciphertext": b64url_encode(ml_ciphertext),
        "x25519_ciphertext": b64url_encode(ephemeral_der),
        "ciphertext": b64url_encode(ciphertext),
    }


def _verify_receipt(receipt: Any, authority: dict[str, Any], request_body: dict[str, Any] | None) -> None:
    _exact(receipt, {"payload", "signatures"}, "escrow receipt")
    payload = receipt["payload"]
    required = {"protocol", "type", "escrow_id", "data_commitment", "release_key_commitment", "unlock_timestamp", "access_policy", "capability_hash", "wrapped_release_sha256", "created_at", "authority_id", "authority_key_ids", "encryption_suite", "signature_suite"}
    _exact(payload, required, "escrow receipt payload")
    verify_authority_signatures(payload, receipt["signatures"], authority)
    b64url_decode(payload["escrow_id"], field="escrow identifier", expected=32)
    if payload["protocol"] != AAVRIT_PROTOCOL or payload["type"] != "escrow_receipt" or payload["authority_id"] != authority["authority_id"]:
        raise AavritClientError("Aavrit escrow receipt is invalid", status_code=400)
    if request_body is not None:
        for receipt_field, request_field in (("data_commitment", "data_commitment"), ("release_key_commitment", "release_key_commitment"), ("unlock_timestamp", "unlock_timestamp"), ("access_policy", "access_policy")):
            if payload[receipt_field] != request_body[request_field]:
                raise AavritClientError("Aavrit escrow receipt does not match the request", status_code=400)
        wrapped_digest = b64url_encode(hashlib.sha256(canonical_json_bytes(request_body["wrapped_release"])).digest())
        if not secrets.compare_digest(payload["wrapped_release_sha256"], wrapped_digest):
            raise AavritClientError("Aavrit wrapped-release commitment verification failed", status_code=400)


def _request(method: str, url: str, *, json_body: dict[str, Any] | None = None, headers: dict[str, str] | None = None) -> dict[str, Any]:
    try:
        response = requests.request(method, url, json=json_body, headers=headers, timeout=HTTP_TIMEOUT, allow_redirects=False)
    except requests.RequestException as exc:
        raise AavritClientError("Aavrit authority is unavailable") from exc
    if response.is_redirect:
        raise AavritClientError("Aavrit authority redirects are not permitted", status_code=400)
    if len(response.content) > MAX_RESPONSE_BYTES:
        raise AavritClientError("Aavrit authority response is oversized", status_code=400)
    if response.status_code == 423:
        raise AavritClientError("Aavrit release time has not been reached", status_code=423)
    if response.status_code in {401, 403}:
        raise AavritClientError("Aavrit authentication is required or expired", status_code=response.status_code)
    if response.status_code == 404:
        raise AavritClientError("Aavrit escrow was not found", status_code=404)
    if response.status_code == 429:
        raise AavritClientError("Aavrit rate limit exceeded", status_code=429)
    if response.status_code < 200 or response.status_code >= 300:
        try:
            detail = response.json().get("error")
        except Exception:
            detail = None
        message = str(detail) if isinstance(detail, str) and 0 < len(detail) <= 240 else "Aavrit authority rejected the request"
        raise AavritClientError(message, status_code=400 if response.status_code == 400 else 502)
    try:
        payload = response.json()
    except ValueError as exc:
        raise AavritClientError("Aavrit authority returned invalid JSON", status_code=400) from exc
    if not isinstance(payload, dict):
        raise AavritClientError("Aavrit authority returned an invalid response", status_code=400)
    return payload


def _exact(value: Any, keys: set[str], label: str) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise AavritClientError(f"{label} has an invalid structure", status_code=400)
