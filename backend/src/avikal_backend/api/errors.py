"""User-facing API error translation helpers."""

from __future__ import annotations

import logging
import re

import requests
from fastapi import HTTPException


log = logging.getLogger("avikal.api")

_ERROR_PATTERNS = [
    (re.compile(r"authentication failed|auth.*fail|invalid.*token|not authenticated|login.*required", re.I), "Authentication failed. Please try again."),
    (re.compile(r"time.?capsule.*locked|locked.*unlock|unlocks in|time.?lock|still locked", re.I), "This capsule is still locked."),
    (re.compile(r"password or keyphrase is required|required for protected archive mode", re.I), "This protected archive requires a password or keyphrase."),
    (re.compile(r"checksum mismatch", re.I), "Invalid keyphrase checksum. Please check the phrase and try again."),
    (re.compile(r"invalid word:", re.I), "Invalid keyphrase word. Please check the phrase and try again."),
    (re.compile(r"invalid length: keyphrase must contain", re.I), "Invalid keyphrase length. Please use a supported mnemonic length."),
    (re.compile(r"incorrect password|wrong password|invalid password|incorrect keyphrase|wrong keyphrase", re.I), "Incorrect password or keyphrase. Please check and try again."),
    (re.compile(r"pqc keyfile not found|requires an external pqc keyfile|provide the \.avkkey|keyfile does not match this archive", re.I), "This archive requires the correct .avkkey file. Please provide the matching PQC keyfile."),
    (re.compile(r"failed to decrypt the pqc keyfile|pqc decapsulation failed", re.I), "The PQC keyfile could not be unlocked. Check the password, keyphrase, and keyfile, then try again."),
    (re.compile(r"integrity check|file.*corrupt|corrupt.*file|checksum.*fail|hash.*mismatch", re.I), "File integrity check failed. The file may be corrupted."),
    (re.compile(r"ntp|time verification|time sync|time\.google\.com", re.I), "Time verification failed. Check your internet connection."),
    (re.compile(r"network error|connection.*refused|econnrefused|no internet|offline", re.I), "Network error. Check your internet connection and try again."),
    (re.compile(r"file not found|no such file|enoent|path.*not.*exist", re.I), "File not found. Please check the file path."),
    (re.compile(r"permission denied|eacces|access denied", re.I), "Permission denied. Check file permissions."),
]


def friendly_error(raw: str) -> str:
    log.debug("Raw error (internal): %s", raw)
    for pattern, message in _ERROR_PATTERNS:
        if pattern.search(raw):
            return message
    return "An unexpected error occurred. Please try again."


def http_error(status_code: int, raw: str, *, preserve_detail: str | None = None) -> HTTPException:
    detail = preserve_detail if preserve_detail is not None else friendly_error(raw)
    return HTTPException(status_code=status_code, detail=detail)


def preserve_time_lock_detail(raw: str) -> str | None:
    text = (raw or "").strip()
    if not text:
        return None
    if "locked until" in text.lower() or "current time:" in text.lower():
        return text
    if "still locked" in text.lower() and ("unlock" in text.lower() or "available at" in text.lower()):
        return text
    return None


def handle_requests_error(exc: Exception, context: str = "external server") -> HTTPException:
    if isinstance(exc, requests.exceptions.Timeout):
        log.warning("%s request timed out: %s", context, exc)
        return HTTPException(
            status_code=504,
            detail="Network error. Check your internet connection and try again.",
        )
    if isinstance(exc, requests.exceptions.ConnectionError):
        log.warning("%s connection error: %s", context, exc)
        return HTTPException(
            status_code=503,
            detail="Network error. Check your internet connection and try again.",
        )
    raise exc
