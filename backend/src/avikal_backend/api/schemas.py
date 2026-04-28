"""Pydantic request and response models for the backend API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel


class EncryptRequest(BaseModel):
    input_files: List[str]
    output_file: str
    password: Optional[str] = None
    keyphrase: Optional[List[str]] = None
    unlock_datetime: Optional[str] = None
    use_timecapsule: bool = False
    timecapsule_provider: Optional[str] = None
    pqc_enabled: bool = False
    pqc_keyfile_output: Optional[str] = None


class DecryptRequest(BaseModel):
    input_file: str
    output_dir: str
    password: Optional[str] = None
    keyphrase: Optional[List[str]] = None
    pqc_keyfile: Optional[str] = None


class ArchiveInspectRequest(BaseModel):
    input_file: str


class PreviewCleanupRequest(BaseModel):
    session_id: str


class GenerateKeyphraseRequest(BaseModel):
    word_count: int = 21
    language: str = "hindi"


class AavritServerCheckRequest(BaseModel):
    aavrit_url: str


class AavritLoginRequest(BaseModel):
    aavrit_url: str
    email: str
    password: str


class VerifySessionRequest(BaseModel):
    session_token: str
    aavrit_url: Optional[str] = None
