"""Transport-neutral request models for the Avikal core service layer.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator

from avikal_backend.archive.security.pqc_keyfile import PQC_KEYFILE_PROTECTION_MODES, PQC_STORAGE_MODES


class EncryptRequest(BaseModel):
    input_files: List[str] = Field(min_length=1, max_length=512)
    excluded_input_paths: Optional[List[str]] = Field(default=None, max_length=4096)
    output_file: str = Field(min_length=1, max_length=4096)
    password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    unlock_datetime: Optional[str] = Field(default=None, min_length=1, max_length=128)
    use_timecapsule: bool = False
    timecapsule_provider: Optional[str] = None
    pqc_enabled: bool = False
    pqc_storage_mode: Optional[str] = Field(default=None, min_length=1, max_length=32)
    pqc_keyfile_output: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    pqc_keyfile_protection_mode: Optional[str] = Field(default=None, min_length=1, max_length=32)
    pqc_keyfile_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)

    @field_validator("input_files")
    @classmethod
    def _validate_input_files(cls, values: List[str]) -> List[str]:
        if not values or not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("At least one input file path is required")
        return values

    @field_validator("excluded_input_paths")
    @classmethod
    def _validate_excluded_input_paths(cls, values: Optional[List[str]]) -> Optional[List[str]]:
        if values is None:
            return None
        normalized = [value.strip() for value in values if isinstance(value, str) and value.strip()]
        return normalized or None

    @field_validator("keyphrase")
    @classmethod
    def _validate_keyphrase(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        words = [word.strip() for word in value if isinstance(word, str) and word.strip()]
        if len(words) != 21:
            raise ValueError("Keyphrase must contain exactly 21 words")
        return words

    @field_validator("pqc_storage_mode")
    @classmethod
    def _validate_pqc_storage_mode(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in PQC_STORAGE_MODES:
            raise ValueError("Unsupported PQC storage mode")
        return normalized

    @field_validator("pqc_keyfile_protection_mode")
    @classmethod
    def _validate_pqc_keyfile_protection_mode(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip().lower()
        if normalized not in PQC_KEYFILE_PROTECTION_MODES:
            raise ValueError("Unsupported PQC keyfile protection mode")
        return normalized


class DecryptRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_dir: Optional[str] = Field(default=None, max_length=4096)
    password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    pqc_keyfile: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    pqc_keyfile_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)

    @field_validator("output_dir", mode="before")
    @classmethod
    def _normalize_output_dir(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Output directory must be a string")
        normalized = value.strip()
        return normalized or None

    @field_validator("keyphrase")
    @classmethod
    def _validate_decrypt_keyphrase(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        words = [word.strip() for word in value if isinstance(word, str) and word.strip()]
        if len(words) != 21:
            raise ValueError("Keyphrase must contain exactly 21 words")
        return words


class ArchiveInspectRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)


class PqcKeyfileInspectRequest(BaseModel):
    keyfile_path: str = Field(min_length=1, max_length=4096)


class RekeyRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_file: str = Field(min_length=1, max_length=4096)
    old_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    old_keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    new_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    new_keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    force: bool = False

    @field_validator("old_keyphrase", "new_keyphrase")
    @classmethod
    def _validate_rekey_keyphrase(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        words = [word.strip() for word in value if isinstance(word, str) and word.strip()]
        if len(words) != 21:
            raise ValueError("Keyphrase must contain exactly 21 words")
        return words


class PreviewCleanupRequest(BaseModel):
    session_id: str = Field(pattern=r"^[0-9a-f]{32}$")


class CancelDecryptRequest(BaseModel):
    session_id: str | None = Field(default=None, pattern=r"^[0-9a-f]{32}$")


class GenerateKeyphraseRequest(BaseModel):
    word_count: int = 21
    language: str = "hindi"


class AavritServerCheckRequest(BaseModel):
    aavrit_url: str = Field(min_length=1, max_length=1024)


class AavritLoginRequest(BaseModel):
    aavrit_url: str = Field(min_length=1, max_length=1024)
    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=4096)


class VerifySessionRequest(BaseModel):
    session_token: str = Field(min_length=1, max_length=8192)
    aavrit_url: Optional[str] = Field(default=None, min_length=1, max_length=1024)
