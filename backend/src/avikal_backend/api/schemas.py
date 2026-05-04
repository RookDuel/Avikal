"""Pydantic request and response models for the backend API."""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


class EncryptRequest(BaseModel):
    input_files: List[str] = Field(min_length=1, max_length=512)
    output_file: str = Field(min_length=1, max_length=4096)
    password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    unlock_datetime: Optional[str] = Field(default=None, min_length=1, max_length=128)
    use_timecapsule: bool = False
    timecapsule_provider: Optional[str] = None
    pqc_enabled: bool = False
    pqc_keyfile_output: Optional[str] = Field(default=None, min_length=1, max_length=4096)

    @field_validator("input_files")
    @classmethod
    def _validate_input_files(cls, values: List[str]) -> List[str]:
        if not values or not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError("At least one input file path is required")
        return values

    @field_validator("keyphrase")
    @classmethod
    def _validate_keyphrase(cls, value: Optional[List[str]]) -> Optional[List[str]]:
        if value is None:
            return None
        words = [word.strip() for word in value if isinstance(word, str) and word.strip()]
        if len(words) != 21:
            raise ValueError("Keyphrase must contain exactly 21 words")
        return words


class DecryptRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_dir: Optional[str] = Field(default=None, max_length=4096)
    password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    pqc_keyfile: Optional[str] = Field(default=None, min_length=1, max_length=4096)

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
