"""Transport-neutral request models for the Avikal core service layer.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from avikal_backend.archive.security.pqc_keyfile import PQC_KEYFILE_PROTECTION_MODES, PQC_STORAGE_MODES
from avikal_backend.archive.security.pqc_provider import (
    ML_DSA_ALGORITHMS,
    ML_KEM_ALGORITHMS,
    PQC_CUSTOM_SUITE_ID,
    SLH_DSA_ALGORITHMS,
    is_supported_pqc_suite_id,
)


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
    pqc_suite_id: Optional[str] = Field(default=None, min_length=1, max_length=64)
    pqc_custom_kem: Optional[str] = Field(default=None, min_length=1, max_length=64)
    pqc_custom_signature: Optional[str] = Field(default=None, min_length=1, max_length=64)
    pqc_custom_slh_signature: Optional[str] = Field(default=None, min_length=1, max_length=64)
    sender_message: Optional[str] = Field(default=None, max_length=2048)
    creator_identity_id: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    creator_signing_identity: Optional[Dict[str, Any]] = Field(default=None, exclude=True)

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

    @field_validator("sender_message")
    @classmethod
    def _validate_sender_message(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        from avikal_backend.archive.format.metadata_pack import normalize_sender_message

        normalized = normalize_sender_message(value)
        return normalized or None

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

    @field_validator("pqc_suite_id")
    @classmethod
    def _validate_pqc_suite_id(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if not is_supported_pqc_suite_id(normalized):
            raise ValueError("Unsupported PQC suite")
        return normalized

    @field_validator("pqc_custom_kem")
    @classmethod
    def _validate_pqc_custom_kem(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if normalized not in ML_KEM_ALGORITHMS:
            raise ValueError("Unsupported custom PQC KEM")
        return normalized

    @field_validator("pqc_custom_signature")
    @classmethod
    def _validate_pqc_custom_signature(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if normalized not in ML_DSA_ALGORITHMS:
            raise ValueError("Unsupported custom PQC signature")
        return normalized

    @field_validator("pqc_custom_slh_signature")
    @classmethod
    def _validate_pqc_custom_slh_signature(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        normalized = value.strip()
        if normalized not in SLH_DSA_ALGORITHMS:
            raise ValueError("Unsupported custom PQC long-term signature")
        return normalized

    def pqc_custom_algorithms(self) -> dict[str, str] | None:
        if self.pqc_suite_id != PQC_CUSTOM_SUITE_ID:
            return None
        if not self.pqc_custom_kem or not self.pqc_custom_signature or not self.pqc_custom_slh_signature:
            raise ValueError("Custom PQC mode requires one KEM, one ML-DSA signature, and one SLH-DSA signature")
        return {
            "post_quantum_kem": self.pqc_custom_kem,
            "authentication_signature": self.pqc_custom_signature,
            "long_term_signature": self.pqc_custom_slh_signature,
        }


class DecryptRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_dir: Optional[str] = Field(default=None, max_length=4096)
    password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    pqc_keyfile: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    pqc_keyfile_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    creator_trust_policy: Optional[Dict[str, str]] = Field(default=None, exclude=True)

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

    @field_validator("creator_trust_policy")
    @classmethod
    def _validate_creator_trust_policy(cls, value: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
        if value is None:
            return None
        if len(value) > 4096:
            raise ValueError("Creator trust policy is too large")
        normalized: Dict[str, str] = {}
        for identity_id, status in value.items():
            if not isinstance(identity_id, str) or not re.fullmatch(r"[0-9a-f]{64}", identity_id):
                raise ValueError("Creator trust policy contains an invalid identity")
            if status not in {"trusted", "revoked"}:
                raise ValueError("Creator trust policy contains an invalid status")
            normalized[identity_id] = status
        return normalized


class ArchiveInspectRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)


class ArchiveSplitVolumesRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_dir: Optional[str] = Field(default=None, max_length=4096)
    volume_size_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=64 * 1024 * 1024,
        le=4 * 1024 * 1024 * 1024 * 1024,
    )

    @field_validator("output_dir", mode="before")
    @classmethod
    def _normalize_volume_output_dir(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Multipart output directory must be a string")
        return value.strip() or None


class ArchiveJoinVolumesRequest(BaseModel):
    volume_set_dir: str = Field(min_length=1, max_length=4096)
    output_file: str = Field(min_length=1, max_length=4096)


class ArchiveOpenSessionRequest(DecryptRequest):
    pass


class ArchiveSelectionRequest(BaseModel):
    session_id: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_ids: List[str] = Field(min_length=1, max_length=100000)

    @field_validator("entry_ids")
    @classmethod
    def _validate_entry_ids(cls, values: List[str]) -> List[str]:
        if len(values) != len(set(values)):
            raise ValueError("Selected archive entry IDs must be unique")
        if not all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) for value in values):
            raise ValueError("Selected archive entry ID is invalid")
        return values


class ArchiveSessionRequest(BaseModel):
    session_id: str = Field(pattern=r"^[0-9a-f]{64}$")


class PqcKeyfileInspectRequest(BaseModel):
    keyfile_path: str = Field(min_length=1, max_length=4096)


class RekeyRequest(BaseModel):
    input_file: str = Field(min_length=1, max_length=4096)
    output_file: str = Field(min_length=1, max_length=4096)
    old_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    old_keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    new_password: Optional[str] = Field(default=None, min_length=1, max_length=4096)
    new_keyphrase: Optional[List[str]] = Field(default=None, min_length=1, max_length=64)
    creator_identity_id: Optional[str] = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    creator_signing_identity: Optional[Dict[str, Any]] = Field(default=None, exclude=True)
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
