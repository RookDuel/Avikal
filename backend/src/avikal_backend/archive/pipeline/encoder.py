"""Canonical Avikal archive encoder entry points.

All new archives use the authenticated AVI1 indexed payload. The historical
single-stream writer was removed; these names remain as public API facades and
always route through the canonical indexed writer.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import secrets
from datetime import datetime

from ..security.pqc_keyfile import PQC_STORAGE_MODE_EXTERNAL


def generate_key_b() -> bytes:
    """Generate a random 256-bit split-key component."""
    return secrets.token_bytes(32)


def create_avk_file_enhanced(
    input_filepath: str,
    output_filepath: str,
    unlock_datetime: datetime | None = None,
    password: str | None = None,
    keyphrase: list | None = None,
    username: str = "",
    variations_per_round: int = 5,
    use_timecapsule: bool = False,
    file_id: str | None = None,
    server_url: str | None = None,
    time_key: bytes | None = None,
    timecapsule_provider: str | None = None,
    aavrit_data_hash: str | None = None,
    aavrit_commit_hash: str | None = None,
    aavrit_server_key_id: str | None = None,
    aavrit_commit_signature: str | None = None,
    aavrit_route: dict | None = None,
    drand_round: int | None = None,
    drand_chain_hash: str | None = None,
    drand_chain_url: str | None = None,
    drand_ciphertext: str | None = None,
    drand_beacon_id: str | None = None,
    pqc_enabled: bool = False,
    pqc_storage_mode: str = PQC_STORAGE_MODE_EXTERNAL,
    pqc_keyfile_output: str | None = None,
    pqc_keyfile_protection_mode: str | None = None,
    pqc_keyfile_password: str | None = None,
    pqc_suite_id: str | None = None,
    pqc_custom_algorithms: dict | None = None,
    sender_message: str = "",
    creator_signing_identity: dict | None = None,
) -> dict:
    """Create a current-format archive from one source path."""
    from .multi_file_encoder import create_multi_file_avk

    return create_multi_file_avk(
        input_filepaths=[input_filepath],
        output_filepath=output_filepath,
        unlock_datetime=unlock_datetime,
        password=password,
        keyphrase=keyphrase,
        username=username,
        variations_per_round=variations_per_round,
        use_timecapsule=use_timecapsule,
        file_id=file_id,
        server_url=server_url,
        time_key=time_key,
        timecapsule_provider=timecapsule_provider,
        aavrit_data_hash=aavrit_data_hash,
        aavrit_commit_hash=aavrit_commit_hash,
        aavrit_server_key_id=aavrit_server_key_id,
        aavrit_commit_signature=aavrit_commit_signature,
        aavrit_route=aavrit_route,
        drand_round=drand_round,
        drand_chain_hash=drand_chain_hash,
        drand_chain_url=drand_chain_url,
        drand_ciphertext=drand_ciphertext,
        drand_beacon_id=drand_beacon_id,
        pqc_enabled=pqc_enabled,
        pqc_storage_mode=pqc_storage_mode,
        pqc_keyfile_output=pqc_keyfile_output,
        pqc_keyfile_protection_mode=pqc_keyfile_protection_mode,
        pqc_keyfile_password=pqc_keyfile_password,
        pqc_suite_id=pqc_suite_id,
        pqc_custom_algorithms=pqc_custom_algorithms,
        sender_message=sender_message,
        creator_signing_identity=creator_signing_identity,
    )


def create_avk_file(*args, **kwargs) -> dict:
    """Create a current-format archive through the stable public name."""
    return create_avk_file_enhanced(*args, **kwargs)


__all__ = ["create_avk_file", "create_avk_file_enhanced", "generate_key_b"]
