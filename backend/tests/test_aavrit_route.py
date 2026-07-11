from __future__ import annotations

import pytest

from avikal_backend.archive.format.header import (
    attach_public_route_tags_to_keychain_pgn,
    extract_public_route_tags_from_keychain_pgn,
)


BASE_PGN = '[Event "Avikal"]\n\n1. e4 *\n'


def _route() -> dict:
    return {
        "protocol": "aavrit",
        "server_url": "https://aavrit.example",
        "escrow_id": "e" * 43,
        "capability": "c" * 43,
        "authority": {"authority_id": "a" * 43, "key_ids": {}, "public_keys": {}},
    }


@pytest.mark.parametrize("requires_pqc,pqc_storage_mode", [(False, None), (True, "external"), (True, "embedded")])
def test_aavrit_route_roundtrip_supports_all_pqc_storage_states(requires_pqc: bool, pqc_storage_mode: str | None) -> None:
    tagged = attach_public_route_tags_to_keychain_pgn(
        BASE_PGN,
        requires_password=True,
        requires_keyphrase=False,
        requires_pqc=requires_pqc,
        pqc_storage_mode=pqc_storage_mode,
        unlock_timestamp=1_900_000_000,
        aavrit_route=_route(),
        time_key_gated=True,
    )
    decoded = extract_public_route_tags_from_keychain_pgn(tagged)
    assert decoded["format_version"] == "3"
    assert decoded["aavrit_route"] == _route()
    assert decoded["time_key_gated"] is True
    assert decoded["pqc_storage_mode"] == pqc_storage_mode


def test_time_gated_route_requires_aavrit_material() -> None:
    with pytest.raises(ValueError, match="requires Aavrit"):
        attach_public_route_tags_to_keychain_pgn(
            BASE_PGN,
            requires_password=False,
            requires_keyphrase=False,
            requires_pqc=False,
            time_key_gated=True,
        )
