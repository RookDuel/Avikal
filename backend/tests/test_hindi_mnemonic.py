"""
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import unicodedata

import pytest

from avikal_backend.mnemonic.generator import HindiMnemonic, normalize_mnemonic_phrase, validate_mnemonic
from avikal_backend.mnemonic.wordlist import ROMAN_WORDLIST_ID, WORDLIST_ID


def test_generated_mnemonic_is_21_words_and_valid():
    mnemonic = HindiMnemonic()
    phrase = mnemonic.generate(21)

    assert len(phrase) == 21
    assert mnemonic.validate(phrase)
    assert mnemonic.wordlist_id == WORDLIST_ID


def test_checksum_mismatch_is_rejected_before_kdf():
    mnemonic = HindiMnemonic()
    phrase = mnemonic.generate(21)
    candidates = mnemonic.get_wordlist()[:32]
    for replacement in candidates:
        tampered = phrase.copy()
        if replacement == tampered[-1]:
            continue
        tampered[-1] = replacement
        with pytest.raises(ValueError, match="Checksum mismatch|Invalid word"):
            mnemonic.validate_or_raise(tampered)
        return

    raise AssertionError("Failed to produce a checksum-mismatching mnemonic candidate")


def test_invalid_word_is_rejected():
    mnemonic = HindiMnemonic()
    phrase = mnemonic.generate(21)
    phrase[3] = "अवैधशब्द"

    with pytest.raises(ValueError, match="Invalid word"):
        mnemonic.validate_or_raise(phrase)


def test_phrase_normalization_produces_same_canonical_output():
    mnemonic = HindiMnemonic()
    canonical = mnemonic.phrase_to_string(mnemonic.generate(21))
    stretched = f"  {canonical.replace(' ', '   ')}  "
    nfkc_variant = unicodedata.normalize("NFKC", stretched)

    assert normalize_mnemonic_phrase(stretched) == canonical
    assert normalize_mnemonic_phrase(nfkc_variant) == canonical
    assert validate_mnemonic(stretched)


def test_romanized_word_pairs_match_canonical_wordlist():
    mnemonic = HindiMnemonic()
    pairs = mnemonic.wordlist.get_roman_pairs()

    assert mnemonic.wordlist.roman_wordlist_id == ROMAN_WORDLIST_ID
    assert len(pairs) == 2048
    assert [pair["hindi"] for pair in pairs] == mnemonic.get_wordlist()
    assert pairs[0] == {"index": 1, "hindi": "आकाश", "roman": "aakash"}
    assert all(pair["roman"] for pair in pairs)
