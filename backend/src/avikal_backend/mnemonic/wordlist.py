"""
Hindi Wordlist Management for Avikal Mnemonic System.
Loads and manages the frozen canonical Hindi wordlist for mnemonic generation.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import os
import re
import unicodedata
from typing import List


WORDLIST_ID = "avikal-hi-2048-v1"
WORDLIST_FILENAME = "wordlist_hi_2048_v1.txt"
ROMAN_WORDLIST_ID = "avikal-hi-roman-2048-v1"
ROMAN_WORDLIST_FILENAME = "wordlist_hi_roman_2048_v1.txt"
WORDLIST_SIZE = 2048
_SPACE_RE = re.compile(r"\s+")
_ROMAN_WORD_RE = re.compile(r"[a-z0-9'\-]+")


def normalize_hindi_word(word: str) -> str:
    """Normalize a single Hindi mnemonic word into canonical NFKC form."""
    if not isinstance(word, str):
        raise ValueError("Invalid word: expected string input")
    return unicodedata.normalize("NFKC", word).strip()


def normalize_phrase_text(phrase: str) -> str:
    """Normalize user-entered phrase text before validation or KDF."""
    if not isinstance(phrase, str):
        raise ValueError("Invalid phrase: expected string input")
    normalized = unicodedata.normalize("NFKC", phrase).strip()
    return _SPACE_RE.sub(" ", normalized)


class HindiWordList:
    """Manages the frozen Hindi 2048-word list for mnemonic generation."""

    wordlist_id = WORDLIST_ID
    roman_wordlist_id = ROMAN_WORDLIST_ID

    def __init__(self):
        self.words = self._load_wordlist()
        self.roman_words = self._load_roman_wordlist()
        self.word_to_index = {word: i for i, word in enumerate(self.words)}

    def _load_wordlist(self) -> List[str]:
        """Load the canonical frozen 2048-word list."""
        wordlist_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "wordlists",
            WORDLIST_FILENAME,
        )

        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [normalize_hindi_word(line) for line in f if line.strip()]

        if len(words) != WORDLIST_SIZE:
            raise ValueError(f"Invalid canonical wordlist size: {len(words)} != {WORDLIST_SIZE}")
        if len(set(words)) != WORDLIST_SIZE:
            raise ValueError("Canonical wordlist contains duplicate entries")
        if any(not word for word in words):
            raise ValueError("Canonical wordlist contains empty entries")

        return words

    def _load_roman_wordlist(self) -> List[str]:
        """Load romanized input helpers that map 1:1 to the canonical Hindi list."""
        roman_path = os.path.join(
            os.path.dirname(__file__),
            "..",
            "wordlists",
            ROMAN_WORDLIST_FILENAME,
        )

        with open(roman_path, "r", encoding="utf-8") as f:
            roman_words = [
                unicodedata.normalize("NFKC", line).strip().lower()
                for line in f
                if line.strip()
            ]

        if len(roman_words) != WORDLIST_SIZE:
            raise ValueError(f"Invalid roman wordlist size: {len(roman_words)} != {WORDLIST_SIZE}")
        if any(not word for word in roman_words):
            raise ValueError("Roman wordlist contains empty entries")
        if any(_ROMAN_WORD_RE.fullmatch(word) is None for word in roman_words):
            raise ValueError("Roman wordlist contains unsupported characters")

        return roman_words

    def get_word(self, index: int) -> str:
        """Get word by index (0-2047)."""
        if not 0 <= index < WORDLIST_SIZE:
            raise ValueError(f"Index must be 0-{WORDLIST_SIZE - 1}, got {index}")
        return self.words[index]

    def get_index(self, word: str) -> int:
        """Get index by normalized word."""
        normalized_word = normalize_hindi_word(word)
        if normalized_word not in self.word_to_index:
            raise ValueError(f"Invalid word: {word}")
        return self.word_to_index[normalized_word]

    def validate_word(self, word: str) -> bool:
        """Check if normalized word exists in wordlist."""
        try:
            normalized_word = normalize_hindi_word(word)
        except ValueError:
            return False
        return normalized_word in self.word_to_index

    def get_all_words(self) -> List[str]:
        """Get all canonical words."""
        return self.words.copy()

    def get_roman_pairs(self) -> List[dict]:
        """Get romanized input helpers paired with canonical Hindi words."""
        return [
            {"index": index + 1, "hindi": hindi, "roman": roman}
            for index, (hindi, roman) in enumerate(zip(self.words, self.roman_words))
        ]

    def search_words(self, prefix: str) -> List[str]:
        """Search words by normalized prefix for autocomplete."""
        normalized_prefix = normalize_hindi_word(prefix)
        return [word for word in self.words if word.startswith(normalized_prefix)]
