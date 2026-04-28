"""
Hindi Mnemonic Generator for Avikal.
Implements a normalized, checksum-validated mnemonic design for archive keyphrases.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

from __future__ import annotations

import hashlib
import secrets
from typing import List

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from .wordlist import HindiWordList, WORDLIST_ID, WORDLIST_SIZE, normalize_hindi_word, normalize_phrase_text


SUPPORTED_WORD_COUNTS = (12, 15, 18, 21, 24)
DEFAULT_WORD_COUNT = 21
MNEMONIC_FORMAT_VERSION = 1

_ENTROPY_BITS_BY_COUNT = {
    12: 128,
    15: 160,
    18: 192,
    21: 224,
    24: 256,
}


def _entropy_bits_for_word_count(word_count: int) -> int:
    if word_count not in SUPPORTED_WORD_COUNTS:
        raise ValueError(
            f"Invalid length: keyphrase must contain {', '.join(str(count) for count in SUPPORTED_WORD_COUNTS)} words"
        )
    return _ENTROPY_BITS_BY_COUNT[word_count]


def _checksum_length_bits(entropy_bits: int) -> int:
    return entropy_bits // 32


def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def _bits_to_bytes(bits: str) -> bytes:
    if not bits or len(bits) % 8 != 0:
        raise ValueError("Invalid mnemonic bitstream")
    return bytes(int(bits[index:index + 8], 2) for index in range(0, len(bits), 8))


def _derive_checksum_bits(entropy: bytes, checksum_length: int) -> str:
    digest_bits = _bytes_to_bits(hashlib.sha256(entropy).digest())
    return digest_bits[:checksum_length]


def _canonicalize_words(words: List[str]) -> List[str]:
    return [normalize_hindi_word(word) for word in words]


class HindiMnemonic:
    """
    Hindi mnemonic generator for Avikal encryption.
    Generates cryptographically secure checksum-validated mnemonic phrases.
    """

    format_version = MNEMONIC_FORMAT_VERSION
    wordlist_id = WORDLIST_ID

    def __init__(self):
        self.wordlist = HindiWordList()

    def generate(self, word_count: int = DEFAULT_WORD_COUNT) -> List[str]:
        """
        Generate a cryptographically secure mnemonic phrase.

        Args:
            word_count: Number of words (12, 15, 18, 21, or 24)

        Returns:
            List of Hindi words
        """
        entropy_bits = _entropy_bits_for_word_count(word_count)
        entropy = secrets.token_bytes(entropy_bits // 8)
        checksum_bits = _derive_checksum_bits(entropy, _checksum_length_bits(entropy_bits))
        full_bits = _bytes_to_bits(entropy) + checksum_bits
        indices = [int(full_bits[index:index + 11], 2) for index in range(0, len(full_bits), 11)]
        return [self.wordlist.get_word(index) for index in indices]

    def validate_or_raise(self, mnemonic: List[str]) -> List[str]:
        """
        Validate and normalize a mnemonic phrase.

        Returns:
            Canonical normalized words.

        Raises:
            ValueError with a specific validation message if invalid.
        """
        if not isinstance(mnemonic, list):
            raise ValueError("Invalid phrase: expected a list of words")

        canonical_words = _canonicalize_words(mnemonic)
        word_count = len(canonical_words)
        entropy_bits = _entropy_bits_for_word_count(word_count)

        for word in canonical_words:
            if not self.wordlist.validate_word(word):
                raise ValueError(f"Invalid word: {word}")

        combined_bits = "".join(f"{self.wordlist.get_index(word):011b}" for word in canonical_words)
        checksum_length = _checksum_length_bits(entropy_bits)
        expected_total_bits = entropy_bits + checksum_length
        if len(combined_bits) != expected_total_bits:
            raise ValueError("Invalid mnemonic encoding")

        entropy = _bits_to_bytes(combined_bits[:entropy_bits])
        checksum_bits = combined_bits[entropy_bits:]
        expected_checksum = _derive_checksum_bits(entropy, checksum_length)
        if checksum_bits != expected_checksum:
            raise ValueError("Checksum mismatch")

        return canonical_words

    def validate(self, mnemonic: List[str]) -> bool:
        """Return True when the phrase passes normalization, word, and checksum validation."""
        try:
            self.validate_or_raise(mnemonic)
            return True
        except Exception:
            return False

    def to_seed(self, mnemonic: List[str], salt: bytes = b"") -> bytes:
        """
        Convert mnemonic to 256-bit encryption key using Argon2id.

        Args:
            mnemonic: List of Hindi words
            salt: Salt for key derivation (from .avk file)

        Returns:
            32-byte encryption key
        """
        canonical_words = self.validate_or_raise(mnemonic)
        mnemonic_str = " ".join(canonical_words)

        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=3,
            lanes=4,
            memory_cost=262144,
        )

        return kdf.derive(mnemonic_str.encode("utf-8"))

    def phrase_to_string(self, mnemonic: List[str]) -> str:
        """Convert mnemonic list to canonical space-separated string."""
        canonical_words = self.validate_or_raise(mnemonic)
        return " ".join(canonical_words)

    def string_to_phrase(self, phrase_str: str) -> List[str]:
        """Convert user-entered string to validated canonical word list."""
        canonical_phrase = normalize_phrase_text(phrase_str)
        words = canonical_phrase.split(" ") if canonical_phrase else []
        return self.validate_or_raise(words)

    def normalize_words(self, mnemonic: List[str]) -> List[str]:
        """Normalize and validate a list of words."""
        return self.validate_or_raise(mnemonic)

    def normalize_phrase(self, phrase_str: str) -> str:
        """Normalize and validate a phrase string, returning canonical text."""
        return self.phrase_to_string(self.string_to_phrase(phrase_str))

    def get_wordlist(self) -> List[str]:
        """Get all canonical 2048 words."""
        return self.wordlist.get_all_words()

    def search_words(self, prefix: str) -> List[str]:
        """Search words by normalized prefix for autocomplete."""
        return self.wordlist.search_words(prefix)


_generator = None


def get_generator():
    """Get or create singleton generator instance."""
    global _generator
    if _generator is None:
        _generator = HindiMnemonic()
    return _generator


def normalize_mnemonic_words(mnemonic: List[str]) -> List[str]:
    """Normalize and validate a mnemonic word list."""
    return get_generator().normalize_words(mnemonic)


def normalize_mnemonic_phrase(phrase_str: str) -> str:
    """Normalize and validate a mnemonic phrase string."""
    return get_generator().normalize_phrase(phrase_str)


def generate_mnemonic(word_count: int = DEFAULT_WORD_COUNT, language: str = "hindi") -> str:
    """
    Generate a Hindi mnemonic phrase.

    Args:
        word_count: Number of words (12, 15, 18, 21, or 24)
        language: Language (only 'hindi' supported)

    Returns:
        Canonical space-separated string of Hindi words
    """
    if language != "hindi":
        raise ValueError(f"Only 'hindi' language supported, got '{language}'")

    gen = get_generator()
    words = gen.generate(word_count)
    return gen.phrase_to_string(words)


def mnemonic_to_seed(mnemonic: str, salt: bytes = b"") -> bytes:
    """
    Convert mnemonic phrase to encryption seed.

    Args:
        mnemonic: Space-separated Hindi words
        salt: Salt for key derivation

    Returns:
        32-byte encryption key
    """
    gen = get_generator()
    words = gen.string_to_phrase(mnemonic)
    return gen.to_seed(words, salt)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a mnemonic phrase.

    Args:
        mnemonic: Space-separated Hindi words

    Returns:
        True if valid, False otherwise
    """
    try:
        gen = get_generator()
        gen.string_to_phrase(mnemonic)
        return True
    except Exception:
        return False
