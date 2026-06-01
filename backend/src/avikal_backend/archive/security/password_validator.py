"""Password strength checks for Avikal archive credentials.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import math
import re


def validate_password_strength(password: str, min_length: int = 12) -> tuple:
    """Validate password strength and raise ValueError for weak input."""
    if not password:
        return True, None  # Empty password is allowed (keyphrase-only mode)

    if len(password) < min_length:
        raise ValueError(
            f"Password must be at least {min_length} characters long.\n"
            f"Current length: {len(password)} characters.\n"
            f"Tip: Use a passphrase like 'MyS3cur3P@ssw0rd2026!'"
        )

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    missing = []
    if not has_lower:
        missing.append("lowercase letter (a-z)")
    if not has_upper:
        missing.append("uppercase letter (A-Z)")
    if not has_digit:
        missing.append("digit (0-9)")
    if not has_symbol:
        missing.append("symbol (!@#$%^&*)")

    if missing:
        raise ValueError(
            f"Password must contain: {', '.join(missing)}\n"
            f"Example strong password: MyS3cur3P@ssw0rd2026!"
        )

    if re.search(r"(.)\1{2,}", password):  # 3+ repeated chars
        raise ValueError(
            "Password contains repeated characters (e.g., 'aaa', '111').\n"
            "Please use a more varied password."
        )

    for i in range(len(password) - 2):
        if password[i : i + 3].isdigit():
            nums = [int(password[i + j]) for j in range(3)]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                raise ValueError(
                    f"Password contains sequential numbers ('{password[i:i+3]}').\n"
                    "Sequential patterns are easy to guess.\n"
                    "Please use a more random password."
                )

    return True, None


def calculate_password_entropy(password: str) -> tuple:
    """Return estimated entropy, label, and UI score."""
    if not password:
        return 0.0, "None", 0

    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32

    if charset_size == 0:
        return 0.0, "Invalid", 0

    entropy = len(password) * math.log2(charset_size)
    penalty = 1.0

    if re.search(r"(.)\1{2,}", password):
        penalty *= 0.7

    adjusted_entropy = entropy * penalty

    if adjusted_entropy < 40:
        strength = "Very Weak"
        score = int(adjusted_entropy / 40 * 20)
    elif adjusted_entropy < 60:
        strength = "Weak"
        score = 20 + int((adjusted_entropy - 40) / 20 * 20)
    elif adjusted_entropy < 80:
        strength = "Medium"
        score = 40 + int((adjusted_entropy - 60) / 20 * 20)
    elif adjusted_entropy < 100:
        strength = "Strong"
        score = 60 + int((adjusted_entropy - 80) / 20 * 20)
    else:
        strength = "Very Strong"
        score = 80 + min(int((adjusted_entropy - 100) / 50 * 20), 20)

    return adjusted_entropy, strength, score


def get_password_feedback(password: str) -> list:
    """Return short UI feedback for a password."""
    if not password:
        return ["No password provided"]

    feedback = []

    if len(password) < 12:
        feedback.append(f"Too short ({len(password)} chars). Aim for 12+ characters.")
    elif len(password) < 16:
        feedback.append(f"Good length ({len(password)} chars). 16+ is even better.")
    else:
        feedback.append(f"Excellent length ({len(password)} chars)!")

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)

    diversity_count = sum([has_lower, has_upper, has_digit, has_symbol])
    if diversity_count == 4:
        feedback.append("Great character diversity!")
    elif diversity_count == 3:
        feedback.append("Good diversity. Add symbols for extra strength.")
    else:
        feedback.append("Add more character types (uppercase, lowercase, digits, symbols).")

    if re.search(r"(.)\1{2,}", password):
        feedback.append("Warning: Contains repeated characters. Use more variety.")

    entropy, strength, score = calculate_password_entropy(password)
    feedback.append(f"Entropy: {entropy:.1f} bits ({strength})")

    return feedback
