"""
Password strength validation for Avikal encryption system.
Enforces strong password policies to prevent weak password attacks.

SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Atharva Sen Barai.
"""

import re
import math


# Top 10,000 most common passwords (subset for demonstration)
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567",
    "password1", "123123", "1234567890", "000000", "abc123", "qwerty",
    "iloveyou", "monkey", "dragon", "111111", "123321", "654321",
    "sunshine", "master", "princess", "letmein", "welcome", "shadow",
    "ashley", "football", "jesus", "michael", "ninja", "mustang",
    "password123", "admin", "root", "toor", "pass", "test",
    "guest", "123qwe", "qwerty123", "1q2w3e4r", "1qaz2wsx",
}

# Keyboard patterns to detect
KEYBOARD_PATTERNS = [
    "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "asdfghjkl",
    "zxcvbnm", "123456", "abcdef", "qazwsx", "1qaz2wsx",
]


def validate_password_strength(password: str, min_length: int = 12) -> tuple:
    """
    Validate password strength and return (is_valid, error_message).
    
    Args:
        password: Password to validate
        min_length: Minimum password length (default 12)
    
    Returns:
        Tuple of (is_valid: bool, error_message: str or None)
    
    Raises:
        ValueError: If password fails validation (with detailed message)
    """
    if not password:
        return True, None  # Empty password is allowed (keyphrase-only mode)
    
    # Check minimum length
    if len(password) < min_length:
        raise ValueError(
            f"Password must be at least {min_length} characters long.\n"
            f"Current length: {len(password)} characters.\n"
            f"Tip: Use a passphrase like 'MyS3cur3P@ssw0rd2026!'"
        )
    
    # Check character diversity
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
    
    # Check against common passwords
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError(
            "This password is too common and easily guessable.\n"
            "It appears in lists of commonly used passwords.\n"
            "Please choose a unique password."
        )
    
    # Check for keyboard patterns
    password_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            raise ValueError(
                f"Password contains keyboard pattern '{pattern}'.\n"
                "Keyboard patterns are easy to guess.\n"
                "Please use a more random password."
            )
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):  # 3+ repeated chars
        raise ValueError(
            "Password contains repeated characters (e.g., 'aaa', '111').\n"
            "Please use a more varied password."
        )
    
    # Check for sequential characters
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            nums = [int(password[i+j]) for j in range(3)]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                raise ValueError(
                    f"Password contains sequential numbers ('{password[i:i+3]}').\n"
                    "Sequential patterns are easy to guess.\n"
                    "Please use a more random password."
                )
    
    return True, None


def calculate_password_entropy(password: str) -> tuple:
    """
    Calculate password entropy in bits.
    
    Args:
        password: Password to analyze
    
    Returns:
        Tuple of (entropy_bits: float, strength_label: str, score: int)
        score is 0-100 for UI display
    """
    if not password:
        return 0.0, "None", 0
    
    # Determine character set size
    charset_size = 0
    if any(c.islower() for c in password):
        charset_size += 26
    if any(c.isupper() for c in password):
        charset_size += 26
    if any(c.isdigit() for c in password):
        charset_size += 10
    if any(not c.isalnum() for c in password):
        charset_size += 32
    
    # Calculate base entropy
    if charset_size == 0:
        return 0.0, "Invalid", 0
    
    entropy = len(password) * math.log2(charset_size)
    
    # Adjust for patterns (reduce entropy)
    penalty = 1.0
    
    # Check for common passwords
    if password.lower() in COMMON_PASSWORDS:
        penalty *= 0.1  # 90% reduction
    
    # Check for keyboard patterns
    password_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            penalty *= 0.5  # 50% reduction
            break
    
    # Check for repeated characters
    if re.search(r'(.)\1{2,}', password):
        penalty *= 0.7  # 30% reduction
    
    # Apply penalty
    adjusted_entropy = entropy * penalty
    
    # Classify strength
    if adjusted_entropy < 40:
        strength = "Very Weak"
        score = int(adjusted_entropy / 40 * 20)  # 0-20
    elif adjusted_entropy < 60:
        strength = "Weak"
        score = 20 + int((adjusted_entropy - 40) / 20 * 20)  # 20-40
    elif adjusted_entropy < 80:
        strength = "Medium"
        score = 40 + int((adjusted_entropy - 60) / 20 * 20)  # 40-60
    elif adjusted_entropy < 100:
        strength = "Strong"
        score = 60 + int((adjusted_entropy - 80) / 20 * 20)  # 60-80
    else:
        strength = "Very Strong"
        score = 80 + min(int((adjusted_entropy - 100) / 50 * 20), 20)  # 80-100
    
    return adjusted_entropy, strength, score


def get_password_feedback(password: str) -> list:
    """
    Get helpful feedback for improving password strength.
    
    Args:
        password: Password to analyze
    
    Returns:
        List of feedback strings
    """
    if not password:
        return ["No password provided"]
    
    feedback = []
    
    # Length feedback
    if len(password) < 12:
        feedback.append(f"Too short ({len(password)} chars). Aim for 12+ characters.")
    elif len(password) < 16:
        feedback.append(f"Good length ({len(password)} chars). 16+ is even better.")
    else:
        feedback.append(f"Excellent length ({len(password)} chars)!")
    
    # Character diversity feedback
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
    
    # Pattern feedback
    if password.lower() in COMMON_PASSWORDS:
        feedback.append("⚠️ This is a commonly used password. Choose something unique.")
    
    password_lower = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        if pattern in password_lower:
            feedback.append(f"⚠️ Contains keyboard pattern '{pattern}'. Avoid patterns.")
            break
    
    if re.search(r'(.)\1{2,}', password):
        feedback.append("⚠️ Contains repeated characters. Use more variety.")
    
    # Entropy feedback
    entropy, strength, score = calculate_password_entropy(password)
    feedback.append(f"Entropy: {entropy:.1f} bits ({strength})")
    
    return feedback
