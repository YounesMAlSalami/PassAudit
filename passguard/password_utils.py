"""Password strength assessment, generation, and safe display helpers."""
from __future__ import annotations
import math
import re
import secrets
import string

def assess_password_strength(password: str) -> dict:
    """Assess password strength without retaining or logging the password."""
    length = len(password)
    categories = []

    if any(character.islower() for character in password):
        categories.append("Lowercase")
    if any(character.isupper() for character in password):
        categories.append("Uppercase")
    if any(character.isdigit() for character in password):
        categories.append("Numbers")
    if any(not character.isalnum() for character in password):
        categories.append("Special")

    pool = 0
    if "Lowercase" in categories:
        pool += 26
    if "Uppercase" in categories:
        pool += 26
    if "Numbers" in categories:
        pool += 10
    if "Special" in categories:
        pool += 32

    if not password:
        search_space = 0
        score = 0
        classification = "Very Weak"
        explanation = "No password was supplied."
    else:
        try:
            from zxcvbn import zxcvbn

            result = zxcvbn(password)
            zxcvbn_score = int(result["score"])
            score = min(100, max(0, zxcvbn_score * 20))
        except Exception:
            diversity_bonus = min(28, len(categories) * 7)
            length_bonus = min(44, length * 3)
            repetitive = len(set(password.lower())) <= max(2, length // 3)
            score = max(0, min(100, length_bonus + diversity_bonus - (20 if repetitive else 0)))
            zxcvbn_score = min(4, score // 20)

        if length < 8 or zxcvbn_score == 0:
            classification = "Very Weak"
        elif zxcvbn_score == 1 or length < 12:
            classification = "Weak"
        elif zxcvbn_score == 2:
            classification = "Moderate"
        elif zxcvbn_score == 3:
            classification = "Strong"
        else:
            classification = "Very Strong"

        if pool:
            search_space = 0 if length == 0 else pow(pool, length)
        else:
            search_space = 0

        explanation = (
            "Estimated strength uses length, character diversity, and "
            "pattern analysis. Search space is a simplified estimate and "
            "does not account for human password-selection patterns."
        )

    recommendations = []
    if length < 12:
        recommendations.append("Increase password length to at least 12 characters.")
    if len(categories) < 3:
        recommendations.append("Use a mix of character categories.")
    if length and len(set(password.lower())) < max(4, length // 4):
        recommendations.append("Avoid repeated characters and predictable sequences.")
    recommendations.append("Use a unique password for every account.")
    if not recommendations:
        recommendations.append("Use a reputable password manager and enable MFA.")

    return {
        "length": length,
        "categories": categories,
        "character_pool": pool,
        "search_space": search_space,
        "score": score,
        "classification": classification,
        "recommendations": recommendations,
        "explanation": explanation,
    }


def generate_strong_password(
    length: int,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_special: bool,
) -> tuple[str | None, str]:
    """Generate a password using cryptographically secure randomness."""
    if length < 4:
        return None, "Password length must be at least 4 characters."

    pools = []
    required = []
    if use_uppercase:
        pools.append(string.ascii_uppercase)
        required.append(secrets.choice(string.ascii_uppercase))
    if use_lowercase:
        pools.append(string.ascii_lowercase)
        required.append(secrets.choice(string.ascii_lowercase))
    if use_numbers:
        pools.append(string.digits)
        required.append(secrets.choice(string.digits))
    if use_special:
        pools.append("!@#$%^&*()-_=+[]{}")
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}"))

    if not pools:
        return None, "Select at least one character category."
    if length < len(required):
        return None, "Requested length cannot include every selected category."

    combined = "".join(pools)
    characters = required + [
        secrets.choice(combined)
        for _ in range(length - len(required))
    ]

    for index in range(len(characters) - 1, 0, -1):
        swap_index = secrets.randbelow(index + 1)
        characters[index], characters[swap_index] = (
            characters[swap_index],
            characters[index],
        )

    return "".join(characters), ""


def detect_linux_hash_algorithm(full_hash: str) -> str:
    if re.fullmatch(r"[./A-Za-z0-9]{13}", full_hash):
        return "DES"
    if full_hash.startswith("$y$"):
        return "Yescrypt"
    if full_hash.startswith("$6$"):
        return "SHA-512"
    if full_hash.startswith("$5$"):
        return "SHA-256"
    if full_hash.startswith("$1$"):
        return "MD5"
    if full_hash.startswith("$2"):
        return "bcrypt"
    if full_hash.startswith("$3$"):
        return "DES"
    return "Unknown"


def is_valid_nt_hash(hash_value: str) -> bool:
    """Return whether a value has the canonical 32-hex-character NT hash format."""
    return re.fullmatch(r"[A-Fa-f0-9]{32}", hash_value) is not None


def mask_hash(full_hash: str) -> str:
    if not full_hash:
        return "Unavailable"
    if len(full_hash) <= 12:
        return "*" * len(full_hash)
    return full_hash[:8] + "*" * (len(full_hash) - 12) + full_hash[-4:]


def mask_password(password: str) -> str:
    if len(password) <= 2:
        return "*" * len(password)

    return password[0] + "*" * (len(password) - 2) + password[-1]
