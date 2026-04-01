"""
Phase 4c — Translation Validator (The Firewall).

The critical boundary between probabilistic LLM output and deterministic
binary injection. Validates every translation before it's allowed to be
written into the game executable.

Checks:
    1. Byte length ≤ allowed maximum
    2. All control codes preserved
    3. No invalid characters (must fit the game's font table)
    4. No empty/null translations
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class ValidationError:
    """A specific validation failure."""
    error_type: str       # "byte_limit", "control_code", "invalid_char", "empty"
    message: str
    severity: str = "error"  # "error" or "warning"


@dataclass
class ValidationResult:
    """Result of validating a translated string."""
    is_valid: bool
    errors: list[ValidationError] = field(default_factory=list)
    warnings: list[ValidationError] = field(default_factory=list)
    byte_count: int = 0
    byte_limit: int = 0


# Default ASCII printable range + common control characters
DEFAULT_VALID_CHARS = set(range(0x20, 0x7F)) | {0x00, 0x0A, 0x0D}

# Pattern to match control code markers like {CTRL:0A}, {NL}, {WAIT}, etc.
CONTROL_CODE_PATTERN = re.compile(r"\{[A-Z_]+(?::[0-9A-Fa-f]+)?\}")


def validate_translation(
    translated: str,
    source: str,
    byte_limit: int,
    control_codes: Optional[list[str]] = None,
    valid_chars: Optional[set[int]] = None,
) -> ValidationResult:
    """
    Validate a translated string against all constraints.

    Args:
        translated: The English translation to validate.
        source: The original Japanese source text.
        byte_limit: Maximum byte length for the output.
        control_codes: List of control code strings that must be preserved.
        valid_chars: Set of valid byte values (default: ASCII printable).

    Returns:
        ValidationResult with detailed error/warning information.
    """
    errors: list[ValidationError] = []
    warnings: list[ValidationError] = []
    valid_char_set = valid_chars or DEFAULT_VALID_CHARS

    # ── Check 1: Empty translation ───────────────────────────
    if not translated or translated.isspace():
        errors.append(ValidationError(
            error_type="empty",
            message="Translation is empty or whitespace-only",
        ))
        return ValidationResult(
            is_valid=False,
            errors=errors,
            byte_count=0,
            byte_limit=byte_limit,
        )

    # ── Check 2: Byte length ─────────────────────────────────
    encoded = translated.encode("ascii", errors="replace")
    byte_count = len(encoded)

    if byte_count > byte_limit:
        errors.append(ValidationError(
            error_type="byte_limit",
            message=(
                f"Translation is {byte_count} bytes, exceeds limit of "
                f"{byte_limit} bytes (over by {byte_count - byte_limit})"
            ),
        ))

    if byte_count == byte_limit:
        warnings.append(ValidationError(
            error_type="byte_limit",
            message="Translation uses exactly the maximum bytes (no padding room)",
            severity="warning",
        ))

    # ── Check 3: Control code preservation ───────────────────
    if control_codes:
        for code in control_codes:
            source_count = source.count(code)
            trans_count = translated.count(code)

            if trans_count < source_count:
                errors.append(ValidationError(
                    error_type="control_code",
                    message=(
                        f"Control code '{code}' appears {source_count}x in source "
                        f"but only {trans_count}x in translation"
                    ),
                ))
            elif trans_count > source_count:
                warnings.append(ValidationError(
                    error_type="control_code",
                    message=(
                        f"Control code '{code}' appears {trans_count}x in translation "
                        f"but only {source_count}x in source (extra codes added)"
                    ),
                    severity="warning",
                ))

    # ── Check 4: Invalid characters ──────────────────────────
    invalid_bytes = []
    for i, byte_val in enumerate(encoded):
        if byte_val not in valid_char_set:
            invalid_bytes.append((i, byte_val))

    if invalid_bytes:
        # Show first 5 invalid bytes
        examples = ", ".join(
            f"0x{b:02X} at position {pos}"
            for pos, b in invalid_bytes[:5]
        )
        errors.append(ValidationError(
            error_type="invalid_char",
            message=f"Translation contains {len(invalid_bytes)} invalid byte(s): {examples}",
        ))

    # ── Check 5: Suspiciously short translation ──────────────
    if len(source) > 10 and byte_count < len(source) * 0.2:
        warnings.append(ValidationError(
            error_type="truncation",
            message=(
                f"Translation ({byte_count} bytes) is unusually short compared "
                f"to source ({len(source)} chars) — possible truncation"
            ),
            severity="warning",
        ))

    is_valid = len(errors) == 0

    return ValidationResult(
        is_valid=is_valid,
        errors=errors,
        warnings=warnings,
        byte_count=byte_count,
        byte_limit=byte_limit,
    )


def validate_batch(
    translations: list[tuple[str, str, int]],
    control_codes: Optional[list[str]] = None,
) -> tuple[list[ValidationResult], int, int]:
    """
    Validate a batch of translations.

    Args:
        translations: List of (translated, source, byte_limit) tuples.
        control_codes: Control codes to enforce.

    Returns:
        (results, pass_count, fail_count)
    """
    results = []
    pass_count = 0
    fail_count = 0

    for translated, source, byte_limit in translations:
        result = validate_translation(
            translated, source, byte_limit, control_codes,
        )
        results.append(result)

        if result.is_valid:
            pass_count += 1
        else:
            fail_count += 1

    logger.info(
        "Validation: %d passed, %d failed out of %d translations",
        pass_count, fail_count, len(translations),
    )

    return results, pass_count, fail_count
