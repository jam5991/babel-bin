import pytest

from src.llm.validator import validate_translation

def test_validate_byte_limit():
    source = "テスト" # Doesn't matter for this limit test
    
    # Fit exactly
    res = validate_translation("Hello", source, byte_limit=5)
    assert res.is_valid
    assert len(res.warnings) == 1 # Exact fit warning
    
    # Fit loosely
    res = validate_translation("Code", source, byte_limit=10)
    assert res.is_valid
    assert len(res.warnings) == 0
    
    # Exceed limit
    res = validate_translation("Too long string", source, byte_limit=10)
    assert not res.is_valid
    assert len(res.errors) == 1
    assert res.errors[0].error_type == "byte_limit"


def test_validate_control_codes():
    source = "Hello {NL} World {WAIT}"
    limit = 50
    codes = ["{NL}", "{WAIT}", "{COLOR:05}"]

    # 1. Perfectly preserved
    trans = "Greetings {NL} Planet {WAIT}"
    res = validate_translation(trans, source, limit, codes)
    assert res.is_valid

    # 2. Missing code -> ERROR
    trans_missing = "Greetings {NL} Planet"
    res = validate_translation(trans_missing, source, limit, codes)
    assert not res.is_valid
    assert len(res.errors) == 1
    assert res.errors[0].error_type == "control_code"
    assert "{WAIT}" in res.errors[0].message

    # 3. Extra code -> WARNING
    trans_extra = "Greetings {NL} Planet {WAIT} {COLOR:05}"
    res = validate_translation(trans_extra, source, limit, codes)
    assert res.is_valid # Extra codes don't break the build
    assert len(res.warnings) == 1
    assert res.warnings[0].error_type == "control_code"


def test_validate_invalid_chars():
    source = "..."
    limit = 50
    # Custom valid set: only A-Z, space
    valid = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ ")
    
    # Valid
    res = validate_translation("HELLO WORLD", source, limit, valid_chars=valid)
    assert res.is_valid

    # Invalid (contains lowercase and punctuation)
    res = validate_translation("Hello, world!", source, limit, valid_chars=valid)
    assert not res.is_valid
    assert len(res.errors) == 1
    assert res.errors[0].error_type == "invalid_char"


def test_validate_empty():
    res = validate_translation("", "abc", 10)
    assert not res.is_valid
    assert res.errors[0].error_type == "empty"

    res = validate_translation("   ", "abc", 10)
    assert not res.is_valid
    assert res.errors[0].error_type == "empty"
