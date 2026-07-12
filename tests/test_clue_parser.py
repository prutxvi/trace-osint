# -*- coding: utf-8 -*-
from __future__ import annotations
"""Tests for clue_parser module."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.sources.clue_parser import classify_clue, detect_case_mode, parse_clues, _looks_like_name, is_common_name
from src.models import ClueType


def test_classify_email():
    result = classify_clue("prutxvi@gmail.com")
    assert result.type == ClueType.EMAIL
    assert result.normalized == "prutxvi@gmail.com"
    assert result.confidence >= 0.9


def test_classify_phone():
    result = classify_clue("+919876543210")
    assert result.type == ClueType.PHONE
    assert result.confidence >= 0.9


def test_classify_github_profile():
    result = classify_clue("https://github.com/prutxvi")
    assert result.type == ClueType.GITHUB_PROFILE
    assert "prutxvi" in result.normalized.lower()


def test_classify_linkedin_profile():
    result = classify_clue("https://linkedin.com/in/johndoe")
    assert result.type == ClueType.LINKEDIN_PROFILE
    assert "johndoe" in result.normalized.lower()


def test_classify_ip():
    result = classify_clue("8.8.8.8")
    assert result.type == ClueType.IP_ADDRESS


def test_classify_domain():
    result = classify_clue("example.com")
    assert result.type == ClueType.DOMAIN
    assert result.normalized == "example.com"


def test_classify_username():
    result = classify_clue("johndoe123")
    assert result.type == ClueType.USERNAME
    assert result.normalized == "johndoe123"


def test_classify_name():
    result = classify_clue("John Smith")
    assert result.type == ClueType.NAME
    assert result.normalized == "John Smith"


def test_classify_unknown():
    result = classify_clue("!!")
    assert result.type == ClueType.UNKNOWN


def test_detect_case_mode_person():
    parsed = parse_clues(["prutxvi@gmail.com", "johndoe"])
    mode = detect_case_mode(parsed)
    assert mode == "person"


def test_detect_case_mode_asset():
    parsed = parse_clues(["example.com", "8.8.8.8"])
    mode = detect_case_mode(parsed)
    assert mode == "asset"


def test_parse_clues_multiple():
    results = parse_clues(["test@gmail.com", "example.com", "+919876543210"])
    assert len(results) == 3
    assert results[0].type == ClueType.EMAIL
    assert results[1].type == ClueType.DOMAIN
    assert results[2].type == ClueType.PHONE


def test_looks_like_name():
    assert _looks_like_name("John Smith") is True
    assert _looks_like_name("SingleName") is False
    assert _looks_like_name("John123 Smith") is False
    assert _looks_like_name("A B") is False


def test_is_common_name():
    assert is_common_name("Raj Kumar") is True
    assert is_common_name("John Singh") is True
    assert is_common_name("Pruthvi Raj") is False


def test_empty_input():
    result = classify_clue("")
    assert result.type == ClueType.UNKNOWN
    assert result.confidence == 0.0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
