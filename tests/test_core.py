"""Tests for pii_sentry.core."""

from __future__ import annotations

import re

import pytest

from pii_sentry import DEFAULT_DETECTORS, Detector, Match, detect, redact


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_detect_finds_email_phone_ssn_in_one_pass():
    text = (
        "Contact alice@example.com or 555-123-4567. "
        "SSN: 123-45-6789."
    )
    findings = detect(text)

    types = {f.type for f in findings}
    assert "email" in types
    assert "phone" in types
    assert "ssn" in types

    # Findings are sorted by start offset.
    starts = [f.start for f in findings]
    assert starts == sorted(starts)

    # Each Match's slice agrees with its value.
    for f in findings:
        assert text[f.start : f.end] == f.value


def test_redact_default_replacement_uses_type_template():
    text = "ping me at bob@example.com"
    out = redact(text)
    assert out == "ping me at [REDACTED:email]"


# ---------------------------------------------------------------------------
# Edge case
# ---------------------------------------------------------------------------


def test_redact_handles_empty_and_no_match_inputs():
    # Empty string -- no findings, output stays empty.
    assert detect("") == []
    assert redact("") == ""

    # Coerced non-string input (matches JS String(text) behavior).
    assert detect(12345) == []
    assert redact(None) == "None"

    # Plain text with nothing sensitive -- output is unchanged.
    assert detect("hello world, nothing to see here") == []
    assert redact("hello world") == "hello world"


# ---------------------------------------------------------------------------
# False-positive guard
# ---------------------------------------------------------------------------


def test_short_numbers_are_not_flagged_as_credit_card():
    # 12 digits is below the 13-19 credit-card window.
    findings = detect("order #12345 at 9am")
    assert all(f.type != "credit_card" for f in findings)


def test_random_words_with_api_in_them_do_not_match_api_key():
    # "api" alone (no separator + 16+ key chars) must not trigger api_key.
    findings = detect("Our public API is documented online.")
    assert all(f.type != "api_key" for f in findings)


# ---------------------------------------------------------------------------
# Configuration override
# ---------------------------------------------------------------------------


def test_custom_detector_via_add_detector():
    det = Detector()
    # Match internal ticket IDs like JIRA-1234.
    det.add_detector("ticket", r"\bJIRA-\d{3,}\b")

    findings = det.detect("see JIRA-4892 for details")
    assert any(f.type == "ticket" and f.value == "JIRA-4892" for f in findings)

    # Constant-string replacement also works on custom detectors.
    assert det.redact("see JIRA-4892", "[X]") == "see [X]"


def test_remove_detector_disables_a_default_pattern():
    det = Detector()
    det.remove_detector("phone")

    # Phone pattern is gone, so a phone-shaped string isn't flagged.
    text = "call 555-123-4567"
    assert all(f.type != "phone" for f in det.detect(text))

    # But other detectors still work.
    text2 = "email me at me@example.com"
    assert any(f.type == "email" for f in det.detect(text2))


def test_replacement_callable_receives_match_type():
    seen: list[str] = []

    def replace(type_name: str) -> str:
        seen.append(type_name)
        return f"<{type_name.upper()}>"

    out = redact("a@b.co and 555-555-5555", replace)
    assert "<EMAIL>" in out
    assert "<PHONE>" in out
    # Both detectors fired.
    assert set(seen) == {"email", "phone"}


# ---------------------------------------------------------------------------
# Error / dataclass behavior
# ---------------------------------------------------------------------------


def test_match_is_immutable_dataclass():
    m = Match(type="email", value="x@y.co", start=0, end=6)
    with pytest.raises(Exception):
        # frozen=True means assignment raises FrozenInstanceError.
        m.start = 99  # type: ignore[misc]


def test_default_detectors_view_is_a_copy():
    det = Detector()
    snapshot = det.detectors
    det.add_detector("ticket", r"X-\d+")
    # Mutating the detector after the fact must not retro-edit the snapshot.
    assert "ticket" not in snapshot
    assert "ticket" in det.detectors


def test_module_level_detect_uses_bundled_detectors():
    # Sanity: every default detector key is exposed via DEFAULT_DETECTORS.
    expected = {"email", "phone", "ssn", "credit_card", "api_key"}
    assert expected.issubset(DEFAULT_DETECTORS.keys())


def test_pre_compiled_pattern_is_accepted():
    det = Detector(detectors={})
    det.add_detector("yell", re.compile(r"[A-Z]{4,}"))
    findings = det.detect("HELLO world")
    assert findings and findings[0].value == "HELLO"
