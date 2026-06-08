"""Core detector and redactor logic for pii-sentry.

Mirrors the JS sibling's ``DETECTORS`` table 1:1, but exposes a Python-friendly
``Detector`` class for users who want to register custom regexes alongside the
bundled set. The module-level ``detect()`` and ``redact()`` use a shared default
detector instance for the common, no-config case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Mapping, Pattern, Union

# Bundled detectors. These are the same patterns shipped in the JS package
# (see ``@mukundakatta/pii-sentry`` v0.1.0 ``src/index.js``). Patterns are
# compiled with re.IGNORECASE where the JS source uses the ``i`` flag.
DEFAULT_DETECTORS: dict[str, Pattern[str]] = {
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    # 13-19 digit card-like sequences. Allows spaces/dashes between digits, like
    # the JS source. Loose by design -- pair with a Luhn check downstream if
    # false positives matter.
    "credit_card": re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
    # Common API-key prefixes. Matches the JS prefix list: ``sk``, ``ghp``,
    # ``xoxb``, ``api``, followed by ``-`` or ``_`` and 16+ key chars.
    "api_key": re.compile(r"\b(?:sk|ghp|xoxb|api)[-_][A-Za-z0-9_-]{16,}\b"),
}


@dataclass(frozen=True)
class Match:
    """A single PII/secret hit.

    Attributes:
        type: detector name (``email``, ``phone``, ``ssn``, ``credit_card``,
            ``api_key``, or any custom name registered on the Detector).
        value: the matched substring, exactly as found in the input.
        start: inclusive start offset in the original text.
        end: exclusive end offset in the original text (``text[start:end]``
            equals ``value``).
    """

    type: str
    value: str
    start: int
    end: int


# Replacement may be a constant string or a callable that takes the match type.
Replacement = Union[str, Callable[[str], str]]


class Detector:
    """Reusable PII detector. Holds a mutable map of name -> compiled regex.

    Construct with ``Detector()`` to get the bundled detectors, or
    ``Detector(detectors={})`` to start empty and register only what you need.
    """

    def __init__(
        self,
        detectors: Mapping[str, Union[str, Pattern[str]]] | None = None,
    ) -> None:
        # Default to a copy of the bundled set so callers can mutate freely.
        if detectors is None:
            self._detectors: dict[str, Pattern[str]] = dict(DEFAULT_DETECTORS)
        else:
            self._detectors = {}
            for name, pattern in detectors.items():
                self.add_detector(name, pattern)

    def add_detector(self, name: str, pattern: Union[str, Pattern[str]]) -> None:
        """Register or override a named detector.

        Accepts either a raw pattern string or a pre-compiled ``re.Pattern``.
        Raw strings are compiled with no flags -- callers wanting case-insensitive
        matching should pass ``re.compile(..., re.IGNORECASE)`` themselves.
        """
        if isinstance(pattern, str):
            pattern = re.compile(pattern)
        self._detectors[name] = pattern

    def remove_detector(self, name: str) -> None:
        """Drop a named detector. No-op if it doesn't exist."""
        self._detectors.pop(name, None)

    @property
    def detectors(self) -> Mapping[str, Pattern[str]]:
        """Read-only view of the active detector map."""
        return dict(self._detectors)

    def detect(self, text: object) -> list[Match]:
        """Find every PII/secret hit in ``text``.

        ``text`` is coerced to ``str`` (matching the JS ``String(text)`` step).
        Results are sorted by start offset for stable, predictable iteration.
        """
        value = str(text)
        findings: list[Match] = []
        for type_name, pattern in self._detectors.items():
            for m in pattern.finditer(value):
                findings.append(
                    Match(
                        type=type_name,
                        value=m.group(0),
                        start=m.start(),
                        end=m.end(),
                    )
                )
        findings.sort(key=lambda f: f.start)
        return findings

    def redact(
        self,
        text: object,
        replacement: Replacement | None = None,
    ) -> str:
        """Replace each detected hit with ``replacement``.

        ``replacement`` may be:
          * ``None`` (default) -- use ``[REDACTED:<type>]`` per-match.
          * a constant ``str`` -- used for every hit.
          * a ``Callable[[str], str]`` -- called with the match ``type``,
            returning the replacement string for that hit.

        Output is rebuilt left-to-right in a single pass. Matches are sorted by
        start offset (see ``detect``); when two detectors produce overlapping
        spans the first one wins and any span overlapping an already-redacted
        region is skipped, so the result is never corrupted by stale offsets.
        """

        def token_for(type_name: str) -> str:
            if replacement is None:
                return f"[REDACTED:{type_name}]"
            if callable(replacement):
                return replacement(type_name)
            return replacement

        source = str(text)
        parts: list[str] = []
        cursor = 0
        for finding in self.detect(source):
            # Skip spans that fall inside a region we've already redacted.
            if finding.start < cursor:
                continue
            parts.append(source[cursor : finding.start])
            parts.append(token_for(finding.type))
            cursor = finding.end
        parts.append(source[cursor:])
        return "".join(parts)


# Shared default instance for the module-level functions. Tests can poke at it
# via ``Detector()`` instances without disturbing the global.
_DEFAULT = Detector()


def detect(text: object) -> list[Match]:
    """Find every PII/secret hit using the bundled detectors. See ``Detector.detect``."""
    return _DEFAULT.detect(text)


def redact(text: object, replacement: Replacement | None = None) -> str:
    """Redact PII/secrets using the bundled detectors. See ``Detector.redact``."""
    return _DEFAULT.redact(text, replacement)


# JS-style aliases for callers porting from ``@mukundakatta/pii-sentry``.
detect_pii = detect
redact_pii = redact
