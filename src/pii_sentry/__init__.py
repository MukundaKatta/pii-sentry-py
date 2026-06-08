"""pii-sentry -- detect and redact PII and secret-like values.

Public surface (mirrors the JS sibling ``@mukundakatta/pii-sentry``):

    from pii_sentry import detect, redact, Match, Detector

* ``detect(text)`` -> ``list[Match]`` -- find PII/secret matches.
* ``redact(text, replacement=...)`` -> ``str`` -- replace matches inline.
* ``Detector`` -- reusable instance with custom regex detectors.
* ``Match`` -- dataclass: ``type``, ``value``, ``start``, ``end``.

The library is zero-dep and uses the stdlib ``re`` module. The bundled
detectors cover email, phone, SSN, credit-card-like sequences, and a
handful of common API-key prefixes (``sk-``, ``ghp_``, ``xoxb-``,
``api_``). Add your own with ``Detector.add_detector(name, regex)``.
"""

from .core import (
    DEFAULT_DETECTORS,
    Detector,
    Match,
    detect,
    detect_pii,
    redact,
    redact_pii,
)

__version__ = "0.1.0"
VERSION = __version__

__all__ = [
    "DEFAULT_DETECTORS",
    "VERSION",
    "Detector",
    "Match",
    "detect",
    "detect_pii",
    "redact",
    "redact_pii",
]
