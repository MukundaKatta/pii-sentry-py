# pii-sentry-py

[![PyPI](https://img.shields.io/pypi/v/pii-sentry-py.svg)](https://pypi.org/project/pii-sentry-py/)
[![Python](https://img.shields.io/pypi/pyversions/pii-sentry-py.svg)](https://pypi.org/project/pii-sentry-py/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Detect and redact PII and secret-like values** before logging or sending text to AI providers. Zero runtime dependencies.

Python port of [@mukundakatta/pii-sentry](https://github.com/MukundaKatta/pii-sentry). The JS sibling has the full design notes; this README sticks to the Python API.

## Install

```bash
pip install pii-sentry-py
```

## Usage

```python
from pii_sentry import detect, redact, Detector

text = "Contact alice@example.com or 555-123-4567. SSN: 123-45-6789."

# Find PII matches.
for match in detect(text):
    print(match.type, match.value, match.start, match.end)
# email   alice@example.com   8   25
# phone   555-123-4567        29  41
# ssn     123-45-6789         48  59

# Inline redaction. Default replacement is f"[REDACTED:{type}]".
redact(text)
# 'Contact [REDACTED:email] or [REDACTED:phone]. SSN: [REDACTED:ssn].'

# Constant or callable replacements work too.
redact(text, "[X]")
redact(text, lambda kind: f"<{kind.upper()}>")
```

### Custom detectors

```python
det = Detector()
det.add_detector("ticket", r"\bJIRA-\d{3,}\b")
det.detect("see JIRA-4892 for details")
# [Match(type='ticket', value='JIRA-4892', start=4, end=13)]
```

Pre-compiled `re.Pattern` objects are accepted too, so you can pass flags like `re.IGNORECASE`.

## Bundled detectors

| Name | Catches |
|---|---|
| `email` | RFC-shaped email addresses |
| `phone` | US-format phone numbers (with optional `+1`) |
| `ssn` | `###-##-####` US SSNs |
| `credit_card` | 13-19 digit sequences (loose; pair with Luhn for accuracy) |
| `api_key` | `sk-`, `ghp_`, `xoxb-`, `api_` prefixed keys |

Override or remove any of them via `Detector.add_detector` / `Detector.remove_detector`.

## API differences from the JS sibling

* `detect()` returns a list of frozen `Match` dataclasses (not plain dicts).
* `redact()` accepts a constant `str` or a `Callable[[str], str]` for replacements.
* `Detector` is a real class -- create instances per workload to keep custom detectors isolated.

See the JS sibling's [README](https://github.com/MukundaKatta/pii-sentry) for the full design notes.

## License

MIT
