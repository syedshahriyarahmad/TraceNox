# Contributing to TraceNox

## Development setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install pytest
```

## Before submitting changes

Run the test suite and check whitespace:

```bash
python -m pytest -q
git diff --check
```

Include regression tests for bug fixes. Keep sample logs synthetic or
sanitized; never commit credentials, private keys, personal data, or
confidential production logs.

## Responsible use

Use TraceNox only on systems and log data you are authorized to investigate.
External IP-reputation lookups may disclose queried IP addresses to the
configured third-party provider.
