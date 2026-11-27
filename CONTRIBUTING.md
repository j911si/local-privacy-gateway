# Contributing

## Setup

```bash
uv sync --group proxy   # omit --group proxy if you only touch the core package
```

## Before you open a pull request

```bash
uv run pytest -q
uv run ruff check .
```

Both must be clean. Line length is 100, type hints everywhere.

## Conventions

- **TDD.** Write the failing test first, then the smallest change that makes it pass.
- **Never leak values.** Detected values must not appear in findings, reports, audit
  events or exception messages — only class names, spans and counts. Tests use
  synthetic data; never commit real personal data.
- **No network in the core.** `privacy_gateway/` must not import `socket`, `http`,
  `urllib.request`, `requests`, `httpx`, `aiohttp`, `ssl`, `ftplib` or `smtplib`;
  `tests/integration/test_no_network.py` enforces this. Network code belongs in
  `privacy_gateway_proxy/`, which nothing in `privacy_gateway/` may import.
- **Conventional Commits.** `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`,
  one commit per logical change.

## Contributing a recognizer

New formats for other countries and languages are welcome. Until country and language packs exist
(see [ROADMAP.md](ROADMAP.md)), a recognizer is a class entry in
`privacy_gateway/data/default_config.yaml` and, if it needs a check digit, a function in
`privacy_gateway/detect/validators.py`. A pull request needs:

- **Official reference.** A link to the specification of the format in the description.
- **Synthetic test values only.** Published example numbers or values you generate with the check
  digit. Never real identifiers, not even your own.
- **Positive and negative tests.** Valid values in the label forms you expect, and near-misses
  that must stay: a wrong check digit, version numbers, dates, order numbers, hashes, UUIDs. Check
  that a synthetic UUID or number does not happen to pass Luhn or another validator.
- **Bounded runtime.** No nested or overlapping repetition; use possessive quantifiers where a
  repetition follows a repetition. Add a scaling test on crafted worst-case input (`n` and `4n`,
  a hard time limit), as in `tests/unit/test_regex_linearity.py`. A short runtime on one long
  input alone is not accepted as proof. A changed default pattern loses its linear finder in
  `patterns.LINEAR_FINDERS`; say so if you touch one.
- **Unicode.** Matching runs on normalized text and spans are mapped back. Test a value with
  non-breaking spaces or other separators if the format allows them.
- **No network and no new runtime code paths.** Validators are plain functions without I/O. No new
  dependency without a license check; contributed data such as name lists needs a license
  compatible with MIT.
- **Coverage register.** Add or move the row in [docs/COVERAGE.md](docs/COVERAGE.md).

Architecture notes are in `CLAUDE.md`, the design documents in `docs/superpowers/`.
