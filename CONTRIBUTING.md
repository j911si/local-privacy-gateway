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

Architecture notes are in `CLAUDE.md`, the design documents in `docs/superpowers/`.
