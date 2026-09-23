# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv sync                                              # install deps and the pgw entry point
uv run pytest -q                                     # full test suite
uv run pytest tests/unit/test_validators.py -q -k luhn   # one test
uv run ruff check .                                  # lint (line length 100)

export PGW_VAULT_DB=/tmp/pgw/vault.db PGW_VAULT_KEY_FILE=/tmp/pgw/vault.key
export PGW_AUDIT_LOG=/tmp/pgw/audit.jsonl PGW_SKIP_USER_CONFIG=1
uv run pgw pseudonymize tests/fixtures/customer_letter_de.txt --session-file /tmp/pgw/sid
uv run pgw restore --session "$(cat /tmp/pgw/sid)" out.txt --mode lenient
uv run pgw validate tests/fixtures/invoice_de.txt    # exit 2 when anything is found
uv run pgw classes
uv run pgw vault list
```

```bash
uv sync --group proxy                                # starlette, uvicorn, httpx
uv run pgw-proxy serve --listen 127.0.0.1:8787       # local Anthropic API proxy
PGW_PROXY_TRANSFORM_SYSTEM=0 uv run pgw-proxy install-launchd   # PGW_* + PATH go into the plist
uv run pgw-proxy status
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787      # point Claude Code at the proxy
claude --model "sonnet[1m]"                          # else Claude Code assumes a 200k window
```

Other env vars: `PGW_RESTORE_MODE`, `PGW_CONFIG`, `PGW_PROXY_LISTEN`, `PGW_PROXY_UPSTREAM`,
`PGW_PROXY_SESSION_STRATEGY`, `PGW_PROXY_TRANSFORM_SYSTEM`, `PGW_PROXY_PLACEHOLDER_NOTICE`,
`PGW_PROXY_DEBUG_DIR`, `PGW_PROXY_DEBUG_ORIGINALS`.

## Architecture

- `detect/__init__.py` normalizes the text before the first stage (NFC per grapheme cluster, every
  `Zs` separator to a plain space, every `Cf` character dropped) and keeps an offset map that
  remaps all spans back onto the original text.
- `detect/__init__.py` owns the stage order: `StructuredStage → PatternStage → DictionaryStage →
  ContextStage`, then `correlate()`, then a `min_confidence` filter, then `resolve_overlaps()`.
- Each stage receives the accumulated findings read-only and returns **only its new findings**
  (`detect/base.py`). The shared interfaces in the plan are a contract — do not change a signature
  without updating the plan's "Shared interfaces" section.
- `correlate()` gives every occurrence of the same value one `entity_id`, so the pseudonymizer
  emits one token per entity, not per occurrence.
- `api.py` fails closed: any exception or `LeakageError` purges the session and re-raises; no
  output is produced. `tests/integration/test_no_network.py` statically forbids importing
  `socket`, `http`, `urllib.request`, `requests`, `httpx`, `aiohttp`, `ssl`, `ftplib`, `smtplib`.
- Gender comes only from an explicit salutation word or from config, never from a first name.
- Policies, patterns, validators, context words and dictionaries live in
  `privacy_gateway/data/default_config.yaml`; user YAML overrides it field by field.
- Network code lives **only** in `privacy_gateway_proxy/` (`transform` and `streaming` are pure,
  `server`/`cli` own `httpx`/`uvicorn`). Nothing there may be imported from `privacy_gateway/`.
- The proxy never modifies `thinking` / `redacted_thinking` blocks or a `signature`: Anthropic
  signs them, so a changed byte invalidates the turn. Same for `tools`, `metadata` and images.
- Streaming restores `text_delta` with a holdback: any trailing fragment that could start a token
  is kept back until the next delta or `content_block_stop`, so a token is never split.
- One gateway session per conversation, keyed by the `session_<uuid>` in `metadata.user_id`;
  `server.py` caches the `GatewaySession` instances so a conversation reuses one in-memory mapping.

## Conventions

- TDD: write the failing test first, then the smallest change that makes it pass.
- `ruff` defaults, line length 100, type hints everywhere. No comments that explain *what*;
  docstrings one line.
- Values never appear in findings, reports, audit events or exception messages — only class names,
  spans and counts.
- Commit per task with a conventional message; end the body with
  `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.

## Documentation

- Spec: `docs/superpowers/specs/2026-09-22-local-privacy-gateway-design.md`
- Plan: `docs/superpowers/plans/2026-09-22-local-privacy-gateway.md`
- Proxy spec: `docs/superpowers/specs/2026-09-23-api-proxy-design.md`
- Proxy plan: `docs/superpowers/plans/2026-09-23-api-proxy.md`
- User-facing docs: `README.md`
