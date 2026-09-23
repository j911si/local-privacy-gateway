# Local Privacy Gateway

A local, offline gateway that removes sensitive data from text before it reaches an external
LLM and puts it back afterwards. Detection is deterministic and rule-based; every detected value
is replaced by a reversible token such as `<IBAN_001>`, the mapping is stored AES-256-GCM-encrypted
in a local SQLite vault, and the pseudonymized text is re-scanned before it is released — if
anything survived, the run fails closed and produces no output at all. It ships as a Python
library, a `pgw` CLI, and a local HTTP proxy (`pgw-proxy`) that sits between Claude Code (or any
Anthropic SDK client) and `api.anthropic.com`. It is **not** an NER model and makes **no
guarantee** for data shapes its rules do not describe: unknown formats, lowercased names and
free-form prose about a person are not detected. Because the process is reversible, it is
pseudonymization, not anonymization — secrets that must never come back use irreversible redaction
(`<API_KEY_REDACTED>`).

Tested on macOS. The library and the `pgw` CLI are plain Python and run on Linux as well; the
bundled service installer is launchd-only, a systemd unit for Linux is documented below but must
be installed by hand.

---

## Table of contents

- [How it works](#how-it-works)
- [Installation](#installation)
- [CLI usage](#cli-usage)
- [Library usage](#library-usage)
- [Proxy for Claude Code and the Anthropic API](#proxy-for-claude-code-and-the-anthropic-api)
- [Configuration](#configuration)
- [Security model and known limits](#security-model-and-known-limits)
- [Troubleshooting](#troubleshooting)
- [Automated installation with a coding agent](#automated-installation-with-a-coding-agent)
- [Development](#development)
- [License](#license)

---

## How it works

```
ORIGINAL
   → LOCAL DETECTION
   → LOCAL PSEUDONYMIZATION
   → LOCAL LEAKAGE VALIDATION
   → AI/LLM
   → LOCAL RESTORATION
   → OUTPUT
```

The gateway itself never opens a network connection. A test in
`tests/integration/test_no_network.py` statically forbids `privacy_gateway` from importing
`socket`, `http`, `urllib.request`, `requests`, `httpx`, `aiohttp`, `ssl`, `ftplib` or `smtplib`.
Network code exists only in the separate `privacy_gateway_proxy` package.

### Detection pipeline

Text runs through a fixed stage order, defined in exactly one place
(`privacy_gateway/detect/__init__.py`):

| Step | What it does |
|---|---|
| **Normalization** | NFC per grapheme cluster, `Cf` format characters (zero-width, soft hyphen) dropped, `Zs` separators folded to a plain space. An offset map carries every span back to the original text, so spans stay valid. |
| **StructuredStage** | Parses first, classifies components second: URLs (host, path, query parameters, embedded credentials, signature parameters), e-mail addresses, JWTs, PEM private-key blocks, database connection strings, HTTP headers and cookies. |
| **PatternStage** | One regex set per class where a format exists: IBAN, BIC, credit card, IPv4/IPv6, MAC, GPS, phone numbers, dates, tax and social-security IDs, VIN, vehicle registration, cloud keys (`AKIA…`, `ghp_…`, `glpat-…`, `sk-ant-…`, `xox…`). Each candidate must pass its validator — Luhn, IBAN MOD-97, `ipaddress`, VIN check digit, calendar date — or it is dropped. |
| **DictionaryStage** | Exact and case-insensitive multi-word matching against configured lists plus bundled first/last-name and city lists. Bundled name hits are low-confidence candidates; they only become findings when a context rule or correlation confirms them. |
| **ContextStage** | Deterministic markers: salutations (`Frau`, `Herr`, `Mr`, `Mrs`, `Ms`), `Kundennummer:`, `Konto`, `Vertrag`, `Ticket`, `namespace:`, `pod/`, `password`, `pin`, address grammar, job and department markers. |
| **`correlate()`** | Gives every occurrence of the same value one `entity_id`, so the pseudonymizer emits one token per entity rather than one per occurrence. |
| **`min_confidence` filter** | Drops everything below the configured threshold (default `0.5`). |
| **`resolve_overlaps()`** | Resolves overlapping findings by class priority, then span length, then stage order. |

### Tokens

Format `<{LABEL}_{NNN}>`, zero-padded to three digits, counted per label per session:
`<ACCOUNT_ID_001>`, `<IBAN_002>`. All `PERSON_*` classes share the label `PERSON`; when an explicit
salutation supplied a gender, the label carries it: `<PERSON_FEMALE_001>`, `<PERSON_MALE_002>`,
otherwise `<PERSON_001>`. Gender is **only** taken from a salutation word or from configuration,
never inferred from a first name.

### Vault

A SQLite file whose values are encrypted with AES-256-GCM. The 32-byte key lives in its own file,
created with `O_CREAT|O_EXCL` and mode `0600` inside a `0700` directory; a key file readable by
group or others is rejected with `VaultError`. The associated data of each ciphertext binds
`session_id | token`, so ciphertexts cannot be swapped between tokens. `purge` removes bytes, not
just rows: the connection runs with `PRAGMA secure_delete=ON` and every purge is followed by
`VACUUM`.

### Sessions

Every `pseudonymize()` call creates a fresh session (counters restart at `001`), so two documents
produce no cross-linkable tokens. A **named** session — `Gateway.session(key)`, `pgw pseudonymize
--session-key`, or one conversation in the proxy — keeps its mapping across calls: a value that
already has a token keeps it, new values continue the counter.

### Policies

| Policy | Effect |
|---|---|
| `tokenize` | Reversible. Value encrypted into the vault, replaced by `<CLASS_NNN>`. |
| `redact` | Irreversible. Replaced by `<CLASS_REDACTED>`, nothing is stored. Default for every `SECRET` class. |
| `ignore` | Detected and reported, left in the text unchanged. |

### Fail closed

Before any output is returned, the pseudonymized text is re-scanned with the full pipeline and
searched for every value stored in the session — exact, case-insensitive, whitespace-collapsed
and, for values with at least six digits, digits-only. Every `<…_NNN>` token in the output must
exist in the session mapping. Any hit raises `LeakageError`, the session is purged and **no text
is returned**. Any other exception in any stage aborts the same way. The proxy translates this
into HTTP 422 and sends nothing upstream.

### Example

`tests/fixtures/customer_letter_de.txt` with the bundled defaults:

```bash
uv run pgw pseudonymize tests/fixtures/customer_letter_de.txt \
  --session-file /tmp/sid --report text --out /tmp/letter.safe.txt
```

stderr:

```
session: e62175d58fb7417682a17ff43ea54e6c
ACADEMIC_TITLE: 1
ACCOUNT_ID: 1
ADDRESS: 1
CUSTOMER_ID: 1
DATE_OF_BIRTH: 1
EMAIL: 1
IBAN: 1
ORGANIZATION_NAME: 1
PERSON_FULL_NAME: 1
PERSON_LAST_NAME: 2
PHONE: 1
PLACE_OF_BIRTH: 1
SALUTATION: 2
tokens: 12
leakage: ok
```

Input (excerpt):

```
Musterbank AG
Kundenbetreuung
Lindenstraße 12, 40210 Düsseldorf

Sehr geehrte Frau Petersen,

Ihre Kundennummer: 884512
Ihr Konto 4711 bleibt unverändert bestehen.

Die Gutschrift über 240,00 EUR haben wir auf die IBAN DE89370400440532013000
angewiesen.

Sie erreichen uns telefonisch unter Tel. +49 211 5559021 oder per Mail an
betreuung@musterbank-beispiel.example.

Für unsere Unterlagen: geboren am 04.07.1979 in Bremen.

Bei Fragen zur Anlage wenden Sie sich bitte an Herrn Dr. Waldmann.

Mit freundlichen Grüßen

Anna Petersen
```

`/tmp/letter.safe.txt`:

```
<ORGANIZATION_NAME_001>
Kundenbetreuung
<ADDRESS_001>

Sehr geehrte Frau <PERSON_FEMALE_001>,

Ihre Kundennummer: <CUSTOMER_ID_001>
Ihr Konto <ACCOUNT_ID_001> bleibt unverändert bestehen.

Die Gutschrift über 240,00 EUR haben wir auf die IBAN <IBAN_001>
angewiesen.

Sie erreichen uns telefonisch unter Tel. <PHONE_001> oder per Mail an
<EMAIL_001>.

Für unsere Unterlagen: geboren am <DATE_OF_BIRTH_001> in <PLACE_OF_BIRTH_001>.

Bei Fragen zur Anlage wenden Sie sich bitte an Herrn <ACADEMIC_TITLE_001> <PERSON_MALE_002>.

Mit freundlichen Grüßen

<PERSON_FEMALE_001>
```

The sentence structure survives, the grammatical gender survives in the label, and the same person
gets the same token in the salutation and in the signature. Restoring is byte-identical:

```bash
uv run pgw restore --session "$(cat /tmp/sid)" /tmp/letter.safe.txt --out /tmp/letter.restored.txt
diff tests/fixtures/customer_letter_de.txt /tmp/letter.restored.txt   # no output
```

---

## Installation

### Requirements

- Python ≥ 3.12
- [`uv`](https://docs.astral.sh/uv/) (recommended) — `curl -LsSf https://astral.sh/uv/install.sh | sh`, or `brew install uv`
- Runtime dependencies: `cryptography`, `pyyaml`. The proxy adds `starlette`, `uvicorn`, `httpx`.

### Clone and install

```bash
git clone https://github.com/j911si/local-privacy-gateway.git
cd local-privacy-gateway

uv sync                  # library + pgw CLI + dev tools (pytest, ruff)
uv sync --group proxy    # additionally starlette, uvicorn, httpx for pgw-proxy

uv run pytest -q         # must end in "passed" with no "failed"
uv run pgw --help
```

Without `uv`, a virtual environment works too:

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e .                 # library + pgw
pip install starlette uvicorn httpx   # only if you want the proxy
```

Everything below that starts with `uv run` then works without the `uv run` prefix.

### Where the state lives

These are the compiled-in defaults from `privacy_gateway/data/default_config.yaml`. They are
literal paths, not `XDG_*`-derived, but they follow the XDG layout:

| What | Default path | Overridden by |
|---|---|---|
| Vault database | `~/.local/share/privacy-gateway/vault.db` | `vault.db_path`, `PGW_VAULT_DB` |
| Vault key (32 random bytes, mode `0600`) | `~/.config/privacy-gateway/vault.key` | `vault.key_file`, `PGW_VAULT_KEY_FILE` |
| Audit log (JSON Lines, mode `0600`) | `~/.local/share/privacy-gateway/audit.jsonl` | `audit.path`, `PGW_AUDIT_LOG` |
| User configuration | `~/.config/privacy-gateway/config.yaml` | `--config` / `PGW_CONFIG` add another layer |

Both parent directories are created with mode `0700`. The key file is created on first use; back
it up together with the database, because without the key the vault cannot be decrypted and every
stored token is lost.

### Environment variables

| Variable | Default | Effect |
|---|---|---|
| `PGW_VAULT_DB` | `~/.local/share/privacy-gateway/vault.db` | Path of the encrypted SQLite vault. |
| `PGW_VAULT_KEY_FILE` | `~/.config/privacy-gateway/vault.key` | Path of the 32-byte AES key file. |
| `PGW_AUDIT_LOG` | `~/.local/share/privacy-gateway/audit.jsonl` | Path of the JSONL audit log. Set `audit.path: null` in YAML to disable auditing. |
| `PGW_RESTORE_MODE` | `strict` | Default restore mode, `strict` or `lenient`. |
| `PGW_CONFIG` | unset | Extra configuration file, applied after the user config. |
| `PGW_SKIP_USER_CONFIG` | unset | `1`/`true`/`yes` ignores `~/.config/privacy-gateway/config.yaml`. Useful for reproducible runs and tests. |
| `PGW_PROXY_LISTEN` | `127.0.0.1:8787` | `host:port` the proxy binds to. |
| `PGW_PROXY_UPSTREAM` | `https://api.anthropic.com` | Upstream base URL. Only `https://` or `http://127.0.0.1` / `http://localhost` are accepted; anything else is a `ConfigError`. |
| `PGW_PROXY_SESSION_STRATEGY` | `metadata` | How the vault session key is derived: `metadata`, `header` or `single`. |
| `PGW_PROXY_TRANSFORM_SYSTEM` | `1` | `0`/`false`/`no`/`off` forwards the `system` prompt unchanged. Required with an OAuth login, see below. |
| `PGW_PROXY_PLACEHOLDER_NOTICE` | `1` | `0`/`false`/`no`/`off` suppresses the short notice that explains the placeholder format to the model. |
| `PGW_PROXY_DEBUG_DIR` | unset | Directory for one JSON dump per transformed request (mode `0600` in a `0700` directory). Contains the **pseudonymized** body. |
| `PGW_PROXY_DEBUG_ORIGINALS` | unset (off) | `1`/`true`/`yes`/`on` additionally dumps the **original, untransformed** body of a request that failed the leak check. Clear text. |

---

## CLI usage

Every command reads a `FILE` or stdin (`-`) and accepts `--config PATH`.

| Exit code | Meaning |
|---|---|
| `0` | Success. |
| `1` | Error (bad configuration, unreadable file, unknown token in `strict` restore, vault problem). |
| `2` | Fail-closed: `pseudonymize` detected a leak, or `validate` found something. |

### `pgw pseudonymize`

```
pgw pseudonymize [FILE|-] [--config PATH] [--out PATH] [--session-file PATH]
                          [--session-key KEY] [--report json|text]
```

Writes the pseudonymized text to stdout or `--out` (mode `0600`). The session id always goes to
stderr; `--session-file` additionally writes it to a file with mode `0600`.

```bash
uv run pgw pseudonymize letter.txt --out letter.safe.txt --session-file sid.txt --report text
```

`--report json` prints one value-free JSON object to stderr:

```bash
$ printf 'Kundennummer: 884512, IBAN DE89370400440532013000\n' | uv run pgw pseudonymize - --report json
session: a90842d46f704d35938b7ba36c090b49
{"counts": {"CUSTOMER_ID": 1, "IBAN": 1}, "duration_ms": 46, "leakage": "ok", "tokens": ["<CUSTOMER_ID_001>", "<IBAN_001>"]}
Kundennummer: <CUSTOMER_ID_001>, IBAN <IBAN_001>
```

`--session-key KEY` continues a named session instead of creating a new one. The same value then
keeps its token across runs — and `--report` produces no output, because a continued session has
no per-run summary:

```bash
$ printf 'IBAN DE89370400440532013000\n' | uv run pgw pseudonymize - --session-key demo
session: 1c968610822e4311a854492ef099059b
IBAN <IBAN_001>
$ printf 'IBAN DE89370400440532013000 again\n' | uv run pgw pseudonymize - --session-key demo
session: 1c968610822e4311a854492ef099059b
IBAN <IBAN_001> again
```

Redaction is irreversible and produces no vault entry:

```bash
$ printf 'password: "Hunter2-secret"\napi_key=AKIAIOSFODNN7EXAMPLE\n' | uv run pgw pseudonymize -
session: e384d012bbec419f9e517e1eebae2db9
password: "<PASSWORD_REDACTED>"
api_key=<API_KEY_REDACTED>
```

### `pgw restore`

```
pgw restore --session ID [FILE|-] [--config PATH] [--mode strict|lenient] [--out PATH]
```

Maps the tokens in the model's answer back to the stored values. The n-th occurrence of a token
restores the n-th recorded surface form; further occurrences use the canonical value.

- **`strict`** (default, configurable via `restore.mode` / `PGW_RESTORE_MODE`): every token must be
  known. An unknown token is an error and aborts with exit code 1. Use it when you must be certain
  the answer contains no invented placeholder.
- **`lenient`**: also matches tokens the model altered cosmetically — lowercase, without angle
  brackets, wrapped in backticks or quotes. Unknown tokens stay in the text and are listed on
  stderr as `unknown tokens: …`. The proxy always restores responses in `lenient` mode so a
  hallucinated placeholder cannot abort an answer.

```bash
$ cat answer.txt
Answer about <PERSON_FEMALE_001> and <IBAN_009>.

$ uv run pgw restore --session "$(cat sid.txt)" answer.txt --mode lenient
unknown tokens: <IBAN_009>
Answer about Petersen and <IBAN_009>.

$ uv run pgw restore --session "$(cat sid.txt)" answer.txt --mode strict
error: unknown token: <IBAN_009>
# exit code 1
```

### `pgw validate`

Detection report only, nothing is rewritten and nothing is stored. Exit code `2` when anything was
found, `0` when the text is clean — useful as a pre-commit or CI check.

```bash
$ uv run pgw validate tests/fixtures/invoice_de.txt
ADDRESS: 1
BIC: 1
CARD_EXPIRY: 1
CREDIT_CARD: 1
CUSTOMER_ID: 1
IBAN: 1
INVOICE_ID: 1
PAYMENT_REFERENCE: 1
TAX_ID: 1
# exit code 2

$ printf 'The build finished in twelve seconds.\n' | uv run pgw validate -
no sensitive data detected
# exit code 0
```

### `pgw classes`

Every registered class as `name`, `policy`, `priority`, tab-separated. 140 classes with the bundled
defaults; your own configuration adds to and overrides that list.

```bash
$ uv run pgw classes | head -8
PERSON_FIRST_NAME	tokenize	140
PERSON_LAST_NAME	tokenize	140
PERSON_FULL_NAME	tokenize	140
PERSON_ALIAS	tokenize	140
PERSON_USERNAME	tokenize	140
PERSON_INITIALS	tokenize	140
SALUTATION	ignore	100
TITLE	tokenize	100
```

A higher priority wins overlap resolution. Note that `pgw classes` lists every registered class,
including ones you set to `enabled: false`.

### `pgw vault`

```bash
$ uv run pgw vault list          # session id, creation time, token count
e62175d58fb7417682a17ff43ea54e6c	2026-09-23T07:12:45.026227+00:00	12
1c968610822e4311a854492ef099059b	2026-09-23T07:13:03.090092+00:00	1

$ uv run pgw vault purge --session "$(cat sid.txt)"
purged 1 session(s)

$ uv run pgw vault purge --older-than 30
purged 0 session(s)
```

`--session` and `--older-than` are mutually exclusive and one of them is required. A purge writes a
`vault_purge` audit event and runs `VACUUM`, so the bytes are gone from the database file.

---

## Library usage

```python
from privacy_gateway import ConfigError, Gateway, LeakageError, RestoreError, VaultError

document = (
    "Sehr geehrte Frau Petersen,\n"
    "Ihre IBAN DE89370400440532013000 wurde am 12.03.2026 gutgeschrieben.\n"
)

try:
    with Gateway() as gateway:                      # or Gateway("config.yaml") / Gateway(cfg)
        # 1. Detect only, no rewriting, nothing stored.
        print(gateway.scan(document).counts_by_class())
        # {'SALUTATION': 1, 'PERSON_LAST_NAME': 1, 'IBAN': 1}

        # 2. Pseudonymize. Raises LeakageError instead of returning unsafe text.
        result = gateway.pseudonymize(document)
        print(result.text)
        # Sehr geehrte Frau <PERSON_FEMALE_001>,
        # Ihre IBAN <IBAN_001> wurde am 12.03.2026 gutgeschrieben.
        print(result.session_id, result.report.tokens)
        # a5b79f8229a84adaac0e804e91f5a606 ['<PERSON_FEMALE_001>', '<IBAN_001>']

        # 3. ... send result.text to the model, receive an answer ...
        answer = "Die Gutschrift für <PERSON_FEMALE_001> auf <IBAN_001> ist gebucht."

        # 4. Restore.
        restored = gateway.restore(answer, result.session_id, mode="lenient")
        print(restored.text, restored.unknown_tokens)
        # Die Gutschrift für Petersen auf DE89370400440532013000 ist gebucht. []

        # 5. A named session keeps its mapping across turns.
        chat = gateway.session("conversation-42")
        print(chat.pseudonymize("Frau Petersen ruft an."))
        # Frau <PERSON_FEMALE_001> ruft an.
        print(chat.pseudonymize("Petersen bestätigt IBAN DE89370400440532013000."))
        # <PERSON_FEMALE_001> bestätigt IBAN <IBAN_001>.
        print(chat.restore_text("<PERSON_FEMALE_001> ist informiert."))
        # Petersen ist informiert.
except LeakageError as exc:
    raise SystemExit(f"fail-closed: {len(exc.leaks)} potential leak(s)") from exc
except (ConfigError, VaultError, RestoreError) as exc:
    raise SystemExit(f"gateway error: {type(exc).__name__}") from exc
```

### API surface

| Call | Returns | Notes |
|---|---|---|
| `Gateway(config=None)` | — | `config` is a path, a `Config` object, or `None` for the layered default. Use it as a context manager or call `close()`. |
| `gateway.scan(text)` | `DetectionReport` | Detection only. `.counts_by_class()`, `.findings`, `.entities`. |
| `gateway.pseudonymize(text)` | `PseudonymizeResult` | `.text`, `.session_id`, `.report` (`counts`, `tokens`, `leakage`, `duration_ms`). Creates a fresh session. |
| `gateway.restore(text, session_id, mode=None)` | `RestoreResult` | `.text`, `.restored_count`, `.unknown_tokens`. `mode` defaults to `restore.mode`. |
| `gateway.session(key=None)` | `GatewaySession` | A named, continued session. `key=None` creates an anonymous one. |
| `session.pseudonymize(text)` | `str` | Reuses the tokens this session already assigned. |
| `session.pseudonymize_many(texts)` | `list[str]` | Same, in order, sharing counters. |
| `session.restore(text, mode=None)` | `RestoreResult` | |
| `session.restore_text(text)` | `str` | Convenience wrapper. |
| `session.entries()` | `Mapping[str, VaultEntry]` | Every token mapping this session knows. |
| `gateway.vault` | `Vault` | `list_sessions()`, `purge()`, `purge_older_than()`. Opened lazily. |

### Fail-closed exceptions

All of them derive from `PrivacyGatewayError`, so one `except PrivacyGatewayError` catches
everything.

- **`LeakageError`** — the pseudonymized text still contained something sensitive. `pseudonymize()`
  returns nothing, the session is purged. `exc.leaks` is a list of `Leak(kind, data_class, start,
  end)` — class names and positions only, never values.
- **`RestoreError`** — a token could not be restored in `strict` mode, or the mode name is unknown.
- **`VaultError`** — the vault or its key cannot be read or written: wrong key, key file with
  group/world permissions, wrong key length, decryption failure.
- **`ConfigError`** — invalid configuration: unknown key, unknown class category or policy, wrong
  type, `min_confidence` outside `0..1`, dictionary for a class that does not exist.

Any other exception inside `pseudonymize()` also aborts without producing output, after purging the
session and writing an `error` audit event.

---

## Proxy for Claude Code and the Anthropic API

`pgw-proxy` runs the gateway as a local HTTP service between an Anthropic API client and
`api.anthropic.com`. Requests are pseudonymized before they leave the machine; answers — streaming
or not — are restored before the client sees them.

```
Claude Code ──(real values)──► proxy ──(tokens)──► api.anthropic.com
Claude Code ◄──(real values)── proxy ◄──(tokens)── api.anthropic.com
```

### Running it

```bash
uv sync --group proxy
uv run pgw-proxy serve --listen 127.0.0.1:8787     # foreground
```

The startup log prints the settings the process actually runs with, which is the fastest way to
check that an environment variable arrived:

```
2026-09-23 09:14:21,594 INFO privacy_gateway_proxy: settings listen=127.0.0.1:8799 upstream=http://127.0.0.1:9 transform_system=True placeholder_notice=True debug_dir=None debug_originals=False
INFO:     Uvicorn running on http://127.0.0.1:8799 (Press CTRL+C to quit)
```

`GET /health` answers `{"status":"ok"}` without touching the upstream.

### As a background service (macOS, launchd)

```bash
uv run pgw-proxy install-launchd                  # writes the plist and bootstraps the job
uv run pgw-proxy status
uv run pgw-proxy uninstall-launchd                # boots the job out and deletes the plist
```

`install-launchd` writes `~/Library/LaunchAgents/com.privacy-gateway.proxy.plist` with `RunAtLoad`
and `KeepAlive`, logs to `~/Library/Logs/privacy-gateway/`, and runs
`uv run --project <repo> pgw-proxy serve`. Use `--label` for a different label and `--log-dir` for
a different log directory.

It copies **every `PGW_*` variable that is set in the installing shell** into the plist's
`EnvironmentVariables`, plus the current `PATH` so launchd finds `uv`. The environment of the
installing shell is therefore the configuration of the service:

```bash
PGW_PROXY_TRANSFORM_SYSTEM=0 uv run pgw-proxy install-launchd
```

The command prints the variables it took over. Re-run it after changing one — the plist is
rewritten from the new environment; it is not merged.

```bash
$ uv run pgw-proxy status
label: com.privacy-gateway.proxy
plist: /Users/you/Library/LaunchAgents/com.privacy-gateway.proxy.plist
loaded: no
listening on 127.0.0.1:8787: no
```

`status` exits `0` when the port answers and `1` when it does not, so it works in a health check.

### As a background service (Linux, systemd user unit)

There is no installer for this; write the unit yourself. Replace `/home/you` with your home
directory and use the **absolute** path of `uv` (`command -v uv`), because systemd does not read
your shell profile.

`~/.config/systemd/user/privacy-gateway.service`:

```ini
[Unit]
Description=Local Privacy Gateway proxy
After=network.target

[Service]
Type=simple
WorkingDirectory=/home/you/local-privacy-gateway
ExecStart=/home/you/.local/bin/uv run --project /home/you/local-privacy-gateway pgw-proxy serve
Restart=always
RestartSec=2

Environment=PATH=/home/you/.local/bin:/usr/local/bin:/usr/bin:/bin
Environment=PGW_PROXY_LISTEN=127.0.0.1:8787
Environment=PGW_PROXY_UPSTREAM=https://api.anthropic.com
# Uncomment when the client logs in with OAuth instead of an API key:
# Environment=PGW_PROXY_TRANSFORM_SYSTEM=0

[Install]
WantedBy=default.target
```

```bash
systemctl --user daemon-reload
systemctl --user enable --now privacy-gateway.service
systemctl --user status privacy-gateway.service
journalctl --user -u privacy-gateway.service -f
```

`loginctl enable-linger $USER` keeps the unit running when you are not logged in.

### Pointing a client at it

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8787
claude --model "sonnet[1m]"
```

**The `[1m]` suffix is not optional.** With `ANTHROPIC_BASE_URL` set, Claude Code assumes a 200k
context window regardless of the model and starts autocompacting early; with a large tool set that
turns into repeated compaction of the same conversation. `--model "sonnet[1m]"`, `--model
"opus[1m]"` or `"model": "sonnet[1m]"` in `~/.claude/settings.json` restores the 1M window and
stops the thrashing. This is a property of the client, not of the proxy — it reproduces against an
unmodified passthrough.

A shell function keeps the private setup separate from your normal `claude`:

```bash
claude-private() {
  ANTHROPIC_BASE_URL=http://127.0.0.1:8787 \
  command claude --model "sonnet[1m]" "$@"
}
```

Note that `PGW_*` variables belong to the **proxy process**, not to the client. Putting
`PGW_PROXY_TRANSFORM_SYSTEM=0` into this function has no effect on a proxy that launchd or systemd
already started; it belongs in the service environment (see above).

### What is transformed

Transformed on `POST /v1/messages` and `POST /v1/messages/count_tokens`:

- **Request:** `system` (string, or the `text` of `type: "text"` blocks), `messages[].content`
  (string or `text` blocks), `tool_result` content (string or `text` blocks), every string leaf
  inside `tool_use.input`, and `source.data` of a `document` block whose `source.type` is `text`.
- **Response:** `content[].text` and every string leaf in `tool_use.input`.

Never touched, forwarded unchanged and **not scanned**:

- `thinking` and `redacted_thinking` blocks and their `signature` — Anthropic signs them, so a
  single changed byte invalidates the turn.
- `image` blocks, and `document` blocks with a base64 or PDF source.
- Server-side and MCP tool blocks: `server_tool_use`, `mcp_tool_use`, `search_result`.
- `tools` definitions, `metadata`, `model`, and all headers.

`GET` and every path outside `/v1/messages…` is proxied verbatim. A `POST` to a `/v1/messages…`
path the proxy cannot transform — unparsable body, non-object body, a body with `Content-Encoding`,
or a sub-path such as `/v1/messages/batches` — is refused with HTTP 422 and never reaches the
upstream. That is deliberate: forwarding it unchanged would mean forwarding clear text.

### Streaming

SSE is parsed event by event. `text_delta` is restored incrementally with a holdback: any trailing
fragment that could be the beginning of a token is kept back until the next delta or
`content_block_stop`, so a token is never split across deltas. `input_json_delta` is buffered per
content block and emitted as one restored delta at `content_block_stop`, which makes tool calls
appear slightly later in the stream (typically under a second). Every other event —
`message_start`, `ping`, `thinking_delta`, `signature_delta`, `message_delta`, `message_stop`,
`error` — is forwarded byte-identical.

### Sessions

One vault session per conversation, so a value keeps its token across turns and prompt caching
keeps working. Strategies (`PGW_PROXY_SESSION_STRATEGY`):

| Strategy | Key |
|---|---|
| `metadata` (default) | The `session_id` field of a JSON `metadata.user_id` as Claude Code sends it; otherwise the `session_<uuid>` part of `metadata.user_id`; otherwise the `X-PGW-Session` header; otherwise a random per-process key. |
| `header` | The `X-PGW-Session` header, else the per-process key. |
| `single` | One fixed key for everything. |

The key must match `[A-Za-z0-9._-]{1,64}`; anything else is refused with HTTP 400. The server keeps
the 64 most recently used `GatewaySession` objects in memory; a conversation that falls out is
reloaded from the vault.

### Placeholder notice

A model that sees `<IBAN_001>` tends to answer with an invented IBAN instead of the placeholder.
The proxy therefore prepends one short text block to the **first user message** of every
transformed request:

```
<privacy-gateway>
Some values in this conversation are pseudonymized placeholders: an uppercase class name and a
three-digit number in angle brackets, written <CLASS_NNN>. They stand for real values that are
restored locally after your reply. Always reproduce placeholders verbatim, exactly as written,
including angle brackets and numbers. Never guess, invent or replace them with example values,
and never remove them.
</privacy-gateway>
```

A string `content` becomes a block list for this. The block is inserted at most once per request,
is visible to the model as ordinary conversation content, counts as one more field in the audit
line, and never goes into `system` — it sits in the messages because an OAuth client's system
prompt cannot be changed (see below). Disable it with `PGW_PROXY_PLACEHOLDER_NOTICE=0`.

### OAuth / Claude subscription: `PGW_PROXY_TRANSFORM_SYSTEM=0`

A client logged in with OAuth (a Claude Pro/Max subscription instead of an API key) gets
`429 rate_limit_error` with the body `"Error"` and **without** any `anthropic-ratelimit-*` header
for every request whose `system` prompt the proxy had changed, while an otherwise identical
passthrough request answers with 200.

```bash
export PGW_PROXY_TRANSFORM_SYSTEM=0   # 0/false/no/off; default 1
```

With the switch the `system` field — string or block list — reaches the upstream byte for byte, is
not counted in `fields`, and the audit line carries `system_transformed: false`. The `messages` are
pseudonymized as before.

The explanation — Anthropic checks the Claude Code system prompt against a fingerprint on OAuth
requests, so one changed byte is enough — is a **hypothesis**, verified empirically on 2026-09-23,
not documented Anthropic behaviour. Treat the switch as a workaround, not as a supported feature.

**Consequence, and it matters:** everything the system prompt carries — project instruction files,
memory files, skill descriptions, tool documentation — leaves the machine unchanged. Only the
conversation content is protected. With an API key the switch is not needed and you get the full
protection.

### Access control

The proxy answers only requests whose `Host` header is loopback (`127.0.0.1`, `localhost`, `[::1]`,
with or without a port) as long as it is bound to a loopback address; anything else gets HTTP 403.
Binding to a non-loopback address turns the host check off and logs a warning at startup.

```bash
$ curl -s -H 'Host: evil.example' -X POST http://127.0.0.1:8787/v1/messages -d '{}'
{"type":"error","error":{"type":"privacy_gateway_forbidden","message":"host header is not loopback"}}
```

There is **no proxy auth token**. Anything that can reach the port and knows or guesses a session
key can have that session's tokens restored. On a single-user machine bound to loopback that is
acceptable; on a shared machine it is not.

The proxy holds no credentials of its own: `x-api-key` and `Authorization` are forwarded untouched.

### Status codes the proxy produces itself

| Code | `error.type` | When |
|---|---|---|
| 400 | `privacy_gateway_session` | The session key does not match `[A-Za-z0-9._-]{1,64}`. |
| 403 | `privacy_gateway_forbidden` | `Host` header is not loopback while bound to loopback. |
| 413 | `privacy_gateway_too_large` | Request body larger than 32 MiB. |
| 422 | `privacy_gateway_rejected` | `POST` to `/v1/messages…` that cannot be transformed: unparsable body, non-object body, `Content-Encoding` set, or a sub-path such as `/v1/messages/batches`. Nothing is sent upstream. |
| 422 | `privacy_gateway_leak` | The leak check found residue in the transformed request. Nothing is sent upstream. The message lists class names and a count, never values. |
| 502 | `privacy_gateway_upstream` | The upstream connection failed. |

Upstream status codes and error bodies are passed through unchanged.

```bash
$ curl -s -X POST http://127.0.0.1:8787/v1/messages -H 'content-type: application/json' -d 'not json'
{"type":"error","error":{"type":"privacy_gateway_rejected","message":"request body is not a transformable JSON object"}}
```

### Debug mode

`PGW_PROXY_DEBUG_DIR` points at a directory into which the proxy writes every transformed request
body as `<timestamp>-<session_key>.json` with mode `0600`, in a directory created with mode `0700`.
That is exactly the pseudonymized JSON that goes upstream, so it answers "what really left the
machine".

A request that fails the leak check is written as
`<timestamp>-<session_key>-FAILED-original.json` and contains the **original, untransformed body**,
because that is the only way to see which value tripped the check. Such a request is never sent
upstream. That second dump is clear text and therefore needs its own switch:

```bash
export PGW_PROXY_DEBUG_DIR=~/pgw-debug
export PGW_PROXY_DEBUG_ORIGINALS=1    # only while you are actually debugging
```

Both kinds contain full prompts and grow quickly. Use them for a single debugging run, delete the
dumps, and unset the variables afterwards. `install-launchd` copies both into the plist, so a
forgotten variable keeps writing dumps from the background service.

### Audit log

One JSON object per line, mode `0600`, never any content. The proxy adds `proxy_request` to the
core's `pseudonymize`, `session_pseudonymize`, `restore`, `vault_purge` and `error` events. A real
sequence for one non-streaming request:

```json
{"ts": "2026-09-23T07:14:58.905939+00:00", "event": "session_pseudonymize", "session_id": "699ed07dca0e4b63b82d5c5e31d32eec", "new_tokens": 0, "reused_tokens": 0, "leakage": "ok", "duration_ms": 47}
{"ts": "2026-09-23T07:14:58.908523+00:00", "event": "session_pseudonymize", "session_id": "699ed07dca0e4b63b82d5c5e31d32eec", "new_tokens": 2, "reused_tokens": 0, "leakage": "ok", "duration_ms": 2}
{"ts": "2026-09-23T07:14:58.929209+00:00", "event": "proxy_request", "session_key": "11111111-2222-3333-4444-555555555555", "path": "/v1/messages", "fields": 2, "tokens": 2, "leakage": "ok", "streaming": false, "duration_ms": 75, "system_transformed": true}
{"ts": "2026-09-23T07:14:58.929707+00:00", "event": "restore", "session_id": "699ed07dca0e4b63b82d5c5e31d32eec", "restored_count": 1, "unknown_token_count": 0, "mode": "lenient"}
```

`fields` is the number of transformed strings, `tokens` the number of mappings the session holds,
`leakage` is `ok`, `failed`, `rejected` or `upstream_error`. Follow it live with
`tail -f ~/.local/share/privacy-gateway/audit.jsonl`.

---

## Configuration

Load order — each layer overrides the previous one **field by field**, it does not replace whole
sections:

1. Bundled `privacy_gateway/data/default_config.yaml`
2. `~/.config/privacy-gateway/config.yaml` (skipped when `PGW_SKIP_USER_CONFIG=1`)
3. `--config PATH`, then `PGW_CONFIG`
4. `PGW_VAULT_DB`, `PGW_VAULT_KEY_FILE`, `PGW_AUDIT_LOG`, `PGW_RESTORE_MODE`

So a class block that only sets `policy:` keeps the built-in category, patterns and context words.
Dictionary lists are appended, not replaced. Unknown keys are an error, never a silent no-op.

### A complete annotated example

`~/.config/privacy-gateway/config.yaml`:

```yaml
classes:
  # A new class. `category` is required for a class that does not exist yet.
  PROJECT_CODE:
    category: PROJECT           # one of PERSON ROLE ORGANIZATION CONTACT LOCATION BIRTH
                                # IDENTIFIER FINANCIAL HEALTH NETWORK DOMAIN URL APPLICATION
                                # KUBERNETES DATABASE TENANT PROJECT EDGE REPOSITORY TICKET
                                # SECRET HTTP
    policy: tokenize            # tokenize | redact | ignore
    patterns: ['\bPRJ-\d{5}\b'] # Python regex; a capturing group marks the part to replace
    context_words: [project, projekt]
    context_required: false     # true: only a match near one of the context words counts
    # priority: 90              # optional, higher wins overlap resolution
    # token_label: PROJECT      # optional, label used in the token instead of the class name

  # Override one field of a built-in class; everything else stays.
  EMAIL:
    policy: redact              # e-mail addresses are now irreversible <EMAIL_REDACTED>

  # Switch a built-in class off entirely.
  CARD_EXPIRY:
    enabled: false

dictionaries:
  # Inline terms, matched case-insensitively, multi-word aware.
  CUSTOMER_NAME: [Contoso GmbH, Fabrikam AG]
  INTERNAL_DOMAIN: [corp.example.internal]
  # Or one term per line from a text file; blank lines and `#` comments are ignored.
  # A relative path is resolved against the directory of this config file.
  files:
    CUSTOMER_NAME: ./customers.txt
    INTERNAL_DOMAIN: ./domains.txt
    HOSTNAME: ./hostnames.txt

vault:
  db_path: ~/.local/share/privacy-gateway/vault.db
  key_file: ~/.config/privacy-gateway/vault.key

audit:
  path: ~/.local/share/privacy-gateway/audit.jsonl   # `null` disables the audit log

restore:
  mode: strict                  # strict | lenient

person:
  record_gender_from_salutation: true   # false: never put a gender into a PERSON token

languages: [de, en]

min_confidence: 0.5             # 0..1; findings below this are dropped
```

`customers.txt`:

```
# one term per line
Contoso GmbH
Fabrikam AG
```

Result:

```bash
$ printf 'Projekt PRJ-40711 für Contoso GmbH läuft auf corp.example.internal.\n' | pgw pseudonymize -
session: 54f2e120faca4668befd06265476bd72
Projekt <PROJECT_CODE_001> für <CUSTOMER_NAME_001> läuft auf <INTERNAL_DOMAIN_001>.
```

Dictionaries are the practical answer to the biggest gap in rule-based detection: customer names,
project names, internal domains and hostnames have no recognizable format, so nothing finds them
unless you list them. Keep those lists in files, keep the files next to the config, and keep both
out of any repository.

Use `pgw classes --config your.yaml` to see the effective class list, and `pgw validate` on a
representative document to check whether a new rule fires.

### Validation errors

Configuration problems raise `ConfigError` and exit with code 1, with a message that names the
offending key:

```bash
$ pgw classes --config bad.yaml
error: unknown keys for class 'FOO': ['categorie']

$ pgw classes --config bad2.yaml
error: 'min_confidence' must be between 0 and 1
```

Other cases: `unknown configuration keys in <path>`, `unknown category '…' for class '…'`,
`unknown policy '…'`, `'patterns' of class '…' must be a list`, `dictionaries for unknown classes:
[…]`, `restore mode must be one of ('strict', 'lenient')`, `config file not found`, `invalid YAML
in config file`. A typo is always an error and never a silently ignored setting — that is on
purpose, because a silently ignored class definition would mean silently disabled protection.

---

## Security model and known limits

### What this protects against

Sending clear-text personal data, credentials and internal identifiers to an external LLM provider.
The provider sees `<PERSON_FEMALE_001>` and `<IBAN_001>`; the mapping stays on your machine in an
encrypted vault; secrets classified as `SECRET` are redacted irreversibly and are not stored at
all.

Supporting properties:

- **Fail closed.** Any exception in any stage aborts `pseudonymize()` without producing output. The
  pseudonymized text is re-scanned and searched for every stored value; any hit raises
  `LeakageError` and purges the session.
- **Never logged.** Findings, detection reports, audit events and exception messages carry class
  names, spans and counts — never values. The audit log records counts, not content.
- **No network in the core.** `privacy_gateway` imports no networking module; a test enforces this
  statically. All network code lives in `privacy_gateway_proxy`, which the core never imports.
- **Per-session tokens.** Two separate documents produce no cross-linkable tokens.
- **Gender** comes only from an explicit salutation or from configuration, never from a first name.

### What this does not protect against

- **A local attacker with access to both the key file and the database.** The vault is encrypted at
  rest against someone who copies `vault.db` alone. Someone who can read your home directory as
  your user reads both files and decrypts everything. There is no passphrase, no key rotation, no
  multi-user separation.
- **Prompt injection that turns restored values into actions.** Restoration happens on the way back
  to the client. A model instructed by text inside a file it read can put `<IBAN_001>` into a tool
  call; the proxy restores it, and the *real* value is what your local tool then executes or sends.
  The gateway prevents the value from reaching the model, not from reaching a tool.
- **Anything at the proxy port.** There is no auth token. Any local process that reaches
  `127.0.0.1:8787` and knows a session key can use the proxy as a restore oracle.
- **Whatever the rules do not describe.** See below.

### Known limits

- **Rule-based only.** Regexes, validators, dictionaries and context rules. There is no NER model,
  so anything the rules do not describe is not found. Classes without a recognizable format —
  person aliases, customer names, department names — need a dictionary entry or a context marker.
- **Names need shape.** `Anna Müller` is detected, `anna müller` is not (lowercase), and a bare
  `Müller` without a salutation or a known full name is not. A single first name or a single city
  name on its own falls below `min_confidence` and is dropped, because treating every occurrence of
  a common first name as a person produces unusable false positives.
- **Name parts across turns.** A session recognizes only the surface forms it has stored. If turn 1
  contains `Frau Anna Müller` and turn 2 contains only `Müller`, turn 2 may go out in the clear or
  receive a second token. Within one document `correlate()` joins them; across turns it does not.
  (An automatic derivation of name parts was implemented and removed again: it made the leak check
  reject legitimate requests.)
- **Images, PDFs and base64.** `image` blocks and `document` blocks with a base64 or PDF source
  pass through unchanged and are never scanned. Screenshots and scanned invoices are not protected.
- **`thinking` blocks keep their tokens.** They are signed by Anthropic, so the proxy cannot rewrite
  them. Extended-thinking text you see may contain `<IBAN_001>` instead of the value.
- **Redaction is irreversible.** A round trip is byte-identical only for documents that contain no
  `redact` class; everything else comes back with `<CLASS_REDACTED>`.
- **`ß`/`SS` case folding** is not covered by the leak check, so a value written `Straße` in the
  input and `STRASSE` in the output would not be flagged.
- **Generic markers are off by default.** Words like "reference", "number" or "name" are not
  context markers, because they produce too many false positives. Add them per class with
  `context_words` if your documents need them.
- **Streaming holdback.** The holdback covers token fragments of up to 80 characters after a `<`,
  and bracket-less uppercase fragments of up to 73 characters. A class name longer than that can
  break restoration in a stream.
- **No proxy auth token**, and the proxy serves exactly one vault and one configuration per
  process.
- **Out of scope:** ML/NER models, OCR, binary documents, multi-user vaults, key rotation.

### Further reading

- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability.
- [`docs/reviews/2026-09-23-security-review.md`](docs/reviews/2026-09-23-security-review.md) — a
  full adversarial review with reproduced findings, written in German. Note that it describes the
  state at the time it was written; several findings have since been fixed, and the ones that
  remain are listed above.
- [`docs/superpowers/specs/2026-09-22-local-privacy-gateway-design.md`](docs/superpowers/specs/2026-09-22-local-privacy-gateway-design.md)
  — core design spec.
- [`docs/superpowers/specs/2026-09-23-api-proxy-design.md`](docs/superpowers/specs/2026-09-23-api-proxy-design.md)
  — proxy design spec.

---

## Troubleshooting

### HTTP 422 `privacy_gateway_leak` — a request was refused

This is the fail-closed path doing its job: something in the request still looked sensitive after
pseudonymization. The request was not sent upstream.

1. Look at the audit log for the `proxy_request` line with `"leakage": "failed"` — it gives you the
   session key, the path and the timestamp.
2. Turn on `PGW_PROXY_DEBUG_DIR` **and** `PGW_PROXY_DEBUG_ORIGINALS=1`, reproduce, and read the
   `-FAILED-original.json` dump. It is clear text, so delete it afterwards.
3. Identify the class that fired. Usually one of two things is happening: a value appears in two
   spellings and only one was tokenized, or a rule matched a fragment of a longer value.
4. **Sharpen the rule, do not weaken the leak check.** Add the value to a dictionary, add a
   `context_word`, or add a pattern that covers the full value instead of a fragment. Lowering
   `min_confidence` or disabling a class to make the error go away removes protection instead of
   fixing the cause.

Note that the same 422 status with `"type": "privacy_gateway_rejected"` is a different problem: the
body was not transformable at all (see the status table above).

### HTTP 403 `privacy_gateway_forbidden`

The `Host` header is not loopback. Use `http://127.0.0.1:8787` or `http://localhost:8787` in
`ANTHROPIC_BASE_URL`, not a LAN address or a hostname that resolves elsewhere. If you really need
to bind to a non-loopback address, the check turns itself off — and so does your only access
control, which the startup log warns about.

### HTTP 429 with an empty body and no rate-limit headers

You are logged in with OAuth (Pro/Max subscription) and the proxy changed the system prompt. Set
`PGW_PROXY_TRANSFORM_SYSTEM=0` in the environment of the **proxy process** — for a launchd service
that means re-running `PGW_PROXY_TRANSFORM_SYSTEM=0 uv run pgw-proxy install-launchd`, for systemd
it means adding the `Environment=` line and `systemctl --user restart`. A real rate limit looks
different: it carries `anthropic-ratelimit-*` headers and a JSON error body.

### Claude Code compacts the conversation over and over

`ANTHROPIC_BASE_URL` is set and the model has no `[1m]` suffix, so the client assumes a 200k
window. Start it as `claude --model "sonnet[1m]"` or put `"model": "sonnet[1m]"` into
`~/.claude/settings.json`.

### `decryption failed` / `VaultError`

The vault database and the key file do not belong together. Most often `PGW_VAULT_KEY_FILE` points
somewhere else than it did when the session was created, or the key file was deleted and silently
recreated — a fresh key cannot decrypt old sessions. Restore the original key file. Also check the
permissions: a key file readable by group or others is rejected on purpose (`chmod 600`).

### `error: unknown token: <X_001>` on restore

You are in `strict` mode and the text contains a token this session does not know — because the
model invented it, or because you passed the wrong session id. Check the session id first
(`pgw vault list`). If the answer legitimately contains invented placeholders, use `--mode lenient`;
unknown tokens then stay in the text and are listed on stderr.

### `error: address already in use` on `pgw-proxy serve`

Something already listens on the port — usually an installed launchd or systemd service.
`pgw-proxy status` tells you whether the job is loaded; `lsof -nP -iTCP:8787 -sTCP:LISTEN` tells you
which process it is. Either stop the service or start your foreground instance on another port with
`--listen 127.0.0.1:8799`.

### Nothing gets detected in my documents

Run `pgw validate document.txt` to see what the rules find. If the answer is "nothing", the values
have no format the rules recognize — customer names, internal project names, hostnames. Add them as
dictionary entries or give the class a `context_word` that actually appears in your documents. Check
`min_confidence` too; the default `0.5` is already permissive, and raising it drops more.

---

## Automated installation with a coding agent

If you use a coding agent (Claude Code, Codex, Cursor or similar), you can hand it the prompt below
and it will install and verify the gateway end to end without asking questions. The same prompt,
with a short explanation of what it does and what to check afterwards, lives in
[`docs/AGENT-INSTALL.md`](docs/AGENT-INSTALL.md).

Read it before you run it — it installs a background service and appends a shell function to your
shell profile.

```text
You are installing the Local Privacy Gateway (https://github.com/j911si/local-privacy-gateway) on
this machine and verifying that it works. Complete the whole installation autonomously: do not ask
me any questions, use the defaults stated below for every decision, and report at the end.

ASSUMPTIONS AND DEFAULTS (use these, do not ask):
- Install directory: $PGW_HOME if that variable is set, otherwise ~/local-privacy-gateway.
- Proxy listen address: 127.0.0.1:8787.
- Gateway config directory: ~/.config/privacy-gateway. Vault data: ~/.local/share/privacy-gateway.
- Model default for the shell function: sonnet[1m]. The [1m] suffix is required, never drop it.
- OS detection: `uname -s` -> "Darwin" means macOS (use launchd), "Linux" means Linux (use a
  systemd user unit). Anything else: skip the service step and report it.
- Login type: if the environment variable ANTHROPIC_API_KEY is set and non-empty, the user has an
  API key, so leave PGW_PROXY_TRANSFORM_SYSTEM unset (full protection). If it is empty or unset,
  assume an OAuth/subscription login and set PGW_PROXY_TRANSFORM_SYSTEM=0, because Anthropic
  answers OAuth requests with a modified system prompt with HTTP 429.
- Do not modify any existing shell configuration except appending one clearly marked block to the
  user's shell rc file (~/.zshrc for zsh, ~/.bashrc for bash). Never edit or reorder existing lines.
- If any step fails, stop, do not improvise a workaround, and report exactly what failed with the
  command output.

SECURITY RULES (non-negotiable):
- Never write an API key, token or password into any file, and never echo one.
- Never set PGW_PROXY_DEBUG_ORIGINALS. It writes untransformed prompts to disk in clear text.
- Never read, print, copy or back up ~/.config/privacy-gateway/vault.key or any vault.db.
- Never send a request to api.anthropic.com as part of this installation. All smoke tests are local.
- If a test fails, report it. Do not edit, skip or weaken tests to make them pass.

STEPS:

1. Check prerequisites.
   - `git --version` must succeed. If git is missing, install it (macOS: `xcode-select --install`
     or `brew install git`; Linux: the distribution package manager) and re-check.
   - `uv --version` must succeed. If uv is missing, install it with
     `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `brew install uv` on macOS if brew is
     present), then make sure the uv binary is on PATH for this session
     (`export PATH="$HOME/.local/bin:$PATH"`) and re-check.
   - uv provides the Python interpreter; the project requires Python >= 3.12. You do not need a
     system Python.

2. Clone the repository into the install directory. If the directory already exists and is a git
   checkout of this repository, run `git pull --ff-only` instead of cloning. If it exists and is
   something else, stop and report.
   `git clone https://github.com/j911si/local-privacy-gateway.git <install dir>`

3. Install dependencies from the install directory:
   `uv sync --group proxy`
   Expected: uv resolves and installs; the packages starlette, uvicorn and httpx appear.

4. Run the test suite: `uv run pytest -q`
   Expected: the last line reports passed tests and contains no "failed" and no "error".
   If anything failed, STOP here and report the failing output. Do not continue.

5. Create the configuration directory and a starter config.
   - `mkdir -p ~/.config/privacy-gateway && chmod 700 ~/.config/privacy-gateway`
   - `mkdir -p ~/.local/share/privacy-gateway && chmod 700 ~/.local/share/privacy-gateway`
   - Create the three empty dictionary files ~/.config/privacy-gateway/customers.txt,
     domains.txt and hostnames.txt, each containing only the comment line
     "# one term per line", and chmod 600 each of them.
   - Write ~/.config/privacy-gateway/config.yaml with mode 600 and exactly this content:

       dictionaries:
         files:
           CUSTOMER_NAME: ./customers.txt
           INTERNAL_DOMAIN: ./domains.txt
           HOSTNAME: ./hostnames.txt

       restore:
         mode: lenient

     If config.yaml already exists, do not overwrite it; leave it alone and note this in the report.

6. First run, which creates the vault key. From the install directory:
   `uv run pgw pseudonymize tests/fixtures/customer_letter_de.txt`
   Expected on stdout: the letter with tokens such as <ORGANIZATION_NAME_001>, <ADDRESS_001>,
   <PERSON_FEMALE_001>, <CUSTOMER_ID_001>, <IBAN_001>, <PHONE_001>, <EMAIL_001>. On stderr a line
   "session: <32 hex characters>". Exit code 0.
   Then verify with `ls -l ~/.config/privacy-gateway/vault.key` that the key file exists with mode
   -rw------- (0600). Do not print its content.

7. Install the background service.
   macOS: from the install directory run
     `PGW_PROXY_TRANSFORM_SYSTEM=0 uv run pgw-proxy install-launchd`
     (omit the PGW_PROXY_TRANSFORM_SYSTEM prefix if ANTHROPIC_API_KEY was set, see assumptions).
     Expected output: "installed /Users/<you>/Library/LaunchAgents/com.privacy-gateway.proxy.plist",
     a list of the PGW_* variables taken over, the log directory, and a line
     "export ANTHROPIC_BASE_URL=http://127.0.0.1:8787".
   Linux: write ~/.config/systemd/user/privacy-gateway.service with this content, substituting the
   real home directory and the absolute path of uv from `command -v uv`:

       [Unit]
       Description=Local Privacy Gateway proxy
       After=network.target

       [Service]
       Type=simple
       WorkingDirectory=<install dir>
       ExecStart=<absolute uv path> run --project <install dir> pgw-proxy serve
       Restart=always
       RestartSec=2
       Environment=PATH=<dirname of uv>:/usr/local/bin:/usr/bin:/bin
       Environment=PGW_PROXY_LISTEN=127.0.0.1:8787
       Environment=PGW_PROXY_UPSTREAM=https://api.anthropic.com
       Environment=PGW_PROXY_TRANSFORM_SYSTEM=0

       [Install]
       WantedBy=default.target

     Omit the PGW_PROXY_TRANSFORM_SYSTEM line if ANTHROPIC_API_KEY was set. Then run
     `systemctl --user daemon-reload` and `systemctl --user enable --now privacy-gateway.service`.
   If neither service manager is available, skip this step, and in the report tell the user to run
   `uv run pgw-proxy serve --listen 127.0.0.1:8787` in the foreground instead.

8. Check the status.
   `uv run pgw-proxy status`
   Expected: the label, the plist path, "loaded: yes" on macOS, and
   "listening on 127.0.0.1:8787: yes". Exit code 0. On Linux use
   `systemctl --user status privacy-gateway.service` plus
   `uv run pgw-proxy status --listen 127.0.0.1:8787` (which will report loaded: no, that is correct
   there, only the listening line matters).
   If the port does not answer, read the log (macOS:
   ~/Library/Logs/privacy-gateway/com.privacy-gateway.proxy.err.log; Linux:
   `journalctl --user -u privacy-gateway.service -n 50`) and report.

9. Local smoke tests. No request reaches Anthropic in any of these.
   a) `curl -s http://127.0.0.1:8787/health`
      Expected exactly: {"status":"ok"}
   b) `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8787/v1/messages \
         -H 'content-type: application/json' -d 'not json'`
      Expected: 422
   c) `curl -s -o /dev/null -w '%{http_code}' -X POST http://127.0.0.1:8787/v1/messages \
         -H 'Host: evil.example' -H 'content-type: application/json' -d '{}'`
      Expected: 403
   If a code differs, report the actual code and the response body; do not change the code to make
   it match.

10. Append the shell function. Detect the shell from $SHELL (zsh -> ~/.zshrc, bash -> ~/.bashrc;
    if neither, report and skip). If the marker "# >>> local-privacy-gateway >>>" is already
    present, replace the block between the markers instead of appending a second one. Append:

        # >>> local-privacy-gateway >>>
        claude-private() {
          ANTHROPIC_BASE_URL=http://127.0.0.1:8787 \
          command claude --model "sonnet[1m]" "$@"
        }
        # <<< local-privacy-gateway <<<

11. Final report. Print, in this order:
    - Installed version and commit hash (`git -C <install dir> rev-parse --short HEAD`).
    - The install directory, the config file, the vault database path and the vault key path.
    - Whether PGW_PROXY_TRANSFORM_SYSTEM=0 was set, and the one-sentence reason.
    - The result of every smoke test with its actual status code.
    - How to use it: open a new shell and run `claude-private`.
    - Where the audit log is and how to watch it
      (`tail -f ~/.local/share/privacy-gateway/audit.jsonl`).
    - Uninstall instructions: macOS `uv run pgw-proxy uninstall-launchd`; Linux
      `systemctl --user disable --now privacy-gateway.service` and delete the unit file; then
      remove the block between the shell markers, delete the install directory, and — only if the
      user wants to discard every stored mapping — delete ~/.local/share/privacy-gateway and
      ~/.config/privacy-gateway.
    - Anything you skipped or that failed, stated plainly.
```

---

## Development

```bash
uv sync --group proxy
uv run pytest -q                                   # full suite
uv run pytest tests/unit/test_validators.py -q -k luhn   # one test
uv run ruff check .                                # lint, line length 100
```

Conventions, in short — [`CONTRIBUTING.md`](CONTRIBUTING.md) has the details:

- **TDD.** Write the failing test first, then the smallest change that makes it pass.
- `ruff` defaults, line length 100, type hints everywhere. Docstrings are one line. No comments that
  explain *what* the code does.
- Values never appear in findings, reports, audit events or exception messages — only class names,
  spans and counts. A patch that puts a value into a log line will not be merged.
- Each detection stage receives the accumulated findings read-only and returns **only its new
  findings**. The shared interfaces in `docs/superpowers/plans/2026-09-22-local-privacy-gateway.md`
  are a contract; do not change a signature without updating that section.
- `detect/__init__.py` is the only place that knows the stage order.
- Network code lives **only** in `privacy_gateway_proxy/`. `transform` and `streaming` are pure
  functions; `server` and `cli` own `httpx` and `uvicorn`. Nothing there may be imported from
  `privacy_gateway/`.
- Commit per task with a conventional message.

Documentation:

- Core spec: `docs/superpowers/specs/2026-09-22-local-privacy-gateway-design.md`
- Core plan: `docs/superpowers/plans/2026-09-22-local-privacy-gateway.md`
- Proxy spec: `docs/superpowers/specs/2026-09-23-api-proxy-design.md`
- Proxy plan: `docs/superpowers/plans/2026-09-23-api-proxy.md`
- Security review: `docs/reviews/2026-09-23-security-review.md`
- Agent installation prompt: `docs/AGENT-INSTALL.md`

---

## License

MIT — see [`LICENSE`](LICENSE).

Security reports: [`SECURITY.md`](SECURITY.md). Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
