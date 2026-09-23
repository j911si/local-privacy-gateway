# Local Privacy Gateway – Design

Date: 2026-09-22
Status: approved for implementation

## 1. Purpose

A local, offline pseudonymization gateway that sits between a document and an external AI/LLM:

```
ORIGINAL → LOCAL DETECTION → LOCAL PSEUDONYMIZATION → LOCAL LEAKAGE VALIDATION → AI/LLM → LOCAL RESTORATION → OUTPUT
```

The gateway never calls any external service. The LLM never sees original sensitive values or the token vault. The gateway fails closed: if any potentially sensitive value survives pseudonymization, no output is produced.

Terminology: the process is reversible, so it is **pseudonymization/tokenization**, not anonymization. Secrets that must never be restored use **irreversible redaction**.

## 2. Decisions

| Topic | Decision |
|---|---|
| Language / tooling | Python ≥ 3.12, project managed with `uv`, tests with `pytest`. Runtime deps: `cryptography`, `pyyaml`. Nothing else. |
| Vault | SQLite file, values encrypted with AES-256-GCM. Key is a random 32-byte file at `~/.config/privacy-gateway/vault.key` (mode 0600, auto-created). Overridable via config or `PGW_VAULT_KEY_FILE`. DB path default `~/.local/share/privacy-gateway/vault.db`, overridable via config or `PGW_VAULT_DB`. |
| Token scope | Per session. Each `pseudonymize()` call creates a session (UUID4); token counters start at 001 per session. No cross-document linkability. |
| Restoration guarantee | Restoring the pseudonymized text itself reproduces the original byte-for-byte (round-trip property, tested). |
| Gender in tokens | Recorded only from an explicit salutation in the source text (`Frau`, `Herr`, `Mrs`, `Ms`, `Mr`) or from configuration. Never inferred from a first name. |
| Languages | Detection vocabularies for German and English. |
| Repo docs language | English (code, README, spec). |

## 3. Package layout

```
privacy_gateway/
  __init__.py          # exports Gateway, exceptions, result types
  api.py               # Gateway facade
  cli.py               # `pgw` entry point (argparse)
  config.py            # YAML loading, defaults, validation, class registry build
  classes.py           # DataClass model, categories, policies, priorities
  model.py             # Finding, Span, Entity, DetectionReport, results
  detect/
    __init__.py        # Pipeline orchestrator: runs stages A–G, returns DetectionReport
    structured.py      # A: URL, email, JWT, PEM blocks, connection strings, cookies, headers
    patterns.py        # B: high-confidence regex candidates per class
    validators.py      # C+D: Luhn, IBAN MOD-97, IP, MAC, VIN, tax/SSN formats, dates
    dictionaries.py    # E: user/customer dictionaries + bundled name/city lists
    context.py         # F: deterministic context rules (salutations, key: value markers)
    correlation.py     # G: entity resolution across findings
    spans.py           # overlap resolution (priority → length → stage order)
  pseudonymize.py      # token generation, text rewriting, redaction policy
  leakage.py           # H: leakage validation, fail-closed
  restore.py           # token → original, strict/lenient
  vault.py             # encrypted SQLite storage
  audit.py             # JSONL audit log without values
  data/
    default_config.yaml
    first_names_de_en.txt, last_names_de_en.txt, cities_de_en.txt, salutations.yaml
tests/
  unit/…  integration/…  fixtures/…
docs/
pyproject.toml, README.md, CLAUDE.md
```

Each module has one purpose and is testable in isolation. `detect/__init__.py` is the only place that knows the stage order.

## 4. Data model (`model.py`)

- `Span(start, end)` – character offsets in the original text.
- `Finding(span, data_class, stage, confidence, entity_id | None, attributes: dict)` – `attributes` holds non-sensitive context only, e.g. `{"gender": "female", "source": "salutation"}`. Findings never carry the value; the value is read from the text via the span when needed.
- `Entity(id, data_class, canonical_norm, surface_forms: set[Span], attributes)` – `canonical_norm` is the first 16 hex characters of the SHA-256 of the normalized key, never the value itself.
- `DetectionReport(findings, entities, stage_stats)`.
- `PseudonymizeResult(text, session_id, report: SummaryReport)`; `SummaryReport` = counts per class, token list, leakage status. No values.
- `RestoreResult(text, restored_count, unknown_tokens: list[str])`.
- Exceptions: `PrivacyGatewayError` → `LeakageError`, `ConfigError`, `VaultError`, `RestoreError`.

## 5. Classification framework (`classes.py`, `config.py`)

- `DataClass(name, category, policy, priority, enabled, token_label)` – there is no `restore` field; `redact` classes are irreversible because nothing is stored.
- Categories: `PERSON, ROLE, ORGANIZATION, CONTACT, LOCATION, BIRTH, IDENTIFIER, FINANCIAL, HEALTH, NETWORK, DOMAIN, URL, APPLICATION, KUBERNETES, DATABASE, TENANT, PROJECT, EDGE, REPOSITORY, TICKET, SECRET, HTTP`.
- Policies: `tokenize` (reversible, stored in vault), `redact` (irreversible, `<CLASS_REDACTED>`, nothing stored), `ignore` (detected, reported, left unchanged – only allowed for classes the user explicitly downgrades).
- Default policy: all `SECRET` classes → `redact`; everything else → `tokenize`.
- Priority order for overlap resolution (high → low): SECRET > FINANCIAL > IDENTIFIER > HEALTH > CONTACT > NETWORK > URL > DOMAIN > PERSON > ORGANIZATION > LOCATION > BIRTH > ROLE > infrastructure names (APPLICATION…TICKET) > HTTP.
- All classes from the task statement are registered in `data/default_config.yaml`. Users extend via their own YAML:

```yaml
classes:
  PROJECT_CODE:
    category: PROJECT
    policy: tokenize
    patterns: ['\bPRJ-\d{5}\b']
    context_words: [project, projekt]
  API_KEY:
    policy: redact        # override built-in
dictionaries:
  CUSTOMER_NAME: [Contoso GmbH, Fabrikam AG]
  INTERNAL_DOMAIN: [corp.example.internal]
  files:
    EMPLOYEE_ID: ./employee_ids.txt
```

Config load order: bundled defaults → `~/.config/privacy-gateway/config.yaml` → `--config PATH` → environment overrides (`PGW_*`). Unknown keys → `ConfigError`.

## 6. Detection pipeline (`detect/`)

Stage order and responsibilities:

**A. Structured parsers** – parse first, then classify components independently.
- URL: `urllib.parse`; emits `URL` for the whole match, plus `HOSTNAME`/`FQDN`/`INTERNAL_DOMAIN` for the host, `API_PATH` when path looks like `/api/…` or `/v\d+/…`, `QUERY_PARAMETER`/`QUERY_VALUE` per parameter, embedded `user:pass@` → `PASSWORD`, `sig=`/`X-Amz-Signature`/`sv=…&sig=` → `SIGNED_URL`/`SAS_TOKEN`.
- Email: local part and domain; domain matched against dictionaries for `CUSTOMER_DOMAIN`/`INTERNAL_DOMAIN`.
- JWT: three base64url segments, header decodes to JSON with `alg` → `JWT`.
- PEM blocks: `-----BEGIN (RSA|EC|OPENSSH|) PRIVATE KEY-----` … → `SSH_PRIVATE_KEY`/`TLS_PRIVATE_KEY`/`PRIVATE_KEY`.
- Connection strings: `postgres://`, `mysql://`, `mongodb://`, `Server=…;Password=…` → `DATABASE_CONNECTION_STRING` plus components (`DATABASE_HOST`, `DATABASE_USER`, `PASSWORD`, `DATABASE_NAME`).
- HTTP headers / cookies: `Authorization: Bearer …`, `Cookie: name=value`, `Set-Cookie`, `X-*:` → `ACCESS_TOKEN`, `SESSION_COOKIE`, `AUTH_COOKIE`, `CSRF_TOKEN`, `CUSTOM_HEADER`/`HEADER_VALUE`, `COOKIE`/`COOKIE_VALUE`.

**B. High-confidence regex candidates** – one pattern set per class where a format exists: IBAN, BIC, credit card, IPv4/IPv6, MAC, GPS, phone (E.164 and DE/AT/CH national forms), dates of birth (with context), tax IDs (DE Steuer-ID, USt-IdNr, AT, CH), social security (DE SV-Nummer, US SSN), passport/ID formats, VIN, vehicle registration (DE), cloud keys (`AKIA…`, `ghp_…`, `glpat-…`, `xox…`, Azure client secrets, GCP JSON key markers), generic `api_key=`/`password=` assignments.

**C/D. Validators and checksums** – every candidate from B passes its validator or is dropped:
- Credit card → Luhn → context (card/karte/visa/…) raises confidence; Luhn fail → drop.
- IBAN → country code + expected length → MOD-97.
- IP → `ipaddress`; private ranges → `PRIVATE_IP`, else `PUBLIC_IP`; both also `IP_ADDRESS`.
- MAC → hex/separator shape; VIN → check-digit; DE Steuer-ID → check digit; DE SV-Nummer → check digit; USt-IdNr → country rules.
- Dates → real calendar date; classified `DATE_OF_BIRTH` only with context (`geboren`, `geb.`, `DOB`, `born`, `Geburtsdatum`).

**E. Dictionaries** – exact and case-insensitive multi-word matching (Aho-Corasick-style trie) for configured lists, plus bundled first/last names and cities. Bundled name lists alone produce `PERSON_FIRST_NAME`/`PERSON_LAST_NAME` candidates with *low* confidence; they become findings only when a context rule (F) or a correlation (G) confirms them, to limit false positives on common words.

**F. Deterministic context rules** –
- Salutation + capitalized token(s): `Frau|Herr|Mrs|Mr|Ms|Dr.|Prof.` → `SALUTATION`/`ACADEMIC_TITLE` + `PERSON_LAST_NAME` or `PERSON_FULL_NAME`; gender attribute set from the salutation word only.
- Key/value markers: `Kunde:`, `customer`, `Account`, `Konto`, `Vertrag`, `Ticket`, `Incident`, `Rechnung`, `Mitarbeiter-Nr`, `namespace:`, `pod/`, `cluster`, `tenant`, `repo`, `branch`, `password`, `pin`, `tan`, `otp`, `token` → the value after the marker gets the mapped class.
- Job/department markers: `Abteilung`, `Department`, `Leiter`, `Head of`, `CTO`… → `DEPARTMENT`/`JOB_TITLE`.
- Address grammar: `<Street> <No>, <PLZ> <City>` → `ADDRESS` plus component findings.
- Health/medical: vocabulary lists (diagnosis words, ICD-10 codes) → `MEDICAL_INFORMATION`/`HEALTH_INFORMATION` on the matching sentence fragment.

**G. Entity correlation** –
- Same normalized value + same class → same entity.
- `PERSON_FULL_NAME` "Anna Müller" then bare "Müller" or "A. Müller" → same entity (unique last-name match within the document).
- Email local part containing a known entity's last name → link entity ids (both still tokenized).
- Gender attribute propagates within an entity; conflicting salutations → attribute dropped, audit warning.

**Span resolution (`spans.py`)** – overlapping findings are resolved by class priority, then span length, then stage order. Component findings inside a structured parent (URL → host) are kept as attributes of the parent finding and pseudonymized as a whole unless the parent class is `ignore`.

## 7. Pseudonymization (`pseudonymize.py`)

- Token format: `<{LABEL}_{NNN}>`, `NNN` zero-padded 3 digits per label per session (`<ACCOUNT_ID_001>`). Labels default to the class name; `PERSON_*` classes use label `PERSON` plus optional gender: `<PERSON_FEMALE_001>`, `<PERSON_MALE_002>`, `<PERSON_001>`.
- One entity → one token, regardless of surface form; surface forms are stored so restoration can reproduce each occurrence exactly.
- Redaction: `<{CLASS}_REDACTED>` with no counter and no vault entry.
- Text rewriting works right-to-left over resolved spans so offsets stay valid.
- Deterministic within a session: identical input → identical output for the same session mapping.

## 8. Vault (`vault.py`)

SQLite schema:

```
sessions(id TEXT PK, created_at TEXT, doc_sha256 TEXT, config_hash TEXT)
mappings(session_id TEXT, token TEXT, data_class TEXT, nonce BLOB, ciphertext BLOB,
         attributes_json TEXT, PRIMARY KEY(session_id, token))
surface_forms(session_id TEXT, token TEXT, ordinal INTEGER, nonce BLOB, ciphertext BLOB)
```

- AES-256-GCM via `cryptography`; associated data = `session_id || token` so ciphertexts cannot be swapped between tokens.
- Key file created with `os.open(..., 0o600)`; refuse to start if permissions are wider than 0600.
- Operations: `create_session`, `store(session, token, value, surface_forms, attrs)`, `load(session) -> dict[token, value]`, `purge(session)`, `purge_older_than(days)`, `list_sessions()`.
- Plaintext never written to disk outside the encrypted columns; no plaintext in exceptions.
- `purge` removes bytes, not just rows: the connection runs with `PRAGMA secure_delete=ON` and every purge is followed by `VACUUM`, so no ciphertext, token or session id survives in the database file or its WAL.

## 9. Leakage validation (`leakage.py`)

Runs on the pseudonymized text before it is returned:

1. Re-run the full detection pipeline on the output. Any finding with policy ≠ `ignore` → leak.
2. For every original value stored in the session, search the output for: exact, case-insensitive, whitespace-collapsed, and (for values with ≥ 6 digits) digits-only variants. Any hit → leak.
3. Token integrity: every `<…_NNN>` token in the output must exist in the session mapping; malformed or unknown tokens → leak (guards against rewrite bugs).

Any leak → `LeakageError(report)` where the report lists classes and positions only. `pseudonymize()` does not return text; the session is purged from the vault. Any exception in any stage also aborts without output (fail closed).

## 10. Restoration (`restore.py`)

- Token regex `<([A-Z][A-Z_]*?)_(\d{3})>`.
- `strict` (default): every token must be known; unknown → `RestoreError`.
- `lenient`: also matches tokens the LLM altered cosmetically (`PERSON_FEMALE_001` without brackets, wrapped in backticks/quotes, lowercase); unknown tokens are left in place and listed in `RestoreResult.unknown_tokens`.
- Surface forms: the n-th occurrence of a token restores the n-th recorded surface form; occurrences beyond the recorded count use the canonical value (LLM may repeat a token).
- Round-trip: `restore(pseudonymize(x).text, session) == x` for every fixture.

## 11. Audit log (`audit.py`)

JSON Lines, default `~/.local/share/privacy-gateway/audit.jsonl` (config/`PGW_AUDIT_LOG`). Events: `pseudonymize` (session_id, doc_sha256, counts per class, token count, leakage: ok|failed, duration_ms), `restore` (session_id, restored_count, unknown_token_count, mode), `vault_purge`, `error` (exception type, stage). Never values, never surface forms, never text fragments. Sensitive fields are structurally impossible: the audit API only accepts the summary types.

## 12. CLI (`cli.py`, entry point `pgw`)

```
pgw pseudonymize [FILE|-] [--config PATH] [--out PATH] [--session-file PATH] [--report json|text]
pgw restore --session ID [FILE|-] [--mode strict|lenient] [--out PATH]
pgw validate [FILE|-]           # detection report only, exit 2 if anything sensitive found
pgw classes [--config PATH]     # list registered classes, policy, priority
pgw vault list | purge --session ID | purge --older-than DAYS
```

Exit codes: 0 success, 1 error, 2 fail-closed (leakage or validate hit). Session id printed to stderr and optionally written to `--session-file`. Pseudonymized text goes to stdout/`--out`.

## 13. Library API (`api.py`)

```python
from privacy_gateway import Gateway

gw = Gateway(config="config.yaml")          # or Gateway() for defaults
res = gw.pseudonymize(text)                  # PseudonymizeResult
res.text, res.session_id, res.report.counts
out = gw.restore(llm_answer, res.session_id, mode="lenient")   # RestoreResult
rep = gw.scan(text)                          # DetectionReport (no rewriting)
```

## 14. Testing

- Unit: each validator (Luhn valid/invalid, IBAN valid/invalid/wrong length, IP private/public/invalid, MAC, VIN, Steuer-ID, SV-Nummer), each structured parser (URL decomposition incl. embedded credentials, email, JWT, PEM, connection string, headers/cookies), context rules (gender only from salutation; explicit test that "Anna" alone yields no gender), correlation (Müller / A. Müller / Frau Müller → one entity), span resolution, pseudonymizer token numbering, vault (ciphertext ≠ plaintext, wrong key → `VaultError`, permissions check, associated-data swap fails), leakage (inject residual value → `LeakageError`, session purged), restore strict/lenient/surface-forms.
- Integration: fixture corpus (`tests/fixtures/*.txt`, DE and EN: customer letter, incident ticket, Kubernetes log excerpt, HTTP request dump, invoice) → pseudonymize → assert no original value in output → restore → byte-equal.
- CLI: subprocess tests for each command and exit codes.
- Config: custom class via YAML detected; policy override applied; unknown key → `ConfigError`.
- Guard test: `privacy_gateway` never imports `socket`, `http`, `urllib.request`, `requests` (static check over the package).

## 15. Out of scope for v1

ML/NER models, OCR, binary documents, HTTP proxy mode, multi-user vault, key rotation. These can be added without changing the stage interfaces.
