# Local Privacy Gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `privacy_gateway`, an offline Python package + `pgw` CLI that detects sensitive data, replaces it with context-preserving tokens, validates that nothing leaked (fail closed), stores the mapping AES-GCM-encrypted in SQLite, and restores the original after the LLM answers.

**Architecture:** A staged detection pipeline (structured parsers → regex+validators → dictionaries → context rules → entity correlation → overlap resolution) produces a `DetectionReport`; the pseudonymizer rewrites text right-to-left and assigns one token per entity; leakage validation re-scans the output and searches for every original value; the vault stores mappings per session; restoration maps tokens back (strict/lenient). Every module has one responsibility and is tested in isolation.

**Tech Stack:** Python ≥ 3.12, `uv`, `pytest`, runtime deps only `cryptography` and `pyyaml`. Spec: `docs/superpowers/specs/2026-09-22-local-privacy-gateway-design.md` (read it first).

## Global Constraints

- No network: the package must never import `socket`, `http.client`, `urllib.request`, `requests`, `httpx`, `aiohttp` (guard test in Task 8).
- Runtime dependencies limited to `cryptography` and `pyyaml`. Dev: `pytest`, `ruff`.
- Findings, reports, audit events, exception messages never contain sensitive values. Values are read from the text via `Span` only where needed (pseudonymizer, vault, leakage).
- Gender attribute only from explicit salutation words (`Frau, Herr, Herrn, Mrs, Ms, Mr` with/without dot) or config. Never from first names.
- Fail closed: any exception in any stage aborts `pseudonymize()` without output; any leak raises `LeakageError` and purges the session.
- Token format `<LABEL_NNN>` (3-digit, per label, per session); redaction `<CLASS_REDACTED>`.
- Round-trip: `restore(pseudonymize(x).text, sid).text == x` byte-for-byte.
- Code and docs in English. `ruff` defaults, line length 100. Type hints everywhere. No comments that explain *what*; docstrings one line max.
- Commit after every task with a conventional message (`feat:`, `test:`, `chore:`, `docs:`); end commit bodies with `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Run tests with `uv run pytest -q`.

## Shared interfaces (contract for all tasks)

Created in Task 1. Later tasks must not change them without updating this section.

```python
# privacy_gateway/model.py
from __future__ import annotations
from dataclasses import dataclass, field

class PrivacyGatewayError(Exception): ...
class ConfigError(PrivacyGatewayError): ...
class VaultError(PrivacyGatewayError): ...
class RestoreError(PrivacyGatewayError): ...
class LeakageError(PrivacyGatewayError):
    def __init__(self, leaks: list["Leak"]): ...   # self.leaks; __str__ lists kind/class/positions only

@dataclass(frozen=True)
class Leak:
    kind: str            # "residual_finding" | "original_value" | "unknown_token"
    data_class: str      # class name or "" for unknown_token
    start: int
    end: int

@dataclass(frozen=True, order=True)
class Span:
    start: int
    end: int
    def overlaps(self, other: "Span") -> bool     # ranges intersect; touching ends do not overlap
    def contains(self, other: "Span") -> bool
    def __len__(self) -> int

@dataclass
class Finding:
    span: Span
    data_class: str
    stage: str                       # "structured" | "pattern" | "dictionary" | "context" | "correlation"
    confidence: float                # 0.0 .. 1.0
    entity_id: str | None = None
    attributes: dict[str, str] = field(default_factory=dict)   # non-sensitive only
    children: list["Finding"] = field(default_factory=list)    # components (URL host, query …)

@dataclass
class Entity:
    id: str                          # "e1", "e2", …
    data_class: str
    canonical_norm: str              # first 16 hex chars of sha256(normalized key), never the value
    spans: list[Span]
    attributes: dict[str, str] = field(default_factory=dict)

@dataclass
class DetectionReport:
    findings: list[Finding]          # final, non-overlapping, sorted by span.start
    entities: dict[str, Entity]
    stage_stats: dict[str, int]      # stage name -> number of findings emitted
    def counts_by_class(self) -> dict[str, int]

@dataclass
class SummaryReport:
    counts: dict[str, int]
    tokens: list[str]
    leakage: str                     # "ok"
    duration_ms: int

@dataclass
class PseudonymizeResult:
    text: str
    session_id: str
    report: SummaryReport

@dataclass
class RestoreResult:
    text: str
    restored_count: int
    unknown_tokens: list[str]

@dataclass
class VaultEntry:
    value: str
    data_class: str
    surface_forms: list[str]         # occurrence order in the original text
    attributes: dict[str, str]

@dataclass
class SessionInfo:
    id: str
    created_at: str                  # ISO-8601 UTC, e.g. "2026-09-22T10:15:00+00:00"
    token_count: int
```

```python
# privacy_gateway/classes.py
from enum import Enum

class Policy(str, Enum):
    TOKENIZE = "tokenize"; REDACT = "redact"; IGNORE = "ignore"

class Category(str, Enum):
    PERSON, ROLE, ORGANIZATION, CONTACT, LOCATION, BIRTH, IDENTIFIER, FINANCIAL, HEALTH, NETWORK,
    DOMAIN, URL, APPLICATION, KUBERNETES, DATABASE, TENANT, PROJECT, EDGE, REPOSITORY, TICKET,
    SECRET, HTTP            # values equal to the names

CATEGORY_PRIORITY: dict[Category, int]
# SECRET=220, FINANCIAL=210, IDENTIFIER=200, HEALTH=190, CONTACT=180, NETWORK=170, URL=160,
# DOMAIN=150, PERSON=140, ORGANIZATION=130, LOCATION=120, BIRTH=110, ROLE=100,
# APPLICATION/KUBERNETES/DATABASE/TENANT/PROJECT/EDGE/REPOSITORY/TICKET=90, HTTP=80

@dataclass(frozen=True)
class DataClass:
    name: str
    category: Category
    policy: Policy
    priority: int                     # defaults to CATEGORY_PRIORITY[category]; config may override
    enabled: bool = True
    token_label: str | None = None    # None -> name; PERSON_* -> "PERSON"
    patterns: tuple[str, ...] = ()    # regexes for the pattern stage
    validator: str | None = None      # key in validators.VALIDATORS
    context_words: tuple[str, ...] = ()   # key/value markers for the context stage
    context_required: bool = False        # pattern hits count only with a context word nearby

class ClassRegistry:
    def __init__(self, classes: Iterable[DataClass]) -> None
    def get(self, name: str) -> DataClass          # raises ConfigError if unknown
    def __contains__(self, name: str) -> bool
    def __iter__(self) -> Iterator[DataClass]
    def enabled(self) -> list[DataClass]
    def label_for(self, name: str) -> str
    def priority_for(self, name: str) -> int
```

```python
# privacy_gateway/config.py
@dataclass
class VaultConfig:   db_path: Path; key_file: Path
@dataclass
class AuditConfig:   path: Path | None
@dataclass
class RestoreConfig: mode: str = "strict"                 # "strict" | "lenient"
@dataclass
class PersonConfig:  record_gender_from_salutation: bool = True
@dataclass
class Config:
    registry: ClassRegistry
    dictionaries: dict[str, list[str]]     # class name -> terms (merged from lists + files)
    vault: VaultConfig
    audit: AuditConfig
    restore: RestoreConfig
    person: PersonConfig
    languages: list[str]                   # default ["de", "en"]
    min_confidence: float                  # default 0.5
    def hash(self) -> str                  # sha256 hex of the normalized config

def load_config(path: str | Path | None = None, *, env: Mapping[str, str] | None = None) -> Config
# Order: bundled data/default_config.yaml -> ~/.config/privacy-gateway/config.yaml (if exists) -> path -> env
# Env: PGW_VAULT_DB, PGW_VAULT_KEY_FILE, PGW_AUDIT_LOG, PGW_RESTORE_MODE, PGW_CONFIG (extra path).
# Unknown YAML keys -> ConfigError.
```

```python
# privacy_gateway/detect/base.py
class Stage(Protocol):
    name: str
    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return only NEW findings. `findings` = everything emitted by earlier stages (read-only)."""
```

Stage classes: `StructuredStage` (`structured.py`), `PatternStage` (`patterns.py`), `DictionaryStage` (`dictionaries.py`), `ContextStage` (`context.py`). Correlation and overlap resolution are functions:

```python
# detect/correlation.py
def correlate(text: str, findings: list[Finding], config: Config) -> tuple[list[Finding], dict[str, Entity]]
# detect/spans.py
def resolve_overlaps(findings: list[Finding], registry: ClassRegistry) -> list[Finding]
# detect/__init__.py
class Pipeline:
    def __init__(self, config: Config) -> None
    def run(self, text: str) -> DetectionReport
```

```python
# pseudonymize.py
@dataclass
class TokenAssignment:
    token: str; data_class: str; entity_id: str | None; spans: list[Span]; attributes: dict[str, str]
@dataclass
class PseudonymizedText:
    text: str; assignments: list[TokenAssignment]      # assignments exclude redactions
def pseudonymize_text(text: str, report: DetectionReport, config: Config) -> PseudonymizedText

# vault.py
def load_or_create_key(path: Path) -> bytes
class Vault:
    def __init__(self, db_path: Path, key_file: Path) -> None
    def create_session(self, doc_sha256: str, config_hash: str) -> str
    def store(self, session_id: str, token: str, data_class: str, value: str,
              surface_forms: list[str], attributes: dict[str, str]) -> None
    # VaultError when the token is already assigned to a different value
    def load(self, session_id: str) -> dict[str, VaultEntry]     # VaultError if session unknown
    def purge(self, session_id: str) -> None
    def purge_older_than(self, days: int) -> int
    def list_sessions(self) -> list[SessionInfo]
    def close(self) -> None

# leakage.py
def check_leakage(text: str, entries: Mapping[str, VaultEntry], scan: Callable[[str], DetectionReport],
                  registry: ClassRegistry) -> None        # raises LeakageError

# restore.py
def restore_text(text: str, entries: Mapping[str, VaultEntry], mode: str = "strict") -> RestoreResult

# audit.py
class AuditLog:
    def __init__(self, path: Path | None) -> None       # None -> disabled
    def pseudonymize(self, session_id: str, counts: dict[str, int],
                     token_count: int, leakage: str, duration_ms: int) -> None
    def restore(self, session_id: str, restored_count: int, unknown_token_count: int, mode: str) -> None
    def vault_purge(self, sessions: int) -> None
    def error(self, exc_type: str, stage: str) -> None

# api.py
class Gateway:
    def __init__(self, config: str | Path | Config | None = None) -> None
    def pseudonymize(self, text: str) -> PseudonymizeResult
    def restore(self, text: str, session_id: str, mode: str | None = None) -> RestoreResult
    def scan(self, text: str) -> DetectionReport
    def close(self) -> None
    # also context manager

# cli.py
def main(argv: list[str] | None = None) -> int
```

## Execution waves

- **Wave 0 (sequential):** Task 1.
- **Wave A (parallel, after Task 1):** Tasks 2, 3, 4, 5, 6, 7.
- **Wave B (after Wave A):** Task 8.
- **Wave C (after Task 8):** Task 9.

---

### Task 1: Project scaffold, data model, class registry, config

**Files:**
- Create: `pyproject.toml`, `privacy_gateway/__init__.py`, `privacy_gateway/model.py`, `privacy_gateway/classes.py`, `privacy_gateway/config.py`, `privacy_gateway/detect/__init__.py` (empty for now), `privacy_gateway/detect/base.py`, `privacy_gateway/data/default_config.yaml`, `tests/conftest.py`, `tests/unit/test_model.py`, `tests/unit/test_classes.py`, `tests/unit/test_config.py`

**Produces:** everything in "Shared interfaces" for `model.py`, `classes.py`, `config.py`, `detect/base.py`.

- [ ] **Step 1: `pyproject.toml`** – name `privacy-gateway`, version `0.1.0`, `requires-python = ">=3.12"`, deps `cryptography>=42`, `pyyaml>=6`; `[project.scripts] pgw = "privacy_gateway.cli:main"`; `[dependency-groups] dev = ["pytest>=8", "ruff>=0.5"]`; `[tool.pytest.ini_options] testpaths = ["tests"]`; `[tool.ruff] line-length = 100`. Build backend `hatchling`, include `privacy_gateway/data/*`. Run `uv sync` and `uv run python -c "import privacy_gateway"`.
- [ ] **Step 2: `model.py`** exactly as in Shared interfaces. Tests: overlap/contains/len; `counts_by_class`; `str(LeakageError([...]))` contains kind and positions and no other text.
- [ ] **Step 3: `classes.py`** exactly as in Shared interfaces. Tests: `get` unknown → `ConfigError`; `label_for("PERSON_FIRST_NAME") == "PERSON"`; `priority_for` uses category default.
- [ ] **Step 4: `data/default_config.yaml`** with top-level keys `classes`, `dictionaries`, `vault`, `audit`, `restore`, `person`, `languages`, `min_confidence`. Register **every** class from the spec list (spec §3 of the task statement — copy the list from the design spec's category table; 136 (exact count of the task statement's list) names) with `category`. `policy: redact` and `restore: false` for every SECRET-category class (API_KEY … SAS_TOKEN); all others `tokenize`. `PERSON_*` classes get `token_label: PERSON`. Add `patterns`/`validator`/`context_words` for these classes (Task 2 relies on them):

  | class | patterns (Python regex) | validator | context_words |
  |---|---|---|---|
  | IBAN | `\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}[ ]?[A-Z0-9]{1,4}\b` | `iban` | iban |
  | BIC | `\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b` | `bic` | bic, swift |
  | CREDIT_CARD | `\b(?:\d[ -]?){13,19}\b` | `luhn` | card, karte, visa, mastercard, amex, kreditkarte |
  | CVV | `\b\d{3,4}\b` (context required) | – | cvv, cvc, prüfziffer |
  | CARD_EXPIRY | `\b(?:0[1-9]\|1[0-2])/(?:\d{2}\|\d{4})\b` (context required) | – | expiry, gültig bis, exp |
  | IP_ADDRESS | IPv4 `\b(?:\d{1,3}\.){3}\d{1,3}\b`; IPv6 `\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b` | `ip` | – |
  | MAC_ADDRESS | `\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b` | `mac` | – |
  | GPS_COORDINATES | `-?\d{1,2}\.\d{4,},\s*-?\d{1,3}\.\d{4,}` | – | – |
  | PHONE / MOBILE_PHONE / FAX | `(?:\+\d{1,3}[ \-]?)?(?:\(?\d{2,5}\)?[ \-/]?)\d{3,}(?:[ \-]?\d{2,})+` (context required) | `phone` | PHONE: tel, telefon, phone, fon; MOBILE_PHONE: mobil, mobile, handy, cell; FAX: fax |
  | DATE_OF_BIRTH | `\b\d{1,2}[./]\d{1,2}[./]\d{2,4}\b`; `\b\d{4}-\d{2}-\d{2}\b` (context required) | `date` | geboren, geb., geburtsdatum, dob, born, birthday |
  | TAX_ID | `\b\d{2}[ ]?\d{3}[ ]?\d{3}[ ]?\d{3}\b` (context required); `\b[A-Z]{2}[0-9A-Z]{8,12}\b` (context required) | `tax_id` | steuer, tax, ust, vat |
  | SOCIAL_SECURITY_ID | `\b\d{2}[ ]?\d{6}[ ]?[A-Z][ ]?\d{3}\b`; `\b\d{3}-\d{2}-\d{4}\b` | `ssn` | sozialversicherung, sv-nummer, ssn, social security |
  | VIN | `\b[A-HJ-NPR-Z0-9]{17}\b` | `vin` | vin, fahrgestell |
  | VEHICLE_REGISTRATION | `\b[A-ZÄÖÜ]{1,3}[- ][A-Z]{1,2}[ ]?\d{1,4}[EH]?\b` (context required) | – | kennzeichen, plate |
  | JWT | `\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b` | – | – |
  | AWS_ACCESS_KEY | `\b(?:AKIA\|ASIA)[A-Z0-9]{16}\b` | – | – |
  | AWS_SECRET_KEY | `\b[A-Za-z0-9/+=]{40}\b` (context required) | – | aws_secret, secret_access_key |
  | GITHUB_TOKEN | `\b(?:ghp\|gho\|ghu\|ghs\|ghr)_[A-Za-z0-9]{36,}\b`; `\bgithub_pat_[A-Za-z0-9_]{80,}\b` | – | – |
  | GITLAB_TOKEN | `\bglpat-[A-Za-z0-9_-]{20,}\b` | – | – |
  | PERSONAL_ACCESS_TOKEN | `\bxox[baprs]-[A-Za-z0-9-]{10,}\b` | – | pat, personal access token |
  | AZURE_SECRET | `\b[A-Za-z0-9~._-]{34,40}\b` (context required) | – | client_secret, azure |
  | GCP_CREDENTIAL | `"private_key_id":\s*"[a-f0-9]{40}"`; `\bAIza[0-9A-Za-z_-]{35}\b` | – | – |
  | API_KEY | `(?i)\b(?:api[_-]?key\|x-api-key)\s*[:=]\s*["']?([A-Za-z0-9_\-]{16,})` | – | – |
  | API_SECRET | `(?i)\bapi[_-]?secret\s*[:=]\s*["']?([A-Za-z0-9_\-]{12,})` | – | – |
  | CLIENT_SECRET | `(?i)\bclient[_-]?secret\s*[:=]\s*["']?([A-Za-z0-9_\-~.]{12,})` | – | – |
  | PASSWORD | `(?i)\b(?:password\|passwd\|pwd\|kennwort\|passwort)\s*[:=]\s*["']?(\S{4,})` | – | – |
  | PIN | `(?i)\bpin\s*[:=]?\s*(\d{4,8})\b` | – | – |
  | TAN | `(?i)\btan\s*[:=]?\s*(\d{6,8})\b` | – | – |
  | OTP | `(?i)\b(?:otp\|one-time code\|einmalcode)\s*[:=]?\s*(\d{6,8})\b` | – | – |
  | ACCESS_TOKEN | `(?i)bearer\s+([A-Za-z0-9._\-]{16,})`; `(?i)access[_-]?token\s*[:=]\s*["']?([A-Za-z0-9._\-]{16,})` | – | – |
  | REFRESH_TOKEN | `(?i)refresh[_-]?token\s*[:=]\s*["']?([A-Za-z0-9._\-]{16,})` | – | – |
  | SESSION_ID | `(?i)\b(?:session[_-]?id\|sessionid\|jsessionid\|phpsessid)\s*[:=]\s*["']?([A-Za-z0-9._\-]{8,})` | – | – |
  | CSRF_TOKEN | `(?i)\b(?:csrf[_-]?token\|x-csrf-token\|_csrf)\s*[:=]\s*["']?([A-Za-z0-9._\-]{8,})` | – | – |
  | OAUTH_CODE | `(?i)[?&]code=([A-Za-z0-9._\-]{16,})` | – | – |
  | EMPLOYEE_ID, CUSTOMER_ID, ACCOUNT_ID, USER_ID, CONTRACT_ID, INSURANCE_ID, TRANSACTION_ID, PAYMENT_REFERENCE, INVOICE_ID, INCIDENT_ID, FINDING_ID, TICKET_ID, CASE_ID, TENANT_ID, ORGANIZATION_ID, SUBSCRIPTION_ID, PASSPORT_ID, NATIONAL_ID, DRIVER_LICENSE_ID, BANK_ACCOUNT | – (context stage only) | – | ACCOUNT_ID: `account, konto, kontonummer, acct`; CUSTOMER_ID: `kundennummer, customer id, customer no, kunden-nr`; TICKET_ID: `ticket, ticket-id`; INCIDENT_ID: `incident, inc`; INVOICE_ID: `rechnung, rechnungsnummer, invoice`; CONTRACT_ID: `vertrag, vertragsnummer, contract`; EMPLOYEE_ID: `mitarbeiter-nr, personalnummer, employee id`; USER_ID: `user id, userid, benutzer-id`; INSURANCE_ID: `versicherungsnummer, policy no, police`; PASSPORT_ID: `reisepass, passport`; NATIONAL_ID: `personalausweis, ausweisnummer, national id`; DRIVER_LICENSE_ID: `führerschein, driver license`; TRANSACTION_ID: `transaktion, transaction, txn`; PAYMENT_REFERENCE: `verwendungszweck, payment reference`; TENANT_ID: `tenant id, mandant`; ORGANIZATION_ID: `org id, organization id`; SUBSCRIPTION_ID: `subscription`; FINDING_ID: `finding`; CASE_ID: `case, fall, aktenzeichen`; BANK_ACCOUNT: `kontonummer, account number` |
  | NAMESPACE, POD_NAME, CONTAINER_NAME, CLUSTER_NAME, DATABASE_NAME, DATABASE_HOST, DATABASE_USER, TENANT_NAME, PROJECT_NAME, ENVIRONMENT_NAME, GATEWAY_NAME, WAF_NAME, LOAD_BALANCER_NAME, REPOSITORY_NAME, BRANCH_NAME, APPLICATION_NAME, SERVICE_NAME, MICROSERVICE_NAME, DEPARTMENT, JOB_TITLE, EMPLOYER, ROOM, BUILDING | – | – | `namespace, ns`; `pod, pod/`; `container`; `cluster`; `database, db name`; `db host, database host`; `db user, database user`; `tenant`; `project, projekt`; `environment, env, umgebung`; `gateway`; `waf`; `load balancer, lb`; `repo, repository`; `branch`; `application, app`; `service`; `microservice`; `abteilung, department`; `position, job title, rolle`; `arbeitgeber, employer`; `raum, room`; `gebäude, building` |

  Classes without patterns/context words (e.g. `PERSON_ALIAS`, `HEALTH_INFORMATION`, `CUSTOMER_NAME`, `INTERNAL_DOMAIN`) are still registered; they are fed by dictionaries, structured parsers or the context stage. The `(context required)` marker is expressed in YAML as `context_required: true` on the class (add this optional boolean field to `DataClass`, default `False`).
- [ ] **Step 5: `config.py`** per Shared interfaces. Merge rule for `classes`: user entries override field-by-field; a user class with unknown `category` → `ConfigError`; `policy: ignore` allowed only via user config. `dictionaries.files` values are paths relative to the config file; lines stripped, blanks/`#` ignored. Default vault/audit paths use `Path.home()`. Tests: defaults load with 136 (exact count of the task statement's list) classes; SECRET classes are `redact`+`restore=False`; user YAML adds class `PROJECT_CODE` with pattern → in registry; override `API_KEY: {policy: tokenize}` applied; unknown top-level key → `ConfigError`; env `PGW_VAULT_DB=/tmp/x.db` applied; `hash()` stable across two loads.
- [ ] **Step 6: `detect/base.py`** with the `Stage` protocol; `detect/__init__.py` empty. `privacy_gateway/__init__.py` exports the model types and exceptions (Gateway export added in Task 8).
- [ ] **Step 7:** `uv run ruff check . && uv run pytest -q` green. Commit `feat: scaffold package with data model, class registry and config`.

---

### Task 2: Validators and pattern stage

**Files:** Create `privacy_gateway/detect/validators.py`, `privacy_gateway/detect/patterns.py`, `tests/unit/test_validators.py`, `tests/unit/test_patterns.py`.

**Consumes:** `DataClass.patterns/validator/context_words/context_required`, `Finding`, `Span`, `Config`.
**Produces:**
```python
VALIDATORS: dict[str, Callable[[str], bool]]   # keys: luhn, iban, bic, ip, mac, vin, phone, date, tax_id, ssn
def luhn_valid(s: str) -> bool; def iban_valid(s) -> bool; def bic_valid(s) -> bool
def ip_scope(s: str) -> str | None            # "private" | "public" | None(invalid); loopback/link-local -> "private"
def mac_valid(s) -> bool; def vin_valid(s) -> bool; def phone_valid(s) -> bool  # 7..15 digits
def date_valid(s) -> bool                     # real calendar date, DD.MM.YYYY / DD/MM/YYYY / YYYY-MM-DD, years 1900-2100
def tax_id_valid(s) -> bool                   # DE Steuer-ID check digit (11 digits) or EU VAT shape
def ssn_valid(s) -> bool                      # DE SV-Nummer check digit or US SSN shape
class PatternStage:  name = "pattern"
```
Behaviour: for each enabled class with `patterns`, run each regex (compile once, `re.MULTILINE`); if the regex has group 1, the finding span is group 1, else group 0. If `validator` set, drop candidates failing it. Confidence 0.9 without validator, 0.95 with validator; +0.03 (cap 0.99) when a `context_words` entry occurs case-insensitively within 40 chars before the match. Classes with `context_required` need a context word within 40 chars before the match or are skipped. `IP_ADDRESS` findings get `attributes["scope"]` and a second finding `PRIVATE_IP`/`PUBLIC_IP` over the same span.

- [ ] Tests (write first, fail first): Luhn `4111111111111111` valid, `4111111111111112` invalid, spaces/dashes ignored; IBAN `DE89 3704 0044 0532 0130 00` valid, `DE89370400440532013001` (wrong length) invalid, `GB82WEST12345698765432` valid, wrong check digits invalid; `ip_scope("10.1.2.3")=="private"`, `"8.8.8.8"=="public"`, `"999.1.1.1" is None`, `"::1"=="private"`, `"2001:db8::1"=="public"`; MAC `00:1A:2B:3C:4D:5E` valid; VIN `1HGCM82633A004352` valid, `1HGCM82633A004353` invalid; date `31.02.2020` invalid, `29.02.2020` valid; DE Steuer-ID `86095742719` valid, `86095742710` invalid; DE SV-Nummer `65 170839 J 003` valid; phone `+49 211 1234567` valid, `12345` invalid.
- [ ] PatternStage tests: `"Karte: 4111 1111 1111 1111"` → CREDIT_CARD ≥ 0.95; `"Nummer 4111 1111 1111 1112"` → none; `"IBAN DE89370400440532013000"` → IBAN; `"host 10.0.0.5 and 8.8.8.8"` → IP_ADDRESS×2 with scope attrs + PRIVATE_IP + PUBLIC_IP; `"CVV 123"` → CVV, `"Seite 123"` → none; `"password: hunter22"` → PASSWORD span == `hunter22`; `"Authorization: Bearer abcdefghijklmnop.qrst"` → ACCESS_TOKEN; `"AKIAIOSFODNN7EXAMPLE"` → AWS_ACCESS_KEY; JWT sample → JWT; `"geboren am 12.03.1980"` → DATE_OF_BIRTH, `"am 12.03.1980"` → none; `repr(finding)` never contains the matched value.
- [ ] Commit `feat: add validators and pattern detection stage`.

---

### Task 3: Structured parsers

**Files:** Create `privacy_gateway/detect/structured.py`, `tests/unit/test_structured.py`.

**Produces:** `class StructuredStage: name = "structured"`. Emits parent findings with `children`:
- URL (`https?://`, `wss?://`, `ftp://` up to whitespace or `>"')`): parent `URL`, or `INTERNAL_URL` if host ∈ `config.dictionaries.get("INTERNAL_DOMAIN", [])`, has no dot, or ends with `.local/.internal/.corp/.lan`. Children: host → `HOSTNAME` (no dot) / `FQDN` (dotted) / `INTERNAL_DOMAIN` / `CUSTOMER_DOMAIN` (dictionary match wins); path → `API_PATH` if it matches `^/(api|v\d+|rest|graphql)(/|$)`; each query param → `QUERY_PARAMETER` (name) and `QUERY_VALUE` (value); `user:pass@` → `PERSON_USERNAME` + `PASSWORD`; query keys `sig, signature, X-Amz-Signature, X-Goog-Signature` → parent reclassified `SIGNED_URL`; `sv=` together with `sig=` → `SAS_TOKEN`; query keys `token, access_token, api_key, apikey, key` → child `ACCESS_TOKEN` (`api_key/apikey/key` → `API_KEY`). Confidence 0.98.
- Email `[\w.+-]+@[\w-]+(\.[\w-]+)+`: parent `EMAIL`, children `PERSON_USERNAME` (local part) and `DOMAIN` / `CUSTOMER_DOMAIN` / `INTERNAL_DOMAIN` (via dictionaries). Confidence 0.98.
- JWT: three base64url parts where part 1 decodes to JSON containing `"alg"` → `JWT` 0.99.
- PEM: `-----BEGIN ([A-Z ]*)PRIVATE KEY-----[\s\S]*?-----END \1PRIVATE KEY-----` → `SSH_PRIVATE_KEY` if label contains `OPENSSH`, `TLS_PRIVATE_KEY` if `RSA`/`EC`, else `PRIVATE_KEY`.
- Connection strings: `(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://…` → parent `DATABASE_CONNECTION_STRING`, children `DATABASE_USER`, `PASSWORD`, `DATABASE_HOST`, `DATABASE_NAME` (first path segment); ADO style `Server=…;Database=…;User Id=…;Password=…` (case-insensitive keys) → same parent/children.
- HTTP headers (line-based `^([A-Za-z-]+):\s*(.+)$`): `Authorization` → child `ACCESS_TOKEN` over the credential after `Bearer`/`Basic`; `Cookie`/`Set-Cookie` → parent `COOKIE`, per pair child `COOKIE_VALUE`, pairs named `sessionid|JSESSIONID|PHPSESSID|connect.sid|sid` → `SESSION_COOKIE`, `auth|token|access_token|id_token` → `AUTH_COOKIE`, `csrf|xsrf|_csrf` → `CSRF_TOKEN`; any `X-*` header except `X-Forwarded-*`, `X-Request-Id` → parent `CUSTOM_HEADER` with child `HEADER_VALUE`.
- Kubernetes `kind: Secret` manifests: each `key: base64value` under `data:` → `KUBERNETES_SECRET` over the value.

- [ ] Tests: `https://api.corp.example.com/v1/users?id=42&token=abcdefghijklmnop` → URL with children FQDN, API_PATH (`/v1/users`), QUERY_PARAMETER×2, QUERY_VALUE×2, ACCESS_TOKEN; `https://alice:s3cret@db.internal:5432/app` → INTERNAL_URL, children PERSON_USERNAME `alice`, PASSWORD `s3cret`; blob URL with `sv=…&sig=…` → SAS_TOKEN; `anna.mueller@kunde.de` with dictionary `CUSTOMER_DOMAIN: [kunde.de]` → EMAIL with PERSON_USERNAME + CUSTOMER_DOMAIN children; valid JWT → JWT, `a.b.c` → none; PEM RSA → TLS_PRIVATE_KEY spanning both markers; `postgres://app:pw@10.0.0.7:5432/orders` → DATABASE_CONNECTION_STRING + 4 children; `Cookie: sessionid=abc123def; theme=dark` → COOKIE with SESSION_COOKIE child over `abc123def`; `X-Tenant-Key: 9f8e7d` → CUSTOM_HEADER + HEADER_VALUE; `Authorization: Basic dXNlcjpwYXNz` → ACCESS_TOKEN; k8s secret manifest → KUBERNETES_SECRET per data value.
- [ ] Commit `feat: add structured parsers stage`.

---

### Task 4: Dictionaries and context rules

**Files:** Create `privacy_gateway/detect/dictionaries.py`, `privacy_gateway/detect/context.py`, `privacy_gateway/data/first_names_de_en.txt` (≥ 300 DE/EN first names), `privacy_gateway/data/last_names_de_en.txt` (≥ 300), `privacy_gateway/data/cities_de_en.txt` (≥ 200 DE/AT/CH/UK/US cities), `privacy_gateway/data/medical_terms_de_en.txt` (≥ 150 diagnoses/medications/ICD-10 codes), `privacy_gateway/data/salutations.yaml`, `tests/unit/test_dictionaries.py`, `tests/unit/test_context.py`.

**Produces:**
```python
class DictionaryStage:  name = "dictionary"
class ContextStage:     name = "context"
class TrieMatcher:
    def __init__(self, terms: Iterable[tuple[str, str]], *, case_insensitive: bool = True)  # (term, class)
    def find(self, text: str) -> list[tuple[Span, str]]   # whole-word, longest match, no overlaps
SALUTATIONS: dict[str, str | None]   # word -> "female"/"male"/None (neutral: Dr., Prof., Mx)
```
DictionaryStage: configured lists (`config.dictionaries[class]`) → findings 0.95. Bundled lists: first names → `PERSON_FIRST_NAME`, last names → `PERSON_LAST_NAME`, cities → `CITY`, medical terms → `MEDICAL_INFORMATION`; bundled hits get confidence 0.3 and `attributes["bundled"]="true"`, medical terms 0.8. Whole words only, Unicode-aware; configured lists case-insensitive; bundled names must start with an uppercase letter in the text.

ContextStage rules (deterministic, DE+EN):
1. **Salutation**: `(?:Sehr geehrte[r]?|Dear|Hallo|Hi|Liebe[r]?)?\s*\b(Frau|Herr|Herrn|Mrs\.?|Mr\.?|Ms\.?|Mx\.?)\s+((?:(?:Dr|Prof|Dipl\.-Ing)\.\s+)*)([A-ZÄÖÜ][\wäöüß-]+(?:\s+[A-ZÄÖÜ][\wäöüß-]+)?)` → `SALUTATION` over the salutation word, `ACADEMIC_TITLE` over titles, and `PERSON_LAST_NAME` (one token) or `PERSON_FULL_NAME` (two tokens) over the name. Attributes: `gender` from `SALUTATIONS` only if `config.person.record_gender_from_salutation`; `source="salutation"`. Confidence 0.95.
2. **First + last name pairs**: bundled `PERSON_FIRST_NAME` followed by single space and bundled `PERSON_LAST_NAME` → `PERSON_FULL_NAME` over both, 0.85, no gender.
3. **Key/value markers**: for every enabled class with `context_words` and **empty** `patterns`: `(?i)\b{word}\b\s*(?:[:#=]|-?\s*nr\.?|no\.?|number|nummer)?\s*([A-Za-z0-9][A-Za-z0-9_\-./]{2,})` → finding over group 1, 0.85. Skip when group 1 is a context word or a stop word (`der, die, das, the, and, und, of, von, for, für, is, ist, am, im, in, on`).
4. **Job/department**: `(?i)\b(?:Abteilung|Department|Dept\.?)\s*[:=]?\s*([A-ZÄÖÜ][\w&/ -]{2,40})` → `DEPARTMENT`; `\b(CEO|CTO|CFO|CISO|Geschäftsführer(?:in)?|Leiter(?:in)?|Head of [A-Z][a-z]+|Senior [A-Z][a-z]+ Engineer|Product Owner|Projektleiter(?:in)?)\b` → `JOB_TITLE`, 0.8.
5. **Address grammar**: `([A-ZÄÖÜ][\wäöüß.-]+(?:straße|strasse|str\.|weg|allee|platz|gasse|ring|damm|ufer|Street|St\.|Road|Rd\.|Avenue|Ave\.|Lane))\s+(\d{1,4}[a-zA-Z]?)\s*,?\s*(\d{4,5})\s+([A-ZÄÖÜ][\wäöüß -]+)` → `ADDRESS` with children `STREET`, `HOUSE_NUMBER`, `POSTAL_CODE`, `CITY`, 0.9. Standalone `(?i)\b(?:PLZ|Postleitzahl|zip)\s*[:=]?\s*(\d{4,5})` → `POSTAL_CODE`.
6. **Place of birth**: `(?i)\b(?:geboren in|geb\. in|born in|Geburtsort[:=]?)\s+([A-ZÄÖÜ][\wäöüß -]+)` → `PLACE_OF_BIRTH`.
7. **Health sentence**: a bundled `MEDICAL_INFORMATION` term with a marker within 60 chars before it (`Diagnose, diagnosis, diagnosed, leidet an, suffers from, Befund, Therapie, treatment, Medikation, medication`) → new `HEALTH_INFORMATION` finding 0.95 over the enclosing sentence fragment (previous `.`/newline to next `.`/newline).
8. **Initials**: `\b([A-ZÄÖÜ]\.\s?[A-ZÄÖÜ]\.)` → `PERSON_INITIALS` 0.4 (correlation promotes on match).
9. **Handles**: `(?<![\w@])@[A-Za-z0-9_]{3,30}\b` → `SOCIAL_MEDIA_HANDLE` 0.8; `(?i)\b(?:telegram|signal|whatsapp|teams|slack)[:\s]+(@?[A-Za-z0-9_.+-]{3,})` → `MESSENGER_ID`; `sip:[^\s>]+` → `SIP_ADDRESS` 0.95.
10. **Countries**: `COUNTRIES` constant in `context.py` (≥ 60 DE/EN names) → `COUNTRY` 0.8.

- [ ] Tests (dictionaries): longest match (`"New York City"` beats `"New York"`), whole-word (`"Bonn"` not in `"Bonnie"`), configured `CUSTOMER_NAME: [Contoso GmbH]` → 0.95; bundled `"Anna"` → PERSON_FIRST_NAME 0.3 with `bundled`; `"anna"` → none; `"Diabetes"` → MEDICAL_INFORMATION 0.8; every bundled data file loads with ≥ required line count.
- [ ] Tests (context): `"Sehr geehrte Frau Müller,"` → SALUTATION + PERSON_LAST_NAME `gender=female`; `"Herrn Dr. Schmidt"` → ACADEMIC_TITLE + PERSON_LAST_NAME `gender=male`; `"Dear Mx Taylor"` → no gender; `record_gender_from_salutation=False` → no gender; **`test_first_name_alone_never_yields_gender`**: `"Anna"` and `"Anna Müller"` carry no `gender`; `"Konto 4711"` → ACCOUNT_ID over `4711`; `"account number: 4711"` → ACCOUNT_ID; `"Ticket INC-2024-0042"` → TICKET_ID; `"namespace: payments-prod"` → NAMESPACE; `"Musterstraße 12, 40210 Düsseldorf"` → ADDRESS with 4 children; `"Diagnose: Diabetes Typ 2."` → HEALTH_INFORMATION over the sentence; `"@max_muster"` → SOCIAL_MEDIA_HANDLE, `"max@example.com"` → none; `"geboren in Köln"` → PLACE_OF_BIRTH; `"Abteilung: IT-Security"` → DEPARTMENT; `"Deutschland"` → COUNTRY.
- [ ] Commit `feat: add dictionary and context detection stages`.

---

### Task 5: Entity correlation and overlap resolution

**Files:** Create `privacy_gateway/detect/correlation.py`, `privacy_gateway/detect/spans.py`, `tests/unit/test_correlation.py`, `tests/unit/test_spans.py`.

**Produces:** `correlate(text, findings, config)` and `resolve_overlaps(findings, registry)`.

`correlate` (input may overlap; returns the same findings with `entity_id` set and confidences promoted, plus entities):
1. Key: `text[span]` → NFKC, casefold, whitespace collapsed; for PHONE/MOBILE_PHONE/FAX/IBAN/CREDIT_CARD/BANK_ACCOUNT digits-only.
2. Same key + same class → same entity. Ids `e1, e2, …` in order of first span.
3. Persons: entities from `PERSON_FULL_NAME`, `PERSON_LAST_NAME`, `PERSON_FIRST_NAME` with confidence ≥ 0.5. A full name "Anna Müller" registers last `müller`, first `anna`. A `PERSON_LAST_NAME` finding (any confidence) whose key matches exactly one entity's last name → same entity, confidence → 0.9. `PERSON_INITIALS` matching exactly one entity's initials → same entity, 0.9. Bundled first-name finding equal to an entity's first name → same entity, 0.9.
4. Gender: propagates within the entity; conflicting values → removed + `attributes["gender_conflict"]="true"`.
5. Email link: an `EMAIL` finding whose `PERSON_USERNAME` child contains an entity's last name → `attributes["linked_entity"]=entity.id` on the email finding.
6. Low-confidence findings are **not** dropped here (Pipeline filters by `min_confidence`).

`resolve_overlaps`: sort by `(start, -len)`; keep a finding when it does not overlap the last kept; on overlap keep higher `registry.priority_for(class)`, then longer span, then earlier stage order (`structured < pattern < dictionary < context < correlation`), then earlier start. Output non-overlapping, sorted by start; kept structured parents keep their `children`.

- [ ] Tests (correlation): findings for `"Frau Anna Müller … Müller … A. M."` → one entity with 3 spans, `gender=female`, bare `Müller` promoted to 0.9; `Müller`/`Schmidt` → two entities; `Frau Müller` then `Herr Müller` → `gender_conflict`; same IBAN twice → one entity; email `a.mueller@x.de` → `linked_entity`; ambiguous bare last name with two entities → unlinked.
- [ ] Tests (spans): CREDIT_CARD vs PHONE same span → CREDIT_CARD; URL containing EMAIL → URL kept; adjacent spans both kept; equal priority → longer wins; equal priority+length → structured beats pattern; output sorted.
- [ ] Commit `feat: add entity correlation and overlap resolution`.

---

### Task 6: Vault and audit log

**Files:** Create `privacy_gateway/vault.py`, `privacy_gateway/audit.py`, `tests/unit/test_vault.py`, `tests/unit/test_audit.py`.

**Produces:** `Vault`, `load_or_create_key`, `AuditLog`.

Vault: schema from spec §8, `PRAGMA journal_mode=WAL`, foreign keys on. `AESGCM(key)`, 12-byte random nonce per row; AAD `f"{session_id}|{token}".encode()`; surface forms encrypted individually with AAD `f"{session_id}|{token}|{ordinal}"`. `load_or_create_key`: missing → `secrets.token_bytes(32)` written via `os.open(path, O_WRONLY|O_CREAT|O_EXCL, 0o600)` (parent dirs 0o700); present → `VaultError` when `st_mode & 0o077 != 0` or length ≠ 32. Wrong key → `VaultError("decryption failed")`. `store` on unknown session → `VaultError`. `created_at = datetime.now(timezone.utc).isoformat()`.

AuditLog: JSON Lines `{"ts": ISO-8601 UTC, "event": ..., ...}`; append per write; parent dir 0o700, file 0o600. `path=None` → no-op.

- [ ] Tests (vault): round-trip with umlauts/emoji; ciphertext column lacks plaintext bytes (raw sqlite query); different key → `VaultError`; swapping two rows' ciphertext via SQL → `VaultError`; key file 0o600; key file 0o644 → `VaultError`; `purge` removes mappings + surface forms; `purge_older_than(0)` after backdating `created_at` → count; `list_sessions` token_count; exception messages never contain the value.
- [ ] Tests (audit): lines parse as JSON with expected keys; `AuditLog(None)` writes nothing; file 0o600; sentinel string passed as `session_id` appears, but a sentinel never passed does not (sanity).
- [ ] Commit `feat: add encrypted vault and audit log`.

---

### Task 7: Pseudonymizer, leakage validation, restoration

**Files:** Create `privacy_gateway/pseudonymize.py`, `privacy_gateway/leakage.py`, `privacy_gateway/restore.py`, `tests/unit/test_pseudonymize.py`, `tests/unit/test_leakage.py`, `tests/unit/test_restore.py`. Tests build `DetectionReport` objects by hand.

`pseudonymize_text`:
- Iterate `report.findings`. `IGNORE` → unchanged. `REDACT` → `<{CLASS}_REDACTED>`, not in assignments. `TOKENIZE` → key = `entity_id` or `(data_class, normalized value)`; first occurrence allocates `<{LABEL}_{NNN}>`, LABEL = `registry.label_for(cls)` plus `_FEMALE`/`_MALE` for label `PERSON` when the entity/finding attribute `gender` is set; counters per full label per call from 1. Same key → same token.
- Rewrite right-to-left. `assignments[i].spans` in left-to-right order. Structured parents replaced as a whole.

`check_leakage(text, entries, scan, registry)`:
1. `scan(text)`; findings with policy ≠ IGNORE → `Leak("residual_finding", …)`; findings entirely inside a `<…>` token are ignored.
2. For each `entry.value` and each surface form: exact; casefold; whitespace-collapsed; digits-only when ≥ 6 digits (search the digits-only projection and map back). Values < 4 chars: exact whole-word match only. Hit → `Leak("original_value", …)`.
3. Tokens `<([A-Z][A-Z_]*?)_(\d{3})>` not in `entries` → `Leak("unknown_token", "", …)`; `_REDACTED>` tokens are fine.
4. Any leak → `LeakageError(leaks)`.

`restore_text(text, entries, mode)`:
- strict: `<([A-Z][A-Z_]*?)_(\d{3})>`; unknown → `RestoreError` (token name only).
- lenient: also `[`"']?([A-Z][A-Z_]*?_\d{3})[`"']?` without brackets, case-insensitive; unknown left in place and listed (deduplicated).
- Occurrence n → `surface_forms[n-1]` if present else `value`. `<X_REDACTED>` untouched.

- [ ] Tests (pseudonymize): spec example with SALUTATION policy `ignore` → `"Sehr geehrte Frau <PERSON_FEMALE_001>,\n\nbitte kontaktieren Sie Herrn <PERSON_MALE_002> regarding account <ACCOUNT_ID_001>."`; default config → `<SALUTATION_001>` etc.; same entity twice → same token; two persons → 001/002; REDACT → `<JWT_REDACTED>` no assignment; IGNORE unchanged; three findings → exact expected text; spans in occurrence order.
- [ ] Tests (leakage): original IBAN in output → `original_value`; `4711` stored and present → leak; `"Anna Müller"` present as `"anna  müller"` → leak; scan stub with CREDIT_CARD finding → `residual_finding`; finding inside `<ACCOUNT_ID_001>` → none; `<FOO_009>` → `unknown_token`; clean → None; `str(error)` has no value.
- [ ] Tests (restore): strict round-trip with surface forms `["Müller", "MÜLLER"]` in order; third occurrence → value; strict unknown → `RestoreError`; lenient unknown → kept + listed; lenient `PERSON_FEMALE_001` and `` `<PERSON_FEMALE_001>` `` → restored; `<JWT_REDACTED>` untouched; `restored_count`.
- [ ] Commit `feat: add pseudonymizer, leakage validation and restoration`.

---

### Task 8: Pipeline, Gateway API, CLI, integration tests

**Files:** Modify `privacy_gateway/detect/__init__.py`, `privacy_gateway/__init__.py`; create `privacy_gateway/api.py`, `privacy_gateway/cli.py`, `tests/fixtures/customer_letter_de.txt`, `tests/fixtures/incident_ticket_en.txt`, `tests/fixtures/k8s_log_excerpt.txt`, `tests/fixtures/http_request_dump.txt`, `tests/fixtures/invoice_de.txt`, `tests/integration/test_roundtrip.py`, `tests/integration/test_fail_closed.py`, `tests/integration/test_cli.py`, `tests/integration/test_no_network.py`, `tests/integration/test_config_extension.py`.

`Pipeline.run`: `StructuredStage, PatternStage, DictionaryStage, ContextStage` in order, each receiving accumulated findings; `correlate`; drop `confidence < config.min_confidence`; `resolve_overlaps`; `stage_stats`. Exceptions propagate.

`Gateway`: see spec §13. `pseudonymize`: sha256 → `pipeline.run` → `vault.create_session` → `pseudonymize_text` → `vault.store` per assignment (`value = text[spans[0]]`, `surface_forms = [text[s] for s in spans]`) → `entries = vault.load` → `check_leakage(pt.text, entries, pipeline.run, registry)`; on `LeakageError`: purge session, audit `leakage="failed"`, re-raise; on any other exception: purge, `audit.error`, re-raise; success: audit `ok`, return result with `SummaryReport`. `restore`: `vault.load` → `restore_text` → audit. `scan`: `pipeline.run`.

`cli.main`: argparse subcommands from spec §12; input FILE or stdin; `pseudonymize` → stdout/`--out`, `session: <id>` to stderr, `--session-file`, `--report json|text` to stderr; `LeakageError` → `fail-closed: N potential leak(s) detected (classes: …)` exit 2; `validate` exit 2 on ≥ 1 finding with per-class counts; `classes` table; `vault list|purge`; other `PrivacyGatewayError` → exit 1 `error: <message>`.

Fixtures: synthetic documents, ≥ 15 lines each. (1) DE letter: Frau/Herr salutations, full names, IBAN, `Konto` number, address, phone, email, `geboren` date, customer number. (2) EN incident ticket: ticket id, incident id, hostnames, private+public IPs, URL with query token, AWS key, JWT, `Mr` person. (3) k8s log: namespace/pod/container markers, connection string, `kind: Secret` manifest. (4) HTTP dump: request line with API path, `Authorization: Bearer`, Cookie with sessionid + csrf, X-custom header, JSON body with `password` and `api_key`. (5) DE invoice: invoice number, VAT id, IBAN/BIC, credit card with `Karte`, address, customer id, payment reference.

- [ ] `test_roundtrip.py` (vault/key/audit under `tmp_path` via env): per fixture: no vault value in `res.text`; expected classes present in `res.report.counts` (parametrized); `gw.restore(res.text, sid).text == text`; simulated LLM answer reordering tokens and dropping brackets → lenient restore, `unknown_tokens == []`; two fixtures → independent sessions both starting at `_001`.
- [ ] `test_fail_closed.py`: monkeypatch `pseudonymize_text` to return the input unchanged → `LeakageError`, no session in vault, audit `leakage: "failed"`; stage raising `RuntimeError` → propagates, no session, audit `error`; `cli.main(["pseudonymize", fixture])` under the same monkeypatch → returns 2; config `IBAN: {policy: ignore}` → IBAN kept and no `LeakageError`.
- [ ] `test_cli.py` (subprocess `python -m privacy_gateway.cli`, env → `tmp_path`): `pseudonymize` fixture → exit 0, no IBAN in stdout, `session:` in stderr; `restore --session` → byte-equal; `validate` fixture → 2; `validate` on `"Hello world."` → 0; `classes` 136 (exact count of the task statement's list) rows; `vault list` shows session; `vault purge --session` → later `restore` exits 1.
- [ ] `test_no_network.py`: `ast`-walk `privacy_gateway/**/*.py`; no import of `socket, http, urllib.request, urllib3, requests, httpx, aiohttp, ssl, ftplib, smtplib`.
- [ ] `test_config_extension.py`: `PROJECT_CODE` with pattern `\bPRJ-\d{5}\b` → `<PROJECT_CODE_001>` and restored; `API_KEY: {policy: tokenize}` → restored; `dictionaries: {CUSTOMER_NAME: [Contoso GmbH]}` → `<CUSTOMER_NAME_001>`; `dictionaries.files` works.
- [ ] `uv run ruff check . && uv run pytest -q` green. Commit `feat: add detection pipeline, Gateway API and pgw CLI with integration tests`.

---

### Task 9: Documentation and final verification

**Files:** Create `README.md`; modify `CLAUDE.md` (replace the stub).

- [ ] `README.md`: purpose + pipeline diagram (spec §1), install (`uv sync`), CLI examples per subcommand, library example (spec §13), config example (spec §5), security model (fail closed, key file 0600, never logged), limitations (spec §15).
- [ ] `CLAUDE.md`: `# CLAUDE.md` + standard sentence, commands (`uv sync`, `uv run pytest -q`, single test example, `uv run ruff check .`, `uv run pgw …`), architecture summary (stage order, shared-interface contract, fail-closed, no-network, gender rule), pointers to spec and plan.
- [ ] Verify: tests green, ruff clean, `uv run pgw pseudonymize tests/fixtures/customer_letter_de.txt` then restore → `diff` empty. Commit `docs: add README and CLAUDE.md`.
