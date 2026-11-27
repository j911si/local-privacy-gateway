# Roadmap

Everything on this page is planned and not implemented, unless a line says otherwise. There are
no dates. What exists today is described in the [README](README.md) and in the
[coverage register](docs/COVERAGE.md).

## Strategic focus: international detection

Detection today covers global formats (IBAN, payment cards, e-mail, IP addresses, phone numbers
with a country code, cloud keys, labelled secrets) and German and English rules for identifiers,
names, addresses and labels. The goal is to make the gateway useful in any country and language
while keeping the detection engine small, deterministic and local.

### What stays as it is

- The own rule-based engine stays: patterns, validators, context rules, dictionaries, a fixed
  stage order and a fail-closed leak check. No detection step calls a network service, paid or
  free.
- Every rule runs on every text. A pack adds rules; it never switches others off, and an unknown
  or mixed language does not disable a detector.

### Country packs and language packs

A country pack holds the identifiers of one country: patterns, normalization, a check-digit
validator, label words and test cases. A language pack holds the vocabulary of one language:
salutations, person labels, address grammar, context words and name lists. Several packs can be
active at once.

A recognizer in a pack will describe:

| Field | Purpose |
|---|---|
| `entity_type` | class it produces, for example `NATIONAL_ID` |
| `countries`, `languages` | where it applies; informational, never used to disable it |
| `patterns` | candidate shapes, each with a linear-time proof (see below) |
| `normalization` | separators and case folded before validation, with spans mapped back to the original text |
| `validator` | name of a check-digit function from a reviewed registry |
| `context_words`, `context_required` | label words and whether one is needed |
| `confidence` | score for a match that passes validation |
| `false_positive_controls` | negative patterns and deny lists, for example version numbers or order numbers |
| `tests` | positive and negative cases with synthetic values |
| `references` | the official specification of the format |

Today a user YAML layer can already add patterns, context words and dictionaries per class. What
is missing: the country and language fields, a validator registry that packs can use without
changing core code, per-recognizer confidence and normalization, and the test and reference
fields. The context grammar for salutations and addresses is still German and English code in
`detect/context.py`.

### Libraries under evaluation

Nothing here is a dependency yet. Each candidate is checked for license, size, offline operation
and runtime on large requests before it is adopted.

| Library | Intended use | Status |
|---|---|---|
| python-stdnum | check digits for national identifiers, tax and VAT numbers | first candidate; LGPL license to be checked against the MIT project |
| phonenumbers (libphonenumber) | phone validation and national lengths, replacing the built-in table | candidate; used as a validator for candidates, not as a scanner |
| Microsoft Presidio | design reference for the recognizer interface | reference only, not a dependency |
| spaCy, GLiNER | optional local name recognition | later and optional; must run offline and must not block the proxy on large requests |

### Security requirements for new recognizers

These are binding for contributed recognizers. [CONTRIBUTING.md](CONTRIBUTING.md#contributing-a-recognizer)
has the checklist.

- **Bounded runtime.** Patterns must not backtrack super-linearly. A fast run on a long input does
  not prove linearity; a pattern needs a construction argument (possessive quantifiers, no nested
  or overlapping repetition) or a linear finder, and a scaling test on crafted worst-case input.
  Detection is planned to get an overall time budget per request; today only the rescan of the
  outgoing body has one (`PGW_PROXY_RESCAN_BUDGET`).
- **No foreign code at runtime.** Packs are data. A validator is code and goes through review into
  the registry like any other change; a pack cannot load or execute code.
- **No network.** No recognizer, validator or pack opens a connection. The existing static test
  for network imports in the core applies.
- **Unicode.** Normalization happens before matching, and every span maps back to the original
  text, so a replacement never cuts or misses characters.
- **Tests.** Positive cases, negative cases with near-misses (wrong check digit, similar formats),
  and a false-positive run against code, logs and agent traffic.
- **References.** Each format links its official specification.
- **License.** Contributed data, such as name lists, and any library must have a license compatible
  with MIT.

### Coverage register from evidence

[docs/COVERAGE.md](docs/COVERAGE.md) is maintained by hand for 0.2.0. The plan is to generate it
from recognizer metadata and test results: per entity type, country and language, the number of
test cases, and precision, recall and false-positive rate measured separately on synthetic data.
A row appears only when tests back it.

### Order

1. Recognizer interface and validator registry inside the existing engine, no new dependency.
2. Generated coverage register and the synthetic test corpus with per-cell metrics.
3. First country packs with python-stdnum validators, after the license check.
4. Phone validation with phonenumbers.
5. Language packs for labels, salutations and addresses, open to contributors.
6. Optional local name recognition layer, evaluated separately.

## Other planned work

- Windows support in CI.
- TLS between clients and a proxy on a private network, and per-client session separation.
- Detection inside the proxy off the event loop, so one large request does not hold other
  sessions.

## Vision

A gateway that works the same in any country, is provider independent beyond the Anthropic API
the proxy speaks today, and whose coverage anyone can read off a generated register.
