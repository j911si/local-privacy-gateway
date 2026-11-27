# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 – unreleased

### Security
- A run of `github_pat_` followed by a non-ASCII letter made the GitHub token rule quadratic
  (171 KiB blocked the proxy for 22 s), and long runs of combining marks made normalization
  quadratic. Both are linear now.
- Values that went out in clear text are now replaced: Kubernetes Secret values with a comment on
  the `kind` or `data` line, quoted keys or CRLF line ends; an IBAN or card number followed by a
  word or number group (`IBAN ... EUR`, `4111 ... 1111 12/27`); a full name after an
  account-holder label when the first name is an ambiguous word (`Kontoinhaber: Max Mustermann`);
  short Basic credentials (`Basic dTpwdw==`); a ticket ID shaped like a token (`OPS_471`); a
  fullwidth IBAN; an IBAN glued to a word (`...3000USD`); a value with a variation selector
  inside (also U+E0100 and up); a card number followed by an expiry with a dot (`05.29`); a learned number written with other grouping after another number.
- The proxy scans numeric path segments and query values, so a card number there is no longer
  forwarded. Request audit lines and the access log no longer carry path segments that are not
  route words, and upstream errors are logged by status and error type without the body. The
  httpx and httpcore loggers, which wrote every upstream URL with its query at INFO, are set to
  WARNING; rate-limit headers and stream usage are logged only as numbers and timestamps.
- The digit and first-word indexes of learned values and the per-field audit counts no longer grow
  with the product of input size and learned values or fields.
- The vault runs SQLite in WAL mode with `synchronous=NORMAL` instead of an fsync on every
  commit (256 KiB with about 6,700 new values: 25 s before, 4.6 s now). A power loss or an
  operating system crash can drop the mappings of the last moments, so a placeholder issued just
  before may not be restored afterwards; nothing goes out in clear text because of it. A purge
  still commits with a full fsync, and skips the VACUUM when the session held no mapping and
  no name.
- Breaking: a finding of a sensitive class in a field the proxy forwards unchanged (`tools`,
  `metadata`, a signed block, the system prompt with `PGW_PROXY_TRANSFORM_SYSTEM=0`, an unknown
  field) now blocks the request with 422 before anything is sent. Before, it went out in clear
  text and was only logged. `PGW_PROXY_UNCHECKED_FIELDS=allow` restores the old behaviour. The
  blocking classes and the two narrow exceptions (Claude Code's `metadata.user_id` and its billing
  line) are listed in [Unchecked fields: blocking classes](README.md#unchecked-fields-blocking-classes).
- Breaking: the proxy refuses to start on a non-loopback address without `PGW_PROXY_AUTH_TOKEN` or
  `PGW_PROXY_AUTH_TOKEN_FILE`. Before, it only warned. `PGW_PROXY_ALLOW_UNAUTHENTICATED=1` is the
  explicit opt-out.
- A second copy of a redacted password, PIN, TAN or other secret in the same text or a later turn
  went out in clear text. Every copy is now redacted, and the leak check looks for it. Redacted
  values are kept in memory only, never in the vault or a log.
- `pgw pseudonymize` without `--session-key` skipped the substring sweep, so a known name glued to
  digits (`Wendland2024`) went out. Documents now take the same path as sessions.
- The substring sweep let a longer known value that failed its boundary check hide a shorter one
  (`awendland` hid `Wendland` in `AnnikaWendland`).
- A short known value glued to a token (`<PHONE_001>li`) passed the leak check. It is now replaced
  or blocked; fragments of longer words still pass.
- Only tokens the gateway issued, and redaction markers, hide a value from the leak check. Before,
  any token-shaped text did.
- Two processes writing the same session into one `vault.db` could give two values the same
  token, so a restore showed the wrong name. Checking and writing a token now happen in one
  `BEGIN IMMEDIATE` transaction; a collision fails closed and reloads the session.
- Detection: IBAN, card and tax numbers next to `_` and in file names, IBAN behind lower-case
  letters, card numbers behind a card word, Kubernetes `stringData`, passwords containing `\"`,
  escaped JSON up to three levels, CSRF and XSRF token spellings, indented, proxy and inline
  `Basic` credentials.
- Detection no longer takes quadratic time on crafted input: PIN/TAN/OTP, ADO connection strings,
  PEM blocks, JWT, labelled tax IDs, postal codes, salutations, the password rules, overlap
  resolution and the leak check's token test. A crafted 0.25 MiB request took 46 s before; the
  same input at 1 MiB now takes 9 s.
- Placeholders inside tool calls are no longer restored by default. Before, the proxy put the
  real value back into every `tool_use.input`, so a prompt-injected `Bash`, `WebFetch` or MCP
  call received it. Now a value is restored only where a rule in `PGW_PROXY_TOOL_RESTORE_POLICY`
  names the tool, the argument and the data class, optionally limited to a target path. The
  allowlist is empty by default. See [Tool calls: restore policy](README.md#tool-calls-restore-policy).
- The request log no longer stores a salted HMAC of each value, and the gateway no longer
  creates `audit.salt`. With the salt, short values such as a CVV or a birth date could be
  recovered by trying all candidates.
- No log line carries the session key or the vault session id any more. The request log, the
  event log (`pseudonymize`, `session_pseudonymize`, `restore`) and debug dump names use random
  audit ids that are kept in memory only.
- An unusable session key (invalid header, too long, control characters) is refused with 400
  before the path scan. Before, the path scan was skipped and the request was forwarded.
- Breaking: besides loopback the proxy binds only to explicit private addresses (RFC 1918,
  `100.64.0.0/10`, `fc00::/7`), even with an auth token. `0.0.0.0`, `[::]`, public and link-local
  addresses and host names need `PGW_PROXY_ALLOW_PUBLIC_BIND=1`. The listener has no TLS.
- Requests without a session header or a usable `metadata.user_id` shared one session per
  process, so a placeholder from one client was restored in another client's answer. Each such
  request now gets a session of its own that is purged when it ends.
- Request headers went upstream unscanned. `Cookie`, `Forwarded`, `X-Forwarded-*`, `X-Real-IP` and
  `Via` are no longer forwarded, and the values of the other headers are scanned with the blocking
  classes of unchecked fields (not `x-api-key`, `Authorization` and UUID id headers).
- The rescan skipped every `data` field next to `type: base64`. It now skips only the base64
  source of an `image` or `document` block with an allowed media type.
- JSON keys outside `tool_use.input` were not rescanned and appeared in clear in request log
  paths. They are now rescanned, and a key outside the Messages API and JSON Schema field names is
  logged as `<key>`.
- certifi 2026.11.20 (PYSEC-2026-4320, GHSA-6q48-6c7w-9gw2: compromised emSign intermediate
  CAs in the bundled CA store).

### Added
- Request log v2: one line per `/v1/messages` request in `PGW_AUDIT_LOG_DIR` (daily file, UTC,
  180-day rotation) with checked and unchecked fields, findings per field, size and sha256 of
  the sent body, the rescan result and the upstream status. It holds no values.
- Rescan of the outgoing body before it is sent. A hit in a checked field blocks the request.
  Time budget `PGW_PROXY_RESCAN_BUDGET` (default 10 s, then 503).
- Verdict `ok_with_unchecked_findings` when a field that is forwarded unchanged contains a finding.
- Tool restore policy (`PGW_PROXY_TOOL_RESTORE_POLICY`, `PGW_PROXY_TOOL_RESTORE_ON_DENY` with
  `keep_token` or `block`) and a value-free decision log `tool-restore-YYYY-MM-DD.jsonl`.
- Optional shared secret `PGW_PROXY_AUTH_TOKEN` / `PGW_PROXY_AUTH_TOKEN_FILE`.
- Detection: international phone numbers without a context word, `(+49)` and `0049` prefixes,
  compressed IPv6 with zone id and prefix length, home-directory user names (`/Users/<name>/`,
  `/home/<name>/`), names behind person labels (`Kontoinhaber`, `Customer:`, `Name:` with a
  known first name), PIN/TAN/OTP with text before the value, labelled tax IDs, birth dates in
  front of a health statement, more secret and password forms.
- Keys of `tool_use.input` are replaced and rescanned. They are never restored.
- systemd user unit example and a variant for a shared proxy on a private network.
- Documentation: design principles in the README, a [coverage register](docs/COVERAGE.md) that
  sorts the 141 configured classes by evidence, a public [roadmap](ROADMAP.md) with country and
  language packs, and rules for contributed recognizers in CONTRIBUTING.md. The `languages`
  setting is documented as having no effect.

### Changed
- Every spelling of a known value gets its own token; restoring works by value only.
- The proxy rejects non-normal paths (400), unknown or non-plain query parameters (400), bodies
  that are not a Messages object (400), write requests outside the transformed and passthrough
  paths (422) and reads with a body.
- `x-pgw-session` and `x-pgw-auth` are never forwarded upstream.
- With `PGW_PROXY_TRANSFORM_SYSTEM=0` the system prompt is logged as an unchecked field.
- Address, organization, e-mail and FQDN patterns run in linear time.

### Fixed
- Many cases where replacing and leak checking disagreed, so that legitimate requests were
  blocked or values could pass (commits `ac22819` to `6f08560`).
- Streaming restore across chunk boundaries and for quote-wrapped tokens, including a closing
  quote directly before `<`.
- Colliding redacted object keys no longer block a request.
- The test suite no longer writes to the real default audit log in your home directory.

### Removed
- Learning single first or last names from a full name (tried twice, reverted because of false
  blocks).

### Upgrading from 0.1.0
- A 0.1.0 vault stays readable. Tokens for which 0.1.0 stored several spellings restore in the
  first spelling.
- Logs written by 0.1.0 hold vault session ids and, from the proxy, session keys. Logs from
  unreleased development branches may also hold `hmac` fields next to an `audit.salt` file. The
  new version does not read or delete any of them; remove them yourself if you do not need them.
- If an agent should write real values into files, add rules to a policy file. Without one,
  every tool call gets placeholders.
- A proxy bound to a private address (Tailscale, LAN) needs a token now. Create one with
  `umask 077; openssl rand -hex 32 > ~/.config/privacy-gateway/proxy-auth-token`, set
  `PGW_PROXY_AUTH_TOKEN_FILE` in the service and send it from each client, for example with
  `ANTHROPIC_CUSTOM_HEADERS="x-pgw-auth: <token>"`.
- With a subscription login and `PGW_PROXY_TRANSFORM_SYSTEM=0`, a working directory under
  `/home/<name>/` or `/Users/<name>/` puts your user name into the unchanged system prompt, and
  every request is blocked. Either work in a directory without your user name or set
  `PGW_PROXY_UNCHECKED_FIELDS=allow`, which sends the name in clear text as 0.1.0 did.

## 0.1.0 – 2026-09-23

Initial release.

- Core gateway: staged detection (structured, pattern, dictionary, context), entity
  correlation, reversible pseudonymization and a fail-closed leakage check; `pgw`
  CLI with `pseudonymize`, `restore`, `validate`, `classes` and `vault`.
- Encrypted vault (AES-256-GCM, key file 0600) mapping tokens to values per session,
  plus an append-only audit log that records class names, spans and counts only.
- Configurable classes, patterns, validators, context words and dictionaries in
  `privacy_gateway/data/default_config.yaml`, overridable by user YAML.
- Local Anthropic API proxy (`pgw-proxy`) that pseudonymizes requests and restores
  responses, including streaming with token-safe holdback, with launchd installation
  for macOS; `thinking`, `signature`, `tools` and `metadata` stay untouched.
- Security review fixes: fail closed on undecodable proxy bodies, loopback host check,
  purged vault bytes wiped, private file modes, token conflict detection and a wider
  streaming holdback (see `docs/reviews/2026-09-23-security-review.md`).
