# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.2.0 – unreleased

### Security
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
