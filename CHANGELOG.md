# Changelog

All notable changes to this project are documented in this file. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
