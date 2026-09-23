# API Proxy Mode – Design

Date: 2026-09-23
Status: approved for implementation
Builds on: `2026-09-22-local-privacy-gateway-design.md` (core gateway, v0.1)

## 1. Purpose

Run the privacy gateway as a local HTTP service between Claude Code (or any Anthropic SDK client) and `api.anthropic.com`. The client is pointed at the proxy via `ANTHROPIC_BASE_URL=http://127.0.0.1:8787`. Every request body is pseudonymized before it leaves the machine; every response (streaming or not) is restored before the client sees it. The upstream API never receives original sensitive values.

```
Claude Code ──(real values)──► proxy ──(tokens)──► api.anthropic.com
Claude Code ◄──(real values)── proxy ◄──(tokens)── api.anthropic.com
```

Deployment target for v1: the user's Mac, bound to `127.0.0.1`, started by launchd. The service has no Mac-specific code; a Worker deployment later needs only a different listen address and a systemd unit.

## 2. Decisions

| Topic | Decision |
|---|---|
| Package | New top-level package `privacy_gateway_proxy/` in the same repo. The core `privacy_gateway/` stays network-free (its guard test is unchanged). |
| Stack | `starlette` + `uvicorn` (server), `httpx` (upstream client, streaming). Installed as optional dependency group `proxy`. |
| Session model | One vault session per conversation. Key derived from the request: `metadata.user_id` if it contains `session_<uuid>` → that uuid; else header `X-PGW-Session`; else the fixed key `default`. Strategy configurable. |
| Token stability | Within a session, the same value always gets the same token (session dictionary stage + persisted counters). This keeps Claude's context consistent across turns and keeps prompt caching effective. |
| What is transformed | Request: `system` (string or text blocks), `messages[].content` (string, `text` blocks, `tool_result.content` string or text blocks, `tool_use.input` recursively for string values). Response: `content[]` `text` blocks and `tool_use.input`. |
| What is never touched | `thinking` / `redacted_thinking` blocks and their `signature` (signed by Anthropic; changing them invalidates the turn), `image` / `document` blocks, `tools` definitions, `metadata`, `model`, headers. |
| Streaming | SSE is parsed event by event. `text_delta` is restored incrementally with a holdback of any trailing fragment that could be the start of a token. `input_json_delta` is buffered per content block and emitted as one delta at `content_block_stop`. Thinking deltas pass through unchanged. |
| Fail closed | `LeakageError` during request transformation → HTTP 422 to the client with a JSON error body listing classes/positions only; nothing is sent upstream. Upstream errors are passed through unchanged. |
| Auth | The proxy forwards the client's auth headers (`x-api-key` or `Authorization: Bearer …`) untouched. It holds no credentials of its own. |
| Endpoints | `POST /v1/messages` and `POST /v1/messages/count_tokens` are transformed. Every other path is proxied verbatim (method, headers, body). |
| Audit | Existing JSONL audit log gets `proxy_request` events: session key, path, number of fields transformed, token count, leak result, streaming yes/no, duration. Never content. |

## 3. Core changes (`privacy_gateway/`)

### 3.1 Session continuation

```python
class GatewaySession:
    session_id: str
    def pseudonymize(self, text: str) -> str
    def pseudonymize_many(self, texts: list[str]) -> list[str]   # shared counters, order preserved
    def restore(self, text: str, mode: str | None = None) -> RestoreResult
    def restore_text(self, text: str) -> str                    # convenience: .restore(text).text
    def entries(self) -> Mapping[str, VaultEntry]
class Gateway:
    def session(self, key: str | None = None) -> GatewaySession   # key → vault.get_or_create_session(external_key=key)
```

- The session keeps an in-memory copy of its entries and per-label counters, loaded from the vault once; new mappings are written through.
- `pseudonymize()` on a session: run the pipeline with the session's known values injected as a first **session dictionary stage** (exact match of every stored value and surface form, confidence 1.0, `attributes["token"] = existing token`); the pseudonymizer reuses that token instead of allocating a new one; counters continue from the persisted maximum per label. Leakage check covers all entries of the session. On `LeakageError` a continued session is **not** purged (earlier turns remain valid); only the new entries of this call are rolled back.
- Vault: `sessions.external_key TEXT UNIQUE` (nullable), `get_or_create_session(external_key, config_hash) -> str`, `find_session(external_key) -> str | None`. Existing databases are migrated in place (`ALTER TABLE` guarded by a column check).
- Overlap resolution: a finding carrying `attributes["token"]` (session stage) outranks every other finding on the same span.

### 3.2 Backwards compatibility

`Gateway.pseudonymize(text)` and `Gateway.restore(text, session_id)` keep their behaviour (fresh session per call). The CLI gains `pgw pseudonymize --session-key KEY` to continue a named session.

## 4. Proxy package (`privacy_gateway_proxy/`)

```
privacy_gateway_proxy/
  __init__.py
  settings.py     # ProxySettings + env loading (PGW_PROXY_LISTEN, PGW_PROXY_UPSTREAM, PGW_PROXY_SESSION_STRATEGY)
  transform.py    # pure functions over parsed JSON bodies
  streaming.py    # SSE parser + StreamRestorer with holdback
  session_key.py  # session_key_for(headers, body, settings) -> str
  server.py       # create_app(settings, gateway, client=None) -> Starlette
  cli.py          # pgw-proxy serve | install-launchd | uninstall-launchd | status
  launchd.py      # plist rendering/loading for macOS
tests/proxy/      # unit + e2e tests with a fake upstream (httpx.MockTransport)
```

### 4.1 `transform.py`

```python
class TextSession(Protocol):
    def pseudonymize_many(self, texts: list[str]) -> list[str]: ...
    def restore_text(self, text: str) -> str: ...

def collect_request_texts(body: dict) -> list[TextRef]       # ordered list of (path, text) references
def pseudonymize_request(body: dict, sess: TextSession) -> tuple[dict, int]   # (new body, fields transformed)
def restore_response(body: dict, sess: TextSession) -> dict
def restore_json(value: Any, restore: Callable[[str], str]) -> Any             # recursive over str leaves
```

Text locations in the request (in document order): `system` (str) or `system[].text` where `type == "text"`; for each message: `content` (str) or `content[]` with `type == "text"` → `.text`; `type == "tool_result"` → `.content` (str) or `.content[].text` for text blocks; `type == "tool_use"` → every string leaf in `.input`. All other block types are copied unchanged. The functions never mutate the input body; they return a deep-copied result. `cache_control` and other sibling keys are preserved.

### 4.2 `streaming.py`

```python
class SSEEvent: event: str | None; data: str; raw: bytes
def parse_sse(buffer: bytes) -> tuple[list[SSEEvent], bytes]   # complete events + remainder
class StreamRestorer:
    def __init__(self, restore: Callable[[str], str]) -> None
    def feed(self, chunk: bytes) -> bytes
    def finish(self) -> bytes
```

Rules: track `content_block_start` types by `index`. For `text_delta` on a text block: append to the block's holdback buffer; split into `safe` + `held` where `held` is the shortest suffix matching `<[^>\s]{0,48}$` or `[A-Z][A-Z_]{1,40}(?:_\d{0,2})?$`; emit `restore(safe)` as a `text_delta` event with identical framing; keep `held`. On `content_block_stop` for that index: emit `restore(held)` if non-empty, then the stop event. For `input_json_delta`: accumulate `partial_json`; on `content_block_stop` emit one `input_json_delta` whose `partial_json` is `json.dumps(restore_json(json.loads(accumulated)))` (if the accumulated JSON does not parse, emit it restored as plain text), then the stop. Every other event (`message_start`, `ping`, `thinking_delta`, `signature_delta`, `message_delta`, `message_stop`, `error`) is forwarded byte-identical. `finish()` flushes any remaining held text and remainder bytes.

### 4.3 `server.py`

- `POST /v1/messages`, `POST /v1/messages/count_tokens`: parse JSON → `sess = gateway.session(session_key_for(...))` → `pseudonymize_request` → forward to upstream with the original headers minus hop-by-hop (`host`, `content-length`, `connection`, `transfer-encoding`; `accept-encoding` set to `identity` so SSE arrives uncompressed) → if `stream: true`: `StreamingResponse` piping upstream chunks through `StreamRestorer`; else restore the JSON body. Status code and upstream headers (minus `content-length`/`content-encoding`) are passed through.
- Responses are always restored in `lenient` mode, so a token the model altered cosmetically or invented never aborts the answer with a `RestoreError`.
- The session key must match `[A-Za-z0-9._-]{1,64}`; anything else → 400. When the proxy listens on loopback, the `Host` header must be loopback too → otherwise 403.
- Transparent proxy for everything that is not a POST to `/v1/messages*`, e.g. `GET /v1/models`. A POST to `/v1/messages*` whose body is not a plain JSON object, that carries a `Content-Encoding`, or whose path is outside the two transformed ones is rejected with 422 instead of being forwarded unchanged.
- The failed original request is only written to the debug directory when `PGW_PROXY_DEBUG_ORIGINALS` is set; `PGW_PROXY_DEBUG_DIR` alone never produces a plaintext copy.
- `LeakageError` → 422 `{"type":"error","error":{"type":"privacy_gateway_leak","message":"fail-closed: N potential leak(s) (classes: …)"}}`.
- Upstream connection errors → 502 with a short JSON error.
- The `httpx.AsyncClient` is injectable for tests; default read timeout 600 s (long generations).

### 4.4 CLI and launchd

- `pgw-proxy serve [--listen 127.0.0.1:8787] [--upstream https://api.anthropic.com] [--config PATH]`
- `pgw-proxy install-launchd` writes `~/Library/LaunchAgents/com.privacy-gateway.proxy.plist` (runs `uv run --project <repo> pgw-proxy serve`, `RunAtLoad`, `KeepAlive`, stdout/stderr to `~/Library/Logs/privacy-gateway/`), then `launchctl bootstrap gui/$UID <plist>`. `uninstall-launchd` reverses it. `status` checks the port and the launchd job.
- `install-launchd` prints the client setup line: `export ANTHROPIC_BASE_URL=http://127.0.0.1:8787`.

## 5. Testing

- Core: session continuation (same value → same token across two calls; counters continue; new values get the next number; leakage on the second call leaves first-call entries intact), vault external keys + migration of a v0.1 database file, overlap rule for session findings, CLI `--session-key`.
- Transform: request fixtures modelled on real Claude Code traffic — system blocks with `cache_control`, a `tool_result` containing a file with an IBAN and a person, a `tool_use` with `{"file_path": "/home/user/…", "content": "…"}`, a `thinking` block with `signature`, an `image` block; assert only the intended strings change, thinking/signature/image bytes identical, `cache_control` preserved. Response fixtures: text + tool_use restored, thinking untouched.
- Streaming: a recorded SSE stream containing `<PERSON_FEMALE_001>` and a tool_use JSON; parametrize the chunk split position over every byte offset of the token; assert the reassembled output equals the non-streaming restoration and the event framing (`event:`/`data:` lines, blank-line separators) is preserved byte-for-byte for pass-through events.
- E2E: `create_app` with an `httpx.MockTransport` upstream that asserts it never receives the original values and replies (non-streaming and streaming) with tokens; the client sees restored values; a request that would leak gets 422 and the mock upstream is never called; `/v1/models` passthrough.
- Manual smoke test (operator): proxy running, `ANTHROPIC_BASE_URL` set, `claude -p` on a document with a customer name; audit log shows the transformation; response contains the real name.

## 6. Known limits (v1)

- Restoration inside streamed `input_json_delta` is emitted at block end, so tool calls appear slightly later in the stream (typically < 1 s).
- Thinking blocks keep tokens; they are not restored (signed content).
- The holdback covers bracket-less token fragments up to 40 uppercase characters; longer fragments are emitted as-is.
- One proxy process serves one vault and one config; multi-user operation on the Worker needs per-user vault keys (out of scope).
- Overlap rule refined during integration: a finding that **strictly contains** a session finding wins, so a full name around a known last name (or a URL around a known hostname) is tokenized as a whole instead of leaving the uncovered part in the clear. The token survives because correlation propagates a group's single session token to the merged entity; when correlation cannot join the two (different classes, e.g. hostname inside a URL), the longer value gets a token of its own.
- A session only recognizes the surface forms it has stored. A bare last name whose full name is known is **not** re-linked in a later call, so it can receive a second token (or, without a context marker, stay undetected).
- `server.py` keeps at most 64 `GatewaySession` instances (most recently used); a conversation that falls out of the cache is reloaded from the vault, which is correct but loses the in-memory counters cache for one call.
