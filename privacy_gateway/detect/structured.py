"""Structured parsers for URLs, emails, JWTs, keys, connection strings, headers and secrets."""

from __future__ import annotations

import base64
import json
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from privacy_gateway.model import Finding, Span

if TYPE_CHECKING:
    from privacy_gateway.config import Config

STAGE_NAME = "structured"
CONFIDENCE = 0.98
JWT_CONFIDENCE = 0.99

URL_RE = re.compile(r"(?:https?|wss?|ftp)://[^\s>\"')]+")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
JWT_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?![A-Za-z0-9_.\-])"
)
PEM_RE = re.compile(
    r"-----BEGIN ([A-Z ]*)PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]*?"
    r"-----END \1PRIVATE KEY(?: BLOCK)?-----"
)
DB_URI_RE = re.compile(
    r"(?:postgresql|postgres|mysql|mongodb\+srv|mongodb|redis|amqp|mssql)://[^\s>\"')]+"
)
ADO_RE = re.compile(r"[A-Za-z][A-Za-z ]{1,24}=[^;\n]*(?:;[ \t]*[A-Za-z][A-Za-z ]{1,24}=[^;\n]*)+")
HEADER_RE = re.compile(r"^([A-Za-z][A-Za-z-]*):[ \t]*(.+)$", re.MULTILINE)
AUTH_RE = re.compile(r"(?i)^(?:bearer|basic)\s+(\S+)")
DOC_SEP_RE = re.compile(r"^---[ \t]*$", re.MULTILINE)
K8S_SECRET_RE = re.compile(r"^kind:[ \t]*Secret[ \t]*$", re.MULTILINE)
K8S_DATA_RE = re.compile(r"^([ \t]*)data:[ \t]*$", re.MULTILINE)
K8S_ENTRY_RE = re.compile(r"^([ \t]+)[\w.\-]+:[ \t]*(\S+)[ \t]*$")

INTERNAL_SUFFIXES = (".local", ".internal", ".corp", ".lan")
SIGNATURE_KEYS = frozenset({"sig", "signature", "x-amz-signature", "x-goog-signature"})
TOKEN_KEYS = frozenset({"token", "access_token"})
API_KEY_KEYS = frozenset({"api_key", "apikey", "key"})
SESSION_COOKIES = frozenset({"sessionid", "jsessionid", "phpsessid", "connect.sid", "sid"})
AUTH_COOKIES = frozenset({"auth", "token", "access_token", "id_token"})
CSRF_COOKIES = frozenset({"csrf", "xsrf", "_csrf"})
SKIPPED_X_HEADERS = frozenset({"x-request-id"})
ADO_HOST_KEYS = frozenset({"server", "data source", "host", "addr", "address"})
ADO_KEY_CLASSES = {
    "server": "DATABASE_HOST",
    "data source": "DATABASE_HOST",
    "host": "DATABASE_HOST",
    "addr": "DATABASE_HOST",
    "address": "DATABASE_HOST",
    "database": "DATABASE_NAME",
    "initial catalog": "DATABASE_NAME",
    "user id": "DATABASE_USER",
    "uid": "DATABASE_USER",
    "user": "DATABASE_USER",
    "password": "PASSWORD",
    "pwd": "PASSWORD",
}


def _finding(
    start: int,
    end: int,
    data_class: str,
    children: list[Finding] | None = None,
    confidence: float = CONFIDENCE,
) -> Finding:
    return Finding(
        span=Span(start, end),
        data_class=data_class,
        stage=STAGE_NAME,
        confidence=confidence,
        children=children if children is not None else [],
    )


def _dictionary_hit(host: str, terms: list[str]) -> bool:
    for term in terms:
        normalized = term.strip().lower().lstrip(".")
        if normalized and (host == normalized or host.endswith("." + normalized)):
            return True
    return False


def _domain_class(host: str, config: Config, default: str) -> str:
    if _dictionary_hit(host, config.dictionaries.get("CUSTOMER_DOMAIN", [])):
        return "CUSTOMER_DOMAIN"
    if _dictionary_hit(host, config.dictionaries.get("INTERNAL_DOMAIN", [])):
        return "INTERNAL_DOMAIN"
    if host.endswith(INTERNAL_SUFFIXES):
        return "INTERNAL_DOMAIN"
    return default


def _is_internal_host(host: str, config: Config) -> bool:
    if _dictionary_hit(host, config.dictionaries.get("INTERNAL_DOMAIN", [])):
        return True
    return "." not in host or host.endswith(INTERNAL_SUFFIXES)


def _split_pairs(raw: str, offset: int, separator: str) -> list[tuple[str, int, str, int]]:
    pairs: list[tuple[str, int, str, int]] = []
    position = 0
    for chunk in raw.split(separator):
        lead = len(chunk) - len(chunk.lstrip())
        item = chunk.strip()
        if item:
            start = offset + position + lead
            index = item.find("=")
            if index == -1:
                pairs.append((item, start, "", start + len(item)))
            else:
                pairs.append((item[:index], start, item[index + 1 :], start + index + 1))
        position += len(chunk) + len(separator)
    return pairs


def _url_query_children(query: str, offset: int) -> tuple[list[Finding], str | None]:
    children: list[Finding] = []
    keys: set[str] = set()
    for name, name_start, raw_value, value_start in _split_pairs(query, offset, "&"):
        key = name.lower()
        keys.add(key)
        children.append(_finding(name_start, name_start + len(name), "QUERY_PARAMETER"))
        if not raw_value:
            continue
        value_end = value_start + len(raw_value)
        children.append(_finding(value_start, value_end, "QUERY_VALUE"))
        if key in TOKEN_KEYS:
            children.append(_finding(value_start, value_end, "ACCESS_TOKEN"))
        elif key in API_KEY_KEYS:
            children.append(_finding(value_start, value_end, "API_KEY"))
    if keys & SIGNATURE_KEYS:
        return children, "SAS_TOKEN" if "sv" in keys else "SIGNED_URL"
    return children, None


def _netloc_children(netloc: str, offset: int, config: Config, host_default: str) -> list[Finding]:
    children: list[Finding] = []
    host_part = netloc
    host_offset = offset
    if "@" in netloc:
        userinfo, _, host_part = netloc.partition("@")
        host_offset = offset + len(userinfo) + 1
        user, separator, password = userinfo.partition(":")
        if user:
            children.append(_finding(offset, offset + len(user), "PERSON_USERNAME"))
        if separator and password:
            password_start = offset + len(user) + 1
            children.append(
                _finding(password_start, password_start + len(password), "PASSWORD")
            )
    host = host_part
    if host.startswith("["):
        host = host[: host.find("]") + 1] if "]" in host else host
    elif ":" in host:
        host = host[: host.rfind(":")]
    if host:
        data_class = _domain_class(host.lower(), config, host_default)
        children.append(_finding(host_offset, host_offset + len(host), data_class))
    return children


def _parse_urls(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in URL_RE.finditer(text):
        raw = match.group(0)
        parts = urlsplit(raw)
        netloc_offset = match.start() + len(parts.scheme) + 3
        host = parts.hostname or ""
        children = _netloc_children(
            parts.netloc, netloc_offset, config, "FQDN" if "." in host else "HOSTNAME"
        )
        path_offset = netloc_offset + len(parts.netloc)
        if parts.path and re.match(r"^/(?:api|v\d+|rest|graphql)(?:/|$)", parts.path):
            children.append(_finding(path_offset, path_offset + len(parts.path), "API_PATH"))
        data_class = "INTERNAL_URL" if _is_internal_host(host, config) else "URL"
        if parts.query:
            query_offset = match.start() + raw.find("?") + 1
            query_children, override = _url_query_children(parts.query, query_offset)
            children.extend(query_children)
            if override is not None:
                data_class = override
        children.sort(key=lambda child: child.span.start)
        findings.append(_finding(match.start(), match.end(), data_class, children))
    return findings


def _parse_emails(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in EMAIL_RE.finditer(text):
        local, _, domain = match.group(0).partition("@")
        domain_start = match.start() + len(local) + 1
        children = [
            _finding(match.start(), match.start() + len(local), "PERSON_USERNAME"),
            _finding(
                domain_start,
                domain_start + len(domain),
                _domain_class(domain.lower(), config, "DOMAIN"),
            ),
        ]
        findings.append(_finding(match.start(), match.end(), "EMAIL", children))
    return findings


def _is_jwt_header(part: str) -> bool:
    padded = part + "=" * (-len(part) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError:
        return False
    return isinstance(payload, dict) and "alg" in payload


def _parse_jwts(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in JWT_RE.finditer(text):
        if _is_jwt_header(match.group(0).split(".")[0]):
            findings.append(_finding(match.start(), match.end(), "JWT", None, JWT_CONFIDENCE))
    return findings


def _parse_pem_blocks(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in PEM_RE.finditer(text):
        label = match.group(1)
        if "OPENSSH" in label:
            data_class = "SSH_PRIVATE_KEY"
        elif "RSA" in label or "EC" in label:
            data_class = "TLS_PRIVATE_KEY"
        else:
            data_class = "PRIVATE_KEY"
        findings.append(_finding(match.start(), match.end(), data_class, None, JWT_CONFIDENCE))
    return findings


def _parse_connection_strings(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in DB_URI_RE.finditer(text):
        raw = match.group(0)
        parts = urlsplit(raw)
        netloc_offset = match.start() + len(parts.scheme) + 3
        children = _netloc_children(parts.netloc, netloc_offset, config, "DATABASE_HOST")
        children = [
            child if child.data_class != "PERSON_USERNAME" else _rename(child, "DATABASE_USER")
            for child in children
        ]
        children = [_force_host_class(child) for child in children]
        name = parts.path.lstrip("/").split("/")[0]
        if name:
            name_offset = netloc_offset + len(parts.netloc) + 1
            children.append(_finding(name_offset, name_offset + len(name), "DATABASE_NAME"))
        findings.append(
            _finding(match.start(), match.end(), "DATABASE_CONNECTION_STRING", children)
        )
    findings.extend(_parse_ado_strings(text))
    return findings


def _rename(child: Finding, data_class: str) -> Finding:
    return _finding(child.span.start, child.span.end, data_class)


def _force_host_class(child: Finding) -> Finding:
    if child.data_class in ("FQDN", "HOSTNAME", "DOMAIN", "INTERNAL_DOMAIN", "CUSTOMER_DOMAIN"):
        return _rename(child, "DATABASE_HOST")
    return child


def _parse_ado_strings(text: str) -> list[Finding]:
    findings: list[Finding] = []
    for match in ADO_RE.finditer(text):
        pairs = _split_pairs(match.group(0), match.start(), ";")
        keys = {name.strip().lower() for name, _, _, _ in pairs}
        if not keys & ADO_HOST_KEYS or not keys & {"database", "user id", "password", "pwd"}:
            continue
        children: list[Finding] = []
        for name, _, raw_value, value_start in pairs:
            data_class = ADO_KEY_CLASSES.get(name.strip().lower())
            value = raw_value.strip()
            if data_class is None or not value:
                continue
            start = value_start + raw_value.find(value)
            children.append(_finding(start, start + len(value), data_class))
        findings.append(
            _finding(match.start(), match.end(), "DATABASE_CONNECTION_STRING", children)
        )
    return findings


def _cookie_class(name: str) -> str | None:
    key = name.strip().lower()
    if key in SESSION_COOKIES:
        return "SESSION_COOKIE"
    if key in AUTH_COOKIES:
        return "AUTH_COOKIE"
    if key in CSRF_COOKIES:
        return "CSRF_TOKEN"
    return None


def _cookie_children(value: str, offset: int, only_first: bool) -> list[Finding]:
    children: list[Finding] = []
    pairs = _split_pairs(value, offset, ";")
    for name, _, raw_value, value_start in pairs[:1] if only_first else pairs:
        if not raw_value:
            continue
        end = value_start + len(raw_value)
        children.append(_finding(value_start, end, "COOKIE_VALUE"))
        data_class = _cookie_class(name)
        if data_class is not None:
            children.append(_finding(value_start, end, data_class))
    return children


def _parse_headers(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for match in HEADER_RE.finditer(text):
        name = match.group(1).lower()
        value = match.group(2)
        value_offset = match.start(2)
        if name == "authorization":
            credential = AUTH_RE.match(value)
            if credential is not None:
                start = value_offset + credential.start(1)
                findings.append(
                    _finding(start, start + len(credential.group(1)), "ACCESS_TOKEN")
                )
        elif name in ("cookie", "set-cookie"):
            children = _cookie_children(value, value_offset, name == "set-cookie")
            if children:
                findings.append(_finding(match.start(), match.end(), "COOKIE", children))
        elif name.startswith("x-") and not name.startswith("x-forwarded-"):
            if name in SKIPPED_X_HEADERS:
                continue
            child = _finding(value_offset, value_offset + len(value), "HEADER_VALUE")
            findings.append(_finding(match.start(), match.end(), "CUSTOM_HEADER", [child]))
    return findings


def _documents(text: str) -> list[tuple[int, int]]:
    starts = [0]
    ends: list[int] = []
    for match in DOC_SEP_RE.finditer(text):
        ends.append(match.start())
        starts.append(match.end())
    ends.append(len(text))
    return list(zip(starts, ends, strict=True))


def _parse_kubernetes_secrets(text: str, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    for doc_start, doc_end in _documents(text):
        block = text[doc_start:doc_end]
        if K8S_SECRET_RE.search(block) is None:
            continue
        for data_match in K8S_DATA_RE.finditer(block):
            indent = len(data_match.group(1))
            position = data_match.end() + 1
            while position < len(block):
                newline = block.find("\n", position)
                line_end = len(block) if newline == -1 else newline
                line = block[position:line_end]
                if line.strip():
                    entry = K8S_ENTRY_RE.match(line)
                    if entry is None or len(entry.group(1)) <= indent:
                        break
                    start = doc_start + position + entry.start(2)
                    findings.append(
                        _finding(start, start + len(entry.group(2)), "KUBERNETES_SECRET")
                    )
                position = line_end + 1
    return findings


PARSERS = (
    _parse_urls,
    _parse_connection_strings,
    _parse_pem_blocks,
    _parse_headers,
    _parse_kubernetes_secrets,
    _parse_jwts,
    _parse_emails,
)


class StructuredStage:
    """Parses structured formats and classifies their components."""

    name = STAGE_NAME

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return new parent findings whose components are attached as children."""
        new: list[Finding] = []
        for parser in PARSERS:
            for candidate in parser(text, config):
                if not any(kept.span.contains(candidate.span) for kept in new):
                    new.append(candidate)
        new.sort(key=lambda finding: (finding.span.start, -len(finding.span)))
        return new
