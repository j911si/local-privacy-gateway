from __future__ import annotations

import dataclasses
import itertools

from privacy_gateway.config import Config
from privacy_gateway.detect.structured import StructuredStage
from privacy_gateway.model import Finding

JWT_SAMPLE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

PEM_RSA = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END RSA PRIVATE KEY-----"""

PEM_OPENSSH = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
-----END OPENSSH PRIVATE KEY-----"""

PEM_PGP = """-----BEGIN PGP PRIVATE KEY BLOCK-----

bFDPWGYxQkdGMUJHRjFCR0YxQkdGMUJHRjFCR0YxQkdGMUJHRjFCR0YxQkdGMUJH
-----END PGP PRIVATE KEY BLOCK-----"""

K8S_SECRET = """apiVersion: v1
kind: Secret
metadata:
  name: app-secrets
type: Opaque
data:
  username: YWRtaW4=
  password: c3VwZXJzZWNyZXQ=
"""


MIXED_LINES = [
    "https://alice:s3cret@db.internal:5432/v1/app?api_key=0123456789abcdef",
    "https://cdn.example.com/f?sv=1&sig=abc",
    "mailto max@example.com",
    JWT_SAMPLE,
    PEM_RSA,
    "postgres://app:pw@10.0.0.7:5432/orders",
    "Authorization: Bearer abcdefghijklmnop",
    "Cookie: sessionid=abc123def",
    "X-Tenant-Key: 9f8e7d",
    K8S_SECRET,
]


def run(text: str, config: Config) -> list[Finding]:
    return StructuredStage().run(text, config, [])


def value(text: str, finding: Finding) -> str:
    return text[finding.span.start : finding.span.end]


def only(findings: list[Finding], data_class: str) -> Finding:
    matches = [f for f in findings if f.data_class == data_class]
    assert len(matches) == 1, [f.data_class for f in findings]
    return matches[0]


def classes(findings: list[Finding]) -> list[str]:
    return [f.data_class for f in findings]


def with_dictionary(config: Config, name: str, terms: list[str]) -> Config:
    return dataclasses.replace(config, dictionaries={**config.dictionaries, name: terms})


def walk(findings: list[Finding]) -> list[Finding]:
    out: list[Finding] = []
    for finding in findings:
        out.append(finding)
        out.extend(walk(finding.children))
    return out


def test_stage_name(default_config: Config) -> None:
    assert StructuredStage().name == "structured"


def test_url_with_query_and_token(default_config: Config) -> None:
    text = "see https://api.corp.example.com/v1/users?id=42&token=abcdefghijklmnop for details"
    findings = run(text, default_config)
    url = only(findings, "URL")
    assert value(text, url) == "https://api.corp.example.com/v1/users?id=42&token=abcdefghijklmnop"
    assert url.confidence == 0.98
    assert url.stage == "structured"
    assert value(text, only(url.children, "FQDN")) == "api.corp.example.com"
    assert value(text, only(url.children, "API_PATH")) == "/v1/users"
    names = [c for c in url.children if c.data_class == "QUERY_PARAMETER"]
    values = [c for c in url.children if c.data_class == "QUERY_VALUE"]
    assert [value(text, c) for c in names] == ["id", "token"]
    assert [value(text, c) for c in values] == ["42", "abcdefghijklmnop"]
    assert value(text, only(url.children, "ACCESS_TOKEN")) == "abcdefghijklmnop"


def test_url_api_key_query_parameter(default_config: Config) -> None:
    text = "https://example.com/v2/items?api_key=0123456789abcdef"
    url = only(run(text, default_config), "URL")
    assert value(text, only(url.children, "API_KEY")) == "0123456789abcdef"


def test_url_with_credentials_is_internal(default_config: Config) -> None:
    text = "connect to https://alice:s3cret@db.internal:5432/app now"
    findings = run(text, default_config)
    url = only(findings, "INTERNAL_URL")
    assert value(text, url) == "https://alice:s3cret@db.internal:5432/app"
    assert value(text, only(url.children, "PERSON_USERNAME")) == "alice"
    assert value(text, only(url.children, "PASSWORD")) == "s3cret"
    assert value(text, only(url.children, "INTERNAL_DOMAIN")) == "db.internal"


def test_url_host_without_dot_is_internal_hostname(default_config: Config) -> None:
    text = "https://intranet/start"
    url = only(run(text, default_config), "INTERNAL_URL")
    assert value(text, only(url.children, "HOSTNAME")) == "intranet"


def test_url_host_from_internal_domain_dictionary(default_config: Config) -> None:
    config = with_dictionary(default_config, "INTERNAL_DOMAIN", ["corp.example.com"])
    text = "https://api.corp.example.com/status"
    url = only(run(text, config), "INTERNAL_URL")
    assert value(text, only(url.children, "INTERNAL_DOMAIN")) == "api.corp.example.com"


def test_url_host_from_customer_domain_dictionary(default_config: Config) -> None:
    config = with_dictionary(default_config, "CUSTOMER_DOMAIN", ["kunde.de"])
    text = "https://shop.kunde.de/cart"
    url = only(run(text, config), "URL")
    assert value(text, only(url.children, "CUSTOMER_DOMAIN")) == "shop.kunde.de"


def test_url_with_signature_is_signed_url(default_config: Config) -> None:
    text = "https://cdn.example.com/file.zip?expires=1700000000&sig=Zm9vYmFyQmF6"
    findings = run(text, default_config)
    assert only(findings, "SIGNED_URL") is not None
    assert "URL" not in classes(findings)


def test_url_with_sv_and_sig_is_sas_token(default_config: Config) -> None:
    text = (
        "https://acct.blob.core.windows.net/c/f.txt"
        "?sv=2021-06-08&ss=b&srt=sco&sig=abcDEF123%2Fxyz"
    )
    findings = run(text, default_config)
    sas = only(findings, "SAS_TOKEN")
    assert value(text, sas) == text


def test_email_with_customer_domain(default_config: Config) -> None:
    config = with_dictionary(default_config, "CUSTOMER_DOMAIN", ["kunde.de"])
    text = "Bitte an anna.mueller@kunde.de senden."
    email = only(run(text, config), "EMAIL")
    assert value(text, email) == "anna.mueller@kunde.de"
    assert email.confidence == 0.98
    assert value(text, only(email.children, "PERSON_USERNAME")) == "anna.mueller"
    assert value(text, only(email.children, "CUSTOMER_DOMAIN")) == "kunde.de"


def test_email_plain_domain(default_config: Config) -> None:
    text = "max@example.com"
    email = only(run(text, default_config), "EMAIL")
    assert value(text, only(email.children, "DOMAIN")) == "example.com"


def test_jwt_detected(default_config: Config) -> None:
    text = f"token {JWT_SAMPLE} end"
    jwt = only(run(text, default_config), "JWT")
    assert value(text, jwt) == JWT_SAMPLE
    assert jwt.confidence == 0.99


def test_three_dotted_words_are_not_a_jwt(default_config: Config) -> None:
    assert run("a.b.c", default_config) == []


def test_pem_rsa_is_tls_private_key(default_config: Config) -> None:
    text = f"key:\n{PEM_RSA}\ndone"
    finding = only(run(text, default_config), "TLS_PRIVATE_KEY")
    assert value(text, finding) == PEM_RSA


def test_pem_openssh_is_ssh_private_key(default_config: Config) -> None:
    finding = only(run(PEM_OPENSSH, default_config), "SSH_PRIVATE_KEY")
    assert value(PEM_OPENSSH, finding) == PEM_OPENSSH


def test_pem_pgp_block_is_private_key(default_config: Config) -> None:
    finding = only(run(PEM_PGP, default_config), "PRIVATE_KEY")
    assert value(PEM_PGP, finding) == PEM_PGP


def test_connection_string_uri(default_config: Config) -> None:
    text = "DSN postgres://app:pw@10.0.0.7:5432/orders configured"
    conn = only(run(text, default_config), "DATABASE_CONNECTION_STRING")
    assert value(text, conn) == "postgres://app:pw@10.0.0.7:5432/orders"
    assert len(conn.children) == 4
    assert value(text, only(conn.children, "DATABASE_USER")) == "app"
    assert value(text, only(conn.children, "PASSWORD")) == "pw"
    assert value(text, only(conn.children, "DATABASE_HOST")) == "10.0.0.7"
    assert value(text, only(conn.children, "DATABASE_NAME")) == "orders"


def test_connection_string_ado(default_config: Config) -> None:
    text = "Server=db1.example.com;Database=orders;User Id=svc_app;Password=Str0ngPw"
    conn = only(run(text, default_config), "DATABASE_CONNECTION_STRING")
    assert value(text, conn) == text
    assert value(text, only(conn.children, "DATABASE_HOST")) == "db1.example.com"
    assert value(text, only(conn.children, "DATABASE_NAME")) == "orders"
    assert value(text, only(conn.children, "DATABASE_USER")) == "svc_app"
    assert value(text, only(conn.children, "PASSWORD")) == "Str0ngPw"


def test_cookie_header(default_config: Config) -> None:
    text = "Cookie: sessionid=abc123def; theme=dark"
    cookie = only(run(text, default_config), "COOKIE")
    assert value(text, cookie) == text
    assert value(text, only(cookie.children, "SESSION_COOKIE")) == "abc123def"
    assert [value(text, c) for c in cookie.children if c.data_class == "COOKIE_VALUE"] == [
        "abc123def",
        "dark",
    ]


def test_set_cookie_auth_and_csrf(default_config: Config) -> None:
    text = "Set-Cookie: access_token=zzz999; Path=/; HttpOnly\nCookie: _csrf=tok12345"
    findings = run(text, default_config)
    cookies = [f for f in findings if f.data_class == "COOKIE"]
    assert len(cookies) == 2
    assert value(text, only(cookies[0].children, "AUTH_COOKIE")) == "zzz999"
    assert value(text, only(cookies[1].children, "CSRF_TOKEN")) == "tok12345"


def test_custom_header(default_config: Config) -> None:
    text = "X-Tenant-Key: 9f8e7d"
    header = only(run(text, default_config), "CUSTOM_HEADER")
    assert value(text, header) == text
    assert value(text, only(header.children, "HEADER_VALUE")) == "9f8e7d"


def test_ignored_x_headers(default_config: Config) -> None:
    text = "X-Forwarded-For: 10.0.0.1\nX-Request-Id: 7a1b2c3d"
    assert run(text, default_config) == []


def test_authorization_basic(default_config: Config) -> None:
    text = "Authorization: Basic dXNlcjpwYXNz"
    token = only(run(text, default_config), "ACCESS_TOKEN")
    assert value(text, token) == "dXNlcjpwYXNz"


def test_authorization_bearer(default_config: Config) -> None:
    text = "Authorization: Bearer abcdefghijklmnop.qrst"
    token = only(run(text, default_config), "ACCESS_TOKEN")
    assert value(text, token) == "abcdefghijklmnop.qrst"


def test_kubernetes_secret_data_values(default_config: Config) -> None:
    findings = run(K8S_SECRET, default_config)
    secrets = [f for f in findings if f.data_class == "KUBERNETES_SECRET"]
    assert [value(K8S_SECRET, f) for f in secrets] == ["YWRtaW4=", "c3VwZXJzZWNyZXQ="]


def test_kubernetes_data_without_secret_kind(default_config: Config) -> None:
    text = "apiVersion: v1\nkind: ConfigMap\ndata:\n  username: YWRtaW4=\n"
    assert "KUBERNETES_SECRET" not in classes(run(text, default_config))


def test_findings_never_expose_the_value(default_config: Config) -> None:
    text = "https://alice:s3cret@db.internal/app and Cookie: sessionid=abc123def"
    for finding in walk(run(text, default_config)):
        assert "s3cret" not in repr(finding)
        assert "abc123def" not in repr(finding)
        assert finding.attributes == {}


def test_all_emitted_classes_are_registered(default_config: Config) -> None:
    text = "\n".join(MIXED_LINES)
    findings = run(text, default_config)
    assert findings
    for finding in walk(findings):
        assert finding.data_class in default_config.registry
        assert finding.stage == "structured"


def test_findings_are_sorted_and_not_nested(default_config: Config) -> None:
    text = f"a https://example.com/x?token=abcdefghijklmnop b {JWT_SAMPLE} c max@example.com"
    findings = run(text, default_config)
    starts = [f.span.start for f in findings]
    assert starts == sorted(starts)
    for first, second in itertools.pairwise(findings):
        assert not first.span.overlaps(second.span)


def test_returns_only_new_findings(default_config: Config) -> None:
    text = "max@example.com"
    existing = run(text, default_config)
    again = StructuredStage().run(text, default_config, existing)
    assert [f.data_class for f in again] == ["EMAIL"]
