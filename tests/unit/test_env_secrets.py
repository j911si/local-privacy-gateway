"""Key/value secrets in `.env`, YAML, JSON and shell form: the name stays, the value goes."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

from privacy_gateway.api import Gateway
from privacy_gateway.config import Config, load_config
from privacy_gateway.detect import Pipeline

SENDGRID = "SG.abcdefghijklmnop.qrstuvwxyz0123456789"
AZURE_KEY = "abcdEFGH1234abcdEFGH1234abcdEFGH1234abcdEFGH1234abcdEFGH1234abcdEFGH12=="


def found(text: str, config: Config) -> list[tuple[str, str]]:
    report = Pipeline(config).run(text)
    return [(f.data_class, text[f.span.start : f.span.end]) for f in report.findings]


@pytest.mark.parametrize(
    ("text", "data_class", "value"),
    [
        ("DB_PASSWORD=hunter2hunter2", "PASSWORD", "hunter2hunter2"),
        ("POSTGRES_PASSWORD=s3cr3tPass", "PASSWORD", "s3cr3tPass"),
        ("DB_PASSWD: s3cr3tPass", "PASSWORD", "s3cr3tPass"),
        ('"DB_PASSWORD": "hunter2hunter2"', "PASSWORD", "hunter2hunter2"),
        ("DB_PASSWORD='hunter2 hunter2'", "PASSWORD", "hunter2 hunter2"),
        ("export DB_PASSWORD=hunter2hunter2", "PASSWORD", "hunter2hunter2"),
        (f"SENDGRID_API_KEY={SENDGRID}", "API_KEY", SENDGRID),
        ("STRIPE_API_KEY: abcdef1234567890abcd", "API_KEY", "abcdef1234567890abcd"),
        ("AWS_ACCESS_KEY=abcdef1234567890abcd", "API_KEY", "abcdef1234567890abcd"),
        (f"DefaultEndpointsProtocol=https;AccountKey={AZURE_KEY};", "API_KEY", AZURE_KEY),
        (f"Endpoint=sb://x;SharedAccessKey={AZURE_KEY}", "API_KEY", AZURE_KEY),
        ("SECRET_KEY=django-insecure-abc123def456", "API_SECRET", "django-insecure-abc123def456"),
        ("app.secret-key=abcdef1234567890", "API_SECRET", "abcdef1234567890"),
        ("export APP_SECRET=abcdef1234567890", "API_SECRET", "abcdef1234567890"),
        ("export APP_TOKEN=abcdef1234567890abcdef", "ACCESS_TOKEN", "abcdef1234567890abcdef"),
        ("slack.token: abcdef1234567890abcdef", "ACCESS_TOKEN", "abcdef1234567890abcdef"),
        ("GITHUB_PRIVATE_KEY=abcdef1234567890abcdef", "PRIVATE_KEY", "abcdef1234567890abcdef"),
        ("OAUTH_CLIENT_SECRET=abcdef1234567890", "CLIENT_SECRET", "abcdef1234567890"),
        ("PAYPAL_REFRESH_TOKEN=abcdef1234567890abcdef", "REFRESH_TOKEN", "abcdef1234567890abcdef"),
    ],
)
def test_env_style_secret_value_is_found_and_the_name_is_not(
    default_config: Config, text: str, data_class: str, value: str
) -> None:
    hits = found(text, default_config)
    assert (data_class, value) in hits
    assert not any(hit_value in {"DB_PASSWORD", "SECRET_KEY"} for _, hit_value in hits)


@pytest.mark.parametrize(
    "text",
    [
        "DB_PASSWORD=",
        "DB_PASSWORD=\nNEXT_VAR=something",
        "password = input()",
        "password = getpass.getpass()",
        "token: str",
        "password: str",
        "password: Optional[str] = None",
        "api_key=None",
        "api_key: None",
        "secret_key = os.environ['X']",
        'secret_key = os.environ["X"]',
        "SECRET_KEY=os.getenv('SECRET_KEY')",
        "api_key=process.env.API_KEY_FOR_SERVICE",
        "token = tokenizer.encode(x_value)",
        "token=get_token_from_header_now",
        "max_tokens=1024",
        "token_count: 5",
        "tokenizer=AutoTokenizer",
        "passwordless: true",
        "reset_password: true",
        "DB_PASSWORD=${DB_PASSWORD}",
        "DB_PASSWORD=$DB_PASSWORD",
        "DB_PASSWORD=${{ secrets.DB_PASSWORD }}",
        "SENDGRID_API_KEY=$SENDGRID_API_KEY",
        "SENDGRID_API_KEY=${SENDGRID_API_KEY}",
        "AccountKey=",
        "my_passwordfile=/etc/x",
        "newpassword_hash=whatever",
    ],
)
def test_code_and_references_are_no_secrets(default_config: Config, text: str) -> None:
    hits = [cls for cls, _ in found(text, default_config) if cls in SECRET_CLASSES]
    assert hits == []


SECRET_CLASSES = {
    "PASSWORD",
    "API_KEY",
    "API_SECRET",
    "ACCESS_TOKEN",
    "REFRESH_TOKEN",
    "CLIENT_SECRET",
    "PRIVATE_KEY",
}


@pytest.fixture
def gateway(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Gateway]:
    for name, value in {
        "PGW_SKIP_USER_CONFIG": "1",
        "PGW_VAULT_DB": str(tmp_path / "vault.db"),
        "PGW_VAULT_KEY_FILE": str(tmp_path / "vault.key"),
        "PGW_AUDIT_LOG": str(tmp_path / "audit.jsonl"),
    }.items():
        monkeypatch.setenv(name, value)
    with Gateway(load_config()) as instance:
        yield instance


ENV_FILE = (
    "# service config\n"
    "DB_HOST=db\n"
    "DB_PASSWORD=hunter2hunter2\n"
    "POSTGRES_PASSWORD=s3cr3tPass\n"
    f"SENDGRID_API_KEY={SENDGRID}\n"
    "SECRET_KEY=django-insecure-abc123def456ghi789\n"
    f"AZURE_STORAGE=DefaultEndpointsProtocol=https;AccountKey={AZURE_KEY}\n"
    "export APP_TOKEN=abcdef1234567890abcdef\n"
    "PORT=8080\n"
)
ENV_SECRETS = (
    "hunter2hunter2",
    "s3cr3tPass",
    SENDGRID,
    "django-insecure-abc123def456ghi789",
    AZURE_KEY,
    "abcdef1234567890abcdef",
)


def test_env_file_goes_through_the_gateway_without_leak(gateway: Gateway) -> None:
    result = gateway.pseudonymize(ENV_FILE)

    assert not any(secret in result.text for secret in ENV_SECRETS)
    names = ("DB_PASSWORD=", "POSTGRES_PASSWORD=", "SENDGRID_API_KEY=", "SECRET_KEY=", "PORT=8080")
    for name in names:
        assert name in result.text
    assert "_REDACTED>" in result.text


def test_env_file_restore_gives_back_the_original_except_the_redaction_markers(
    gateway: Gateway,
) -> None:
    result = gateway.pseudonymize(ENV_FILE)
    restored = gateway.restore(result.text, result.session_id).text

    assert restored == result.text
    assert "DB_HOST=db" in restored and "PORT=8080" in restored


def test_env_file_without_secrets_is_unchanged(gateway: Gateway) -> None:
    text = "DB_HOST=db\nPORT=8080\nDB_PASSWORD=${DB_PASSWORD}\nmax_tokens=1024\n"
    result = gateway.pseudonymize(text)

    assert result.text == text
    assert gateway.restore(result.text, result.session_id).text == text


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("PGPASSWORD=Sup3rGeheim psql -h db01 -U app", "Sup3rGeheim"),
        ("SECRET_KEY=abcDEF123456!xyz789$QWErty%2024", "QWErty%2024"),
        ("API_KEY=ab12!cd34$ef56%gh78#ij90", "ij90"),
        ("DB_PASS=Kx8Lm2Qp7RtVw", "Kx8Lm2Qp7RtVw"),
        ("ENCRYPTION_KEY=Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==", "Zm9vYmFy"),
        ("SIGNING_KEY=6e3f1a9c8b7d5e4f2a1b0c9d8e7f6a5b", "6e3f1a9c"),
        ("LICENSE_KEY=AB12C-DE34F-GH56I-JK78L-MN90P", "DE34F-GH56I"),
        ("key=9f8e7d6c5b4a39281706f5e4d3c2b1a0", "9f8e7d6c"),
        ("TELEGRAM_BOT_TOKEN=7123456789:AAHk3Jx9Lm2Qp7Rt5Vw8Yz1Bc4Df6Gh0JnQ", "AAHk3Jx9"),
        ("CREDENTIALS=annika:Sommer2024geheim", "Sommer2024geheim"),
        ("passphrase: korrekt-pferd-batterie-heftklammer-77", "pferd-batterie"),
        ("os.environ['API_SECRET'] = 'Qw3rTy7uI9oP1aS5dF8gH2jK'", "Qw3rTy7uI9oP"),
        ("HTPASSWD=admin:$apr1$Zx9Yw8Vu$7Ts6Rq5Po4Nm3Lk2Ji1Hg0", "7Ts6Rq5Po4Nm"),
        ("password: Tr0ub4dor&3 horse", "Tr0ub4dor"),
    ],
)
def test_secret_value_is_replaced_completely(gateway: Gateway, text: str, secret: str) -> None:
    result = gateway.pseudonymize(text)
    assert secret not in result.text
    assert "_REDACTED>" in result.text


def test_value_with_special_characters_is_replaced_up_to_the_line_end(gateway: Gateway) -> None:
    result = gateway.pseudonymize("SECRET_KEY=abcDEF123456!xyz789$QWErty%2024\nPORT=8080")
    assert result.text.splitlines()[0] == "SECRET_KEY=<API_SECRET_REDACTED>"
    assert result.text.splitlines()[1] == "PORT=8080"


@pytest.mark.parametrize(
    "text",
    [
        "if password == confirm_password:",
        "if password != confirm_password:",
        "if (password := get_password()) is None:",
        "while token == expected_token_value:",
        "assert secret_key === other_secret_key_value",
        "password = new_password",
        "password = user.password",
        "password=confirm_password",
        "secret = hashlib.sha256(data).hexdigest()",
        "csrf_token = generate_csrf()",
        "client_secret: process.env.CLIENT_SECRET,",
        "Passwort: wird per Post verschickt",
        "Password: (leer lassen fuer Standard)",
        "api_key=<your-key-here>",
        "api_key=your_api_key_here",
        "key=value_without_digits_here",
        "primary_key=True",
        "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
        "token = get_access_token()",
        "credentials: include",
        "PGPASSWORD=${DB_PASSWORD} psql",
    ],
)
def test_comparisons_calls_references_and_prose_are_no_secrets(
    gateway: Gateway, text: str
) -> None:
    assert gateway.pseudonymize(text).text == text
