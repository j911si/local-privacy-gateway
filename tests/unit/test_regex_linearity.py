"""Rules that backtracked quadratically stay linear: 2n costs < 3x n, with an absolute cap."""

from __future__ import annotations

import random
import re
import signal
import time
from collections.abc import Callable, Iterator

import pytest

from privacy_gateway.config import Config
from privacy_gateway.detect import context, patterns, structured

HARD_TIMEOUT_S = 60
MAX_FACTOR = 3.0
MAX_SECONDS = 1.0
NOISE_FLOOR_S = 0.02
N = 100_000
ADO_N = 20_000


@pytest.fixture(autouse=True)
def _hard_timeout() -> Iterator[None]:
    """SIGALRM stops a quadratic regex instead of hanging the run."""

    def _expired(signum: int, frame: object) -> None:
        raise TimeoutError(f"regex scan exceeded {HARD_TIMEOUT_S}s")

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.alarm(HARD_TIMEOUT_S)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def best_of_three(scan: Callable[[], object]) -> float:
    timings = []
    for _ in range(3):
        started = time.perf_counter()
        scan()
        timings.append(time.perf_counter() - started)
    return min(timings)


def assert_linear(
    scan: Callable[[str], object], payload: Callable[[int], str], n: int = N
) -> None:
    small_text, large_text = payload(n), payload(2 * n)
    small = best_of_three(lambda: scan(small_text))
    large = best_of_three(lambda: scan(large_text))
    assert large < MAX_SECONDS, f"{large:.3f}s for {2 * n} characters"
    assert large < NOISE_FLOOR_S or large / small < MAX_FACTOR, f"factor {large / small:.2f}"


def finditer(pattern: re.Pattern[str]) -> Callable[[str], object]:
    return lambda text: list(pattern.finditer(text))


def config_patterns(config: Config, name: str) -> list[re.Pattern[str]]:
    return [re.compile(p, re.MULTILINE) for p in config.registry.get(name).patterns]


@pytest.mark.parametrize(
    ("name", "word"),
    [("PIN", "PIN"), ("TAN", "TAN"), ("OTP", "OTP"), ("OTP", "einmalcode")],
)
def test_pin_tan_otp_after_long_blank_runs(default_config: Config, name: str, word: str) -> None:
    for pattern in config_patterns(default_config, name):
        assert_linear(finditer(pattern), lambda n: word + " " * n + "fehlt")
        assert_linear(finditer(pattern), lambda n: (word + " " * 50) * (n // 53))


@pytest.mark.parametrize(
    ("text", "value"),
    [
        ("PIN 1234", "1234"),
        ("PIN:1234", "1234"),
        ("pin = 12345678", "12345678"),
        ("PIN \n 4711", "4711"),
        ("TAN: 123456", "123456"),
        ("OTP=654321", "654321"),
        ("Einmalcode :  654321", "654321"),
    ],
)
def test_pin_tan_otp_matches_are_unchanged(default_config: Config, text: str, value: str) -> None:
    found = [
        m.group(1)
        for name in ("PIN", "TAN", "OTP")
        for pattern in config_patterns(default_config, name)
        for m in pattern.finditer(text)
    ]
    assert value in found


def random_texts(alphabet: list[str], seed: int, count: int = 3000) -> list[str]:
    rng = random.Random(seed)
    return ["".join(rng.choice(alphabet) for _ in range(rng.randint(0, 40))) for _ in range(count)]


ADO_ALPHABET = [
    "Server=db1", "Database=x", "User Id=u", "Password=p", "a", "aA=", "A", " ", "\t", ";", "; ",
    "=", "\n", "1", "x y=", "Data Source=h", "abcdefghijklmnopqrstuvwxyz=", "Pwd=", ";;",
]


def test_ado_finditer_equals_finditer() -> None:
    from privacy_gateway.detect.structured import ADO_RE, ado_finditer

    matched = 0
    texts = random_texts(ADO_ALPHABET, 4711)
    texts += ["aA=" * 500 + ";", "aA=" * 500 + ";x", "a=b;" * 300, "a=b;c" * 300, ";" * 400]
    for text in texts:
        expected = [m.span() for m in ADO_RE.finditer(text)]
        assert [m.span() for m in ado_finditer(text)] == expected
        matched += len(expected)
    assert matched > 0


@pytest.mark.parametrize(
    "unit", ["aA=", "aA=;1", "a=b;", ";", "Server=a;Database=b;" + "x" * 30, "aA= "]
)
def test_ado_connection_strings_scan_in_linear_time(unit: str) -> None:
    assert_linear(
        structured._parse_ado_strings, lambda n: unit * (n // len(unit)), n=ADO_N
    )


PEM_ALPHABET = [
    "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----",
    "-----END RSA PRIVATE KEY-----", "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "-----END PGP PRIVATE KEY BLOCK-----", "-----BEGIN EC PRIVATE KEY-----", "-----END ", "-",
    "-----", "BEGIN ", "PRIVATE KEY", "\n", "MIIB", " ", "A", "-----BEGIN PRIVATE KEY BLOCK-----",
]


def test_pem_finditer_equals_finditer() -> None:
    from privacy_gateway.detect.structured import PEM_RE, pem_finditer

    matched = 0
    texts = random_texts(PEM_ALPHABET, 815)
    texts.append("-----BEGIN PRIVATE KEY-----BEGIN PRIVATE KEY-----x-----END PRIVATE KEY-----")
    for text in texts:
        expected = [(m.span(), m.group(1)) for m in PEM_RE.finditer(text)]
        assert [(m.span(), m.group(1)) for m in pem_finditer(text)] == expected
        matched += len(expected)
    assert matched > 0


@pytest.mark.parametrize(
    "unit",
    [
        "-----BEGIN PRIVATE KEY-----\n",
        "-----BEGIN RSA PRIVATE KEY-----\n-----END PRIVATE KEY-----\n",
        "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
    ],
)
def test_pem_blocks_scan_in_linear_time(default_config: Config, unit: str) -> None:
    assert_linear(
        lambda text: structured._parse_pem_blocks(text, default_config),
        lambda n: unit * (n // len(unit)),
    )


JWT_ALPHABET = ["eyJ", "-", "_", ".", "a", "Z", "0", "abcdefghij", " ", "xeyJ", "=", "\n"]


def test_jwt_finditer_equals_finditer(default_config: Config) -> None:
    from privacy_gateway.detect.runs import JWT_PATTERN, jwt_finditer

    assert default_config.registry.get("JWT").patterns == (JWT_PATTERN,)
    pattern = re.compile(JWT_PATTERN, re.MULTILINE)
    matched = 0
    texts = random_texts(JWT_ALPHABET, 99, 6000)
    texts.append("eyJ" + "a" * 12 + "." + "b" * 12 + "." + "c" * 12)
    for text in texts:
        expected = [m.span() for m in pattern.finditer(text)]
        assert [m.span() for m in jwt_finditer(pattern, text)] == expected
        matched += len(expected)
    assert matched > 0


@pytest.mark.parametrize("unit", ["eyJ-", "eyJaaaaaaaaaaaa.", "eyJ_"])
def test_jwt_rule_scans_in_linear_time(default_config: Config, unit: str) -> None:
    pattern = re.compile(default_config.registry.get("JWT").patterns[0], re.MULTILINE)
    scan = patterns.LINEAR_FINDERS.get(pattern.pattern)
    assert_linear(
        (lambda text: list(scan(pattern, text))) if scan else finditer(pattern),
        lambda n: unit * (n // len(unit)),
    )


@pytest.mark.parametrize("word", ["steuernummer", "Steuer-ID", "tax id"])
def test_labelled_tax_id_after_long_blank_runs(default_config: Config, word: str) -> None:
    for pattern in config_patterns(default_config, "TAX_ID"):
        assert_linear(finditer(pattern), lambda n: word + " " * n + "fehlt")


@pytest.mark.parametrize("word", ["PLZ", "Postleitzahl", "zip"])
def test_postal_code_after_long_blank_runs(word: str) -> None:
    assert_linear(finditer(context.POSTAL_CODE_RE), lambda n: word + " " * n + "fehlt")


@pytest.mark.parametrize("payload", ["Dear", "Hi", "Hallo", "x", ""])
def test_salutation_after_long_blank_runs(payload: str) -> None:
    assert_linear(finditer(context.SALUTATION_RE), lambda n: payload + " " * n + "fehlt")


@pytest.mark.parametrize(
    ("text", "spans"),
    [
        ("Sehr geehrte Frau Müller,", [(0, 24)]),
        ("x   Herr Dr. Meier", [(1, 18)]),
        ("hallo Dear Frau Kühn", [(6, 20)]),
        ("  \n Mr. Smith", [(0, 13)]),
    ],
)
def test_salutation_spans_are_unchanged(text: str, spans: list[tuple[int, int]]) -> None:
    assert [m.span() for m in context.SALUTATION_RE.finditer(text)] == spans


@pytest.mark.parametrize(
    ("text", "value"),
    [("PLZ: 80331", "80331"), ("Postleitzahl 1010", "1010"), ("zip=12345", "12345")],
)
def test_postal_code_matches_are_unchanged(text: str, value: str) -> None:
    assert [m.group(1) for m in context.POSTAL_CODE_RE.finditer(text)] == [value]


ESCAPED_JSON_RULES = {
    "PASSWORD": "password",
    "API_KEY": "api_key",
    "API_SECRET": "api_secret",
    "CLIENT_SECRET": "client_secret",
    "ACCESS_TOKEN": "access_token",
    "REFRESH_TOKEN": "refresh_token",
    "PRIVATE_KEY": "private_key",
    "CSRF_TOKEN": "xsrf-token",
    "SESSION_ID": "sessionid",
}
ESCAPED_JSON_UNITS = [
    '{key}\\": \\"',
    '{key}\\\\\\": \\\\\\"a',
    '{key}\\\\\\\\\\\\\\": \\\\\\\\\\\\\\"ab',
    '{key}:\\"a1\\\\\\"',
    "\\",
    '\\"',
]


@pytest.mark.parametrize("name", sorted(ESCAPED_JSON_RULES))
@pytest.mark.parametrize("unit", ESCAPED_JSON_UNITS)
def test_escaped_json_rules_scan_in_linear_time(
    default_config: Config, name: str, unit: str
) -> None:
    text_unit = unit.format(key=ESCAPED_JSON_RULES[name])
    for pattern in config_patterns(default_config, name):
        if "{0,7}" not in pattern.pattern and "\\\\{1,7}" not in pattern.pattern:
            continue
        assert_linear(finditer(pattern), lambda n: text_unit * (n // len(text_unit)))
        assert_linear(
            finditer(pattern), lambda n: text_unit + "a" * n + " " + text_unit + "\\" * n
        )


@pytest.mark.parametrize(
    "unit", ["karte", "Karte4", "4", "visa41111", "aDE89", "DE8937040044", "xDE89 3704 "]
)
@pytest.mark.parametrize("name", ["IBAN", "CREDIT_CARD"])
def test_glued_iban_and_card_rules_scan_in_linear_time(
    default_config: Config, name: str, unit: str
) -> None:
    for pattern in config_patterns(default_config, name):
        assert_linear(finditer(pattern), lambda n: unit * (n // len(unit)))


PASS_ALPHABET = [
    "pw", "pass", ":", " ", "\t", "\n", "a", "1", "ab12cd", ".", ")", '"', "$", "=", "x",
]
LINE_ALPHABET = [
    "mysql", "mysqldump", "mariadb", "sshpass", " ", "\t", "\n", "-p", " -p", " -p ", "'", '"',
    "secret1", "\\", "-", "$x", "ab", "u",
]


def test_pass_pw_finditer_equals_finditer() -> None:
    from privacy_gateway.detect.runs import PASS_PW_PATTERN, pass_pw_finditer

    pattern = re.compile(PASS_PW_PATTERN, re.MULTILINE)
    matched = 0
    texts = random_texts(PASS_ALPHABET, 31, 20_000)
    texts += ["pw:" * 300, "pw:pw:ab12cd", 'pw:"pw:ab12cd x', "pw: pw:" * 50 + "a1b2c3"]
    for text in texts:
        expected = [m.span(1) for m in pattern.finditer(text)]
        assert [m.span(1) for m in pass_pw_finditer(pattern, text)] == expected
        matched += len(expected)
    assert matched > 0


def test_line_keyword_finditer_equals_finditer(default_config: Config) -> None:
    rules = [
        re.compile(p, re.MULTILINE)
        for p in default_config.registry.get("PASSWORD").patterns
        if p.startswith("\\b")
    ]
    assert len(rules) == 4
    matched = 0
    texts = random_texts(LINE_ALPHABET, 57, 20_000)
    for pattern in rules:
        for text in texts:
            expected = [m.span(1) for m in pattern.finditer(text)]
            assert [m.span(1) for m in patterns.finditer(pattern, text)] == expected
            matched += len(expected)
    assert matched > 0


PASSWORD_WORST_CASES = [
    'passwd: "',
    "password: wird ",
    "password: must 8 chars ",
    "password: must x ",
    "pwd: the 1 ",
    "pw:",
    "pw: ",
    'mariadb"',
    "mysql ",
    "sshpass ",
    "sshpass=",
    "password=x.",
]


@pytest.mark.parametrize("unit", PASSWORD_WORST_CASES)
def test_password_rules_scan_in_linear_time(default_config: Config, unit: str) -> None:
    for pattern in config_patterns(default_config, "PASSWORD"):
        assert_linear(
            lambda text, pattern=pattern: list(patterns.finditer(pattern, text)),
            lambda n: unit * (n // len(unit)),
        )


@pytest.mark.parametrize("filler", [" ", "\t", ".", " .", ").", "x."])
@pytest.mark.parametrize(
    "head",
    [
        "password: x",
        "password=x",
        "pwd = x",
    ],
)
def test_password_rules_with_a_long_blank_or_dot_run(
    default_config: Config, head: str, filler: str
) -> None:
    for pattern in config_patterns(default_config, "PASSWORD"):
        assert_linear(finditer(pattern), lambda n: head + filler * n + "y", n=20_000)


COLON_ALPHABET = [
    "password", "Passwort", "pwd", "_pass", ":", " ", "\t", "\n", "wird", "the", "a", "an",
    "must", "should", "8", "12+", " characters", " chars", " Zeichen", "x", "secret9", ".", ",",
    "(", ")", '"', "$", "none", "a.b", "my_var", "\r", "\u212a", "\u017f", "ü", "-", "'",
]


def test_colon_finditer_equals_finditer() -> None:
    from privacy_gateway.detect.runs import COLON_PATTERN, colon_finditer

    pattern = re.compile(COLON_PATTERN, re.MULTILINE)
    rng = random.Random(360)
    matched = 0
    for _ in range(60_000):
        text = "".join(rng.choice(COLON_ALPHABET) for _ in range(rng.randint(1, 30)))
        if rng.random() < 0.5:
            text = rng.choice(["password: ", "pwd:", "Passwort :\t"]) + text
        expected = [m.span(1) for m in pattern.finditer(text)]
        assert [m.span(1) for m in colon_finditer(pattern, text)] == expected, text
        matched += len(expected)
    assert matched > 1000


def test_the_colon_rule_takes_the_linear_path(default_config: Config) -> None:
    from privacy_gateway.detect.runs import COLON_PATTERN

    assert COLON_PATTERN in default_config.registry.get("PASSWORD").patterns
    assert COLON_PATTERN in patterns.LINEAR_FINDERS


@pytest.mark.parametrize("unit", ["password: wird ", "password: must 8 chars ", "pwd: a "])
def test_colon_rule_stays_linear_on_megabyte_lines(default_config: Config, unit: str) -> None:
    pattern = re.compile(
        next(p for p in default_config.registry.get("PASSWORD").patterns if "(?:wird" in p),
        re.MULTILINE,
    )
    assert_linear(
        lambda text: list(patterns.finditer(pattern, text)),
        lambda n: unit * (n // len(unit)),
        n=1_000_000,
    )
