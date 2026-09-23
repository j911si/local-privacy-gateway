"""Check-digit and shape validators used by the pattern stage."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable
from datetime import date

COUNTRY_CODES = frozenset(
    (
        "AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX",
        "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ",
        "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK",
        "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
        "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR",
        "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS",
        "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN",
        "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
        "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV",
        "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ",
        "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI",
        "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
        "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC",
        "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV",
        "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR",
        "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
        "VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
    )
)

IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22,
    "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28,
    "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23,
    "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27,
    "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}

PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "100.64.0.0/10",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    )
)

KNOWN_TLDS = frozenset(
    (
        "com", "net", "org", "edu", "gov", "mil", "int", "io", "de", "at", "ch", "eu", "uk",
        "us", "fr", "nl", "it", "es", "pl", "se", "no", "dk", "fi", "be", "cz", "pt", "ie",
        "lu", "li", "info", "biz", "cloud", "dev", "app", "tech", "ai", "co", "me", "tv",
        "cc", "internal", "local", "corp", "lan", "intra", "home", "test", "example",
        "invalid", "localhost",
    )
)

FILE_EXTENSIONS = frozenset(
    (
        "txt", "py", "js", "ts", "json", "yaml", "yml", "md", "html", "css", "png", "jpg",
        "jpeg", "gif", "svg", "pdf", "zip", "tar", "gz", "log", "csv", "xml", "ini", "cfg",
        "toml", "sh", "exe", "dll", "so",
    )
)

MAX_LABEL_LENGTH = 63
MIN_LABELS = 2

IBAN_RE = re.compile(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}")
BIC_RE = re.compile(r"[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?")
MAC_RE = re.compile(r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|(?:[0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}")
VIN_RE = re.compile(r"[A-HJ-NPR-Z0-9]{17}")
PHONE_RE = re.compile(r"[\d+()/ .\-]+")
VAT_RE = re.compile(r"[A-Z]{2}[0-9A-Z]{8,12}")
DE_SSN_RE = re.compile(r"\d{2}\d{6}[A-Z]\d{3}")
US_SSN_RE = re.compile(r"\d{9}")

DATE_RE = re.compile(r"(?:(\d{1,2})([./])(\d{1,2})\2(\d{2,4})|(\d{4})-(\d{2})-(\d{2}))")
MIN_YEAR = 1900
MAX_YEAR = 2100

VIN_VALUES = {c: i for i, c in enumerate("0123456789")} | {
    c: v
    for c, v in zip(
        "ABCDEFGHJKLMNPRSTUVWXYZ",
        (1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9, 2, 3, 4, 5, 6, 7, 8, 9),
        strict=True,
    )
}
VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)
DE_SSN_WEIGHTS = (2, 1, 2, 5, 7, 1, 2, 1, 2, 1, 2, 1)


def luhn_valid(s: str) -> bool:
    """Luhn check digit; spaces and dashes are ignored."""
    digits = s.replace(" ", "").replace("-", "")
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def iban_valid(s: str) -> bool:
    """ISO 13616 shape, country length and mod-97 check."""
    compact = s.replace(" ", "").upper()
    if IBAN_RE.fullmatch(compact) is None:
        return False
    expected = IBAN_LENGTHS.get(compact[:2])
    if expected is not None and len(compact) != expected:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(char, 36)) for char in rearranged)
    return int(numeric) % 97 == 1


def bic_valid(s: str) -> bool:
    """ISO 9362 shape with a real ISO 3166-1 country code."""
    compact = s.replace(" ", "")
    if BIC_RE.fullmatch(compact) is None:
        return False
    return compact[4:6] in COUNTRY_CODES


def ip_scope(s: str) -> str | None:
    """Return "private", "public" or None when the address is invalid."""
    try:
        address = ipaddress.ip_address(s.strip())
    except ValueError:
        return None
    for network in PRIVATE_NETWORKS:
        if address.version == network.version and address in network:
            return "private"
    return "public"


def ip_valid(s: str) -> bool:
    """True when the string is a syntactically valid IP address."""
    return ip_scope(s) is not None


def fqdn_valid(s: str) -> bool:
    """Multi-label host name whose last label is a known TLD, not a file name."""
    labels = s.lower().split(".")
    if len(labels) < MIN_LABELS:
        return False
    if any(not label or len(label) > MAX_LABEL_LENGTH for label in labels):
        return False
    if labels[-1] in FILE_EXTENSIONS:
        return False
    return labels[-1] in KNOWN_TLDS


def mac_valid(s: str) -> bool:
    """Six hex octets separated consistently by colons or dashes."""
    return MAC_RE.fullmatch(s.strip()) is not None


def vin_valid(s: str) -> bool:
    """ISO 3779 vehicle identification number with check digit at position nine."""
    compact = s.strip().upper()
    if VIN_RE.fullmatch(compact) is None:
        return False
    total = sum(VIN_VALUES[char] * weight for char, weight in zip(compact, VIN_WEIGHTS, strict=True))
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return compact[8] == expected


def phone_valid(s: str) -> bool:
    """Seven to fifteen digits, only dialling punctuation around them."""
    if PHONE_RE.fullmatch(s.strip()) is None:
        return False
    return 7 <= sum(char.isdigit() for char in s) <= 15


def date_valid(s: str) -> bool:
    """A real calendar date in DD.MM.YYYY, DD/MM/YYYY or YYYY-MM-DD between 1900 and 2100."""
    match = DATE_RE.fullmatch(s.strip())
    if match is None:
        return False
    if match.group(1) is not None:
        day, month, year = int(match.group(1)), int(match.group(3)), int(match.group(4))
    else:
        year, month, day = int(match.group(5)), int(match.group(6)), int(match.group(7))
    if not MIN_YEAR <= year <= MAX_YEAR:
        return False
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def tax_id_valid(s: str) -> bool:
    """German Steuer-ID check digit, or an EU VAT identifier shape."""
    compact = s.replace(" ", "").upper()
    if compact.isdigit():
        return len(compact) == 11 and _de_tax_check(compact)
    if VAT_RE.fullmatch(compact) is None:
        return False
    return compact[:2] in COUNTRY_CODES


def ssn_valid(s: str) -> bool:
    """German SV-Nummer check digit, or a plausible US social security number."""
    compact = re.sub(r"[ \-]", "", s.strip().upper())
    if DE_SSN_RE.fullmatch(compact) is not None:
        return _de_ssn_check(compact)
    if US_SSN_RE.fullmatch(compact) is None:
        return False
    area, group, serial = compact[:3], compact[3:5], compact[5:]
    return area not in ("000", "666") and area[0] != "9" and group != "00" and serial != "0000"


def _de_tax_check(digits: str) -> bool:
    product = 10
    for char in digits[:10]:
        total = (int(char) + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    return (11 - product) % 10 == int(digits[10])


def _de_ssn_check(compact: str) -> bool:
    expanded = "".join(
        f"{ord(char) - ord('A') + 1:02d}" if char.isalpha() else char for char in compact[:11]
    )
    total = 0
    for char, weight in zip(expanded, DE_SSN_WEIGHTS, strict=True):
        product = int(char) * weight
        total += product // 10 + product % 10
    return total % 10 == int(compact[11])


VALIDATORS: dict[str, Callable[[str], bool]] = {
    "luhn": luhn_valid,
    "iban": iban_valid,
    "bic": bic_valid,
    "ip": ip_valid,
    "mac": mac_valid,
    "vin": vin_valid,
    "phone": phone_valid,
    "date": date_valid,
    "tax_id": tax_id_valid,
    "ssn": ssn_valid,
    "fqdn": fqdn_valid,
}
