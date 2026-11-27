"""The one token shape every module of the library agrees on."""

from __future__ import annotations

import re

NUMBERED_TOKEN = re.compile(r"<(?P<name>(?P<label>[A-Z][A-Z0-9_]*?)_(?P<number>\d{3,}))>")
ANY_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]*?_(?:\d{3,}|REDACTED)>")
