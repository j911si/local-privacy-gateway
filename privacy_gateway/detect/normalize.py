"""Text normalization with an offset map back onto the original text."""

from __future__ import annotations

import unicodedata

from privacy_gateway.model import Span

# Clusters longer than this skip NFC: canonical ordering is quadratic in the cluster length, and
# no letter of any script needs more combining marks than this.
MAX_CLUSTER = 32
# Default-ignorable characters outside "Cf": the combining grapheme joiner and the variation
# selectors. Python reports them as combining class 0, so they would otherwise split a cluster.
IGNORABLE = frozenset({"\u034f", *(chr(code) for code in range(0xFE00, 0xFE10))})
# Fullwidth ASCII (U+FF01..U+FF5E) folds one to one onto ASCII, so the offset map stays exact.
FULLWIDTH_OFFSET = 0xFF01 - 0x21


def _ignorable(char: str) -> bool:
    return char in IGNORABLE or unicodedata.category(char) == "Cf"


def _fold(char: str) -> str:
    code = ord(char)
    return chr(code - FULLWIDTH_OFFSET) if 0xFF01 <= code <= 0xFF5E else char


class OffsetMap:
    """Normalized text plus, per normalized character, the original cluster it came from."""

    def __init__(self, text: str) -> None:
        chars: list[str] = []
        self.starts: list[int] = []
        self.ends: list[int] = []
        index = 0
        while index < len(text):
            char = text[index]
            if _ignorable(char):
                # ponytail: "Cf" already covers U+00AD and every zero-width character.
                index += 1
                continue
            cluster = [char]
            cluster_end = index + 1
            while cluster_end < len(text):
                follower = text[cluster_end]
                if unicodedata.combining(follower):
                    cluster.append(follower)
                elif not _ignorable(follower):
                    break
                cluster_end += 1
            if unicodedata.category(char) == "Zs":
                # ponytail: a spacing separator never carries combining marks.
                chunk = " "
            elif len(cluster) > MAX_CLUSTER:
                chunk = "".join(cluster)
            else:
                chunk = unicodedata.normalize("NFC", _fold(char) + "".join(cluster[1:]))
            chars.extend(chunk)
            self.starts.extend([index] * len(chunk))
            self.ends.extend([cluster_end] * len(chunk))
            index = cluster_end
        self.text = "".join(chars)

    def original(self, span: Span) -> Span:
        """The span of the original text that a normalized span came from."""
        return Span(self.starts[span.start], self.ends[span.end - 1])


def offset_map(text: str) -> OffsetMap | None:
    """Return the map, or None when the text needs no normalization."""
    if text.isascii():
        # ponytail: every character we would touch is non-ASCII.
        return None
    mapping = OffsetMap(text)
    return None if mapping.text == text else mapping


def normalized(text: str) -> str:
    """The text after normalization."""
    mapping = offset_map(text)
    return text if mapping is None else mapping.text
