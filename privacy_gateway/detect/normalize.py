"""Text normalization with an offset map back onto the original text."""

from __future__ import annotations

import unicodedata

from privacy_gateway.model import Span


class OffsetMap:
    """Normalized text plus, per normalized character, the original cluster it came from."""

    def __init__(self, text: str) -> None:
        chars: list[str] = []
        self.starts: list[int] = []
        self.ends: list[int] = []
        index = 0
        while index < len(text):
            char = text[index]
            if unicodedata.category(char) == "Cf":
                # ponytail: "Cf" already covers U+00AD and every zero-width character.
                index += 1
                continue
            cluster_end = index + 1
            while cluster_end < len(text) and unicodedata.combining(text[cluster_end]):
                cluster_end += 1
            if unicodedata.category(char) == "Zs":
                # ponytail: a spacing separator never carries combining marks.
                chunk = " "
            else:
                chunk = unicodedata.normalize("NFC", text[index:cluster_end])
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
