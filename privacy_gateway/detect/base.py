"""Protocol every detection stage implements."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from privacy_gateway.model import Finding

if TYPE_CHECKING:
    from privacy_gateway.config import Config


@runtime_checkable
class Stage(Protocol):
    """A detection stage that adds findings to the ones earlier stages produced."""

    name: str

    def run(self, text: str, config: Config, findings: list[Finding]) -> list[Finding]:
        """Return only NEW findings. `findings` = everything emitted by earlier stages."""
        ...
