from __future__ import annotations

import pytest

from privacy_gateway.config import Config, load_config

SKIP_USER_CONFIG_ENV = {"PGW_SKIP_USER_CONFIG": "1"}


@pytest.fixture
def default_config() -> Config:
    """Bundled defaults only; the user's ~/.config file is ignored."""
    return load_config(env=SKIP_USER_CONFIG_ENV)
