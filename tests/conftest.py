"""Shared test fixtures for Vigil Security."""

import pytest
from vigil.config import VigilConfig


@pytest.fixture
def default_config():
    return VigilConfig()
