"""Shared pytest fixtures for governance tuple tests.

Replaces the module-level `os.environ["ENABLE_IDP"] = "true"` side-effect
that previously leaked across test modules (issue #2). The autouse fixture
sets the env var for each test and restores the original value afterward,
so tests are isolated and don't mutate global state at import time.
"""

import os

import pytest


@pytest.fixture(autouse=True)
def _enable_idp(monkeypatch):
    """Enable governance enforcement for every test, restored after.

    Uses monkeypatch so the env var is automatically restored to its
    original value when the test completes — no leakage across modules.
    """
    monkeypatch.setenv("ENABLE_IDP", "true")
    yield
