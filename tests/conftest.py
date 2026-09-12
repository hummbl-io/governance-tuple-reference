"""Shared test fixtures for governance-tuple-reference.

Moves the ENABLE_IDP environment variable setup out of module-level
import-time code and into a session-scoped autouse fixture. This
prevents the os.environ side effect from leaking across test modules
when pytest collects them in unpredictable order. See #2.
"""

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _enable_idp() -> None:
    os.environ["ENABLE_IDP"] = "true"
    yield
    os.environ.pop("ENABLE_IDP", None)
