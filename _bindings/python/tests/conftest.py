"""Pytest configuration for masktunnel tests."""

import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--integration-tests",
        action="store_true",
        default=False,
        help="run integration tests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "integration_tests: mark test as integration test")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--integration-tests"):
        return

    skip_mark = pytest.mark.skip(reason="need --integration-tests option to run")
    for item in items:
        if "integration_tests" in item.keywords:
            item.add_marker(skip_mark)
