import pytest

import fire
import olympus
from olympus.gateway.settings import GatewaySettings


def test_fire_facade_reports_the_deployed_version() -> None:
    assert fire.__version__ == olympus.__version__


def test_fire_environment_prefix_is_canonical(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FIRE_ENVIRONMENT", "test")
    monkeypatch.setenv("FIRE_DEV_COMMAND_TOKEN", "x" * 32)

    settings = GatewaySettings(_env_file=None)

    assert settings.environment == "test"
    assert settings.dev_command_token.get_secret_value() == "x" * 32


def test_legacy_environment_prefix_remains_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OLYMPUS_ENVIRONMENT", "test")
    monkeypatch.setenv("OLYMPUS_DEV_COMMAND_TOKEN", "x" * 32)

    settings = GatewaySettings(_env_file=None)

    assert settings.environment == "test"


def test_conflicting_brand_environment_values_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FIRE_ENVIRONMENT", "test")
    monkeypatch.setenv("OLYMPUS_ENVIRONMENT", "development")

    with pytest.raises(ValueError, match="conflicting Fire and legacy Olympus"):
        GatewaySettings(_env_file=None, dev_command_token="x" * 32)
