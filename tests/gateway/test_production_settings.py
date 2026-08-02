from datetime import timedelta
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from olympus.gateway.production_settings import ProductionGatewaySettings


def valid_settings(**overrides: object) -> ProductionGatewaySettings:
    values: dict[str, object] = {
        "commander_id": "628053765181800448",
        "discord_application_public_key": SecretStr("a" * 64),
        "discord_guild_id": "111111111111111111",
        "discord_channel_ids": frozenset({"222222222222222222"}),
        "webauthn_origin": "https://olympus.tail-example.ts.net",
        "webauthn_rp_id": "olympus.tail-example.ts.net",
        "database_dsn": SecretStr("postgresql+asyncpg://olympus:test@db/olympus"),
        "emergency_latch_path": Path("/var/lib/olympus/emergency-freeze.json"),
        "emergency_latch_verification_key": SecretStr("b" * 64),
    }
    values.update(overrides)
    # _env_file=None so these tests describe the settings class, not whatever
    # .env.production happens to hold on the machine running them. Without it a
    # deployed host's real configuration silently overrides the fixture.
    return ProductionGatewaySettings(_env_file=None, **values)  # type: ignore[arg-type]


def test_accepts_exact_single_commander_and_private_https_origin() -> None:
    settings = valid_settings()

    assert settings.commander_id == "628053765181800448"
    assert settings.lease_ttl == timedelta(hours=24)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("commander_id", "123"),
        ("discord_guild_id", "guild-name"),
        ("discord_channel_ids", frozenset()),
        ("discord_channel_ids", frozenset({"channel-name"})),
        ("discord_application_public_key", SecretStr("a" * 63)),
        ("webauthn_origin", "http://olympus.tail-example.ts.net"),
        ("webauthn_origin", "https://localhost"),
        ("webauthn_origin", "https://other.tail-example.ts.net"),
        ("webauthn_rp_id", "*.tail-example.ts.net"),
        ("lease_ttl", timedelta(hours=24, microseconds=1)),
        ("emergency_latch_path", Path("relative/latch.json")),
    ],
)
def test_rejects_unsafe_production_settings(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        valid_settings(**{field: value})


def test_rejects_development_authentication_field() -> None:
    with pytest.raises(ValidationError):
        valid_settings(dev_command_token=SecretStr("x" * 32))


def test_explicit_tls_port_in_origin_is_not_part_of_the_rp_id() -> None:
    """A dedicated port is an origin detail, never a relying-party identity.

    WebAuthn scopes a credential to the RP ID, which is a bare domain and
    cannot carry a port; the port belongs to the origin the browser checks
    separately. Olympus binds its own TLS listener on a high port because 443
    and 8443 already belong to other services, so this is the production
    configuration, not a corner case. Validation that folded the port into the
    RP ID comparison would reject the real deployment.
    """
    settings = valid_settings(
        webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
        webauthn_rp_id="vps-41e741fc.tail70f263.ts.net",
        http_port=9443,
    )

    assert str(settings.webauthn_origin).rstrip("/") == (
        "https://vps-41e741fc.tail70f263.ts.net:9443"
    )
    assert settings.webauthn_rp_id == "vps-41e741fc.tail70f263.ts.net"
    assert settings.webauthn_origin.host == settings.webauthn_rp_id


def test_port_bearing_origin_still_requires_the_rp_id_to_equal_the_hostname() -> None:
    # The port must not become a loophole: everything else about the origin and
    # RP ID binding stays exactly as strict as it is without one.
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="tail70f263.ts.net",
            http_port=9443,
        )
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="vps-41e741fc.tail70f263.ts.net:9443",
            http_port=9443,
        )
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="http://vps-41e741fc.tail70f263.ts.net:9443",
            webauthn_rp_id="vps-41e741fc.tail70f263.ts.net",
            http_port=9443,
        )


def test_public_host_header_carries_the_port_but_the_rp_id_never_does() -> None:
    settings = valid_settings(
        webauthn_origin="https://vps-41e741fc.tail70f263.ts.net:9443",
        webauthn_rp_id="vps-41e741fc.tail70f263.ts.net",
        http_port=9443,
    )

    # These three are deliberately not the same string.
    assert settings.public_host_header == "vps-41e741fc.tail70f263.ts.net:9443"
    assert settings.webauthn_rp_id == "vps-41e741fc.tail70f263.ts.net"
    assert str(settings.webauthn_origin).rstrip("/").endswith(":9443")


def test_default_https_port_is_omitted_from_the_host_header() -> None:
    settings = valid_settings(
        webauthn_origin="https://olympus.tail-example.ts.net",
        webauthn_rp_id="olympus.tail-example.ts.net",
    )

    assert settings.public_host_header == "olympus.tail-example.ts.net"


def test_origin_port_must_match_the_port_actually_served() -> None:
    # Otherwise every ceremony fails the origin check with nothing to say why.
    with pytest.raises(ValidationError):
        valid_settings(
            webauthn_origin="https://olympus.tail-example.ts.net:9443",
            webauthn_rp_id="olympus.tail-example.ts.net",
            http_port=8443,
        )


@pytest.mark.parametrize("wildcard", ["0.0.0.0", "::", ""])  # noqa: S104 - asserting refusal
def test_wildcard_bind_address_is_refused(wildcard: str) -> None:
    # The enrollment page may only ever be reachable over the private tailnet.
    with pytest.raises(ValidationError):
        valid_settings(http_host=wildcard)


def test_tls_certificate_and_key_must_be_supplied_together() -> None:
    with pytest.raises(ValidationError):
        valid_settings(tls_certificate_path=Path("/etc/olympus/tls.crt"))
    with pytest.raises(ValidationError):
        valid_settings(tls_private_key_path=Path("/etc/olympus/tls.key"))


def test_tls_paths_must_be_absolute() -> None:
    with pytest.raises(ValidationError):
        valid_settings(
            tls_certificate_path=Path("tls.crt"),
            tls_private_key_path=Path("tls.key"),
        )


def test_bootstrap_enrollment_is_off_unless_explicitly_enabled() -> None:
    assert valid_settings().bootstrap_enabled is False
    assert valid_settings(bootstrap_enabled=True).bootstrap_enabled is True


def test_audit_export_needs_a_bucket_and_a_key_together() -> None:
    """Half a configuration is worse than none.

    A bucket without a signing key would export segments nobody can attribute;
    a key without a bucket exports nothing at all while looking configured.
    """
    with pytest.raises(ValidationError):
        valid_settings(audit_export_bucket="olympus-audit")
    with pytest.raises(ValidationError):
        valid_settings(audit_export_kms_key_id="arn:aws:kms:us-west-2:1:key/abc")

    settings = valid_settings(
        audit_export_bucket="olympus-audit",
        audit_export_kms_key_id="arn:aws:kms:us-west-2:1:key/abc",
    )
    assert settings.audit_export_bucket == "olympus-audit"


def test_audit_export_is_absent_by_default_so_development_needs_no_aws() -> None:
    settings = valid_settings()

    assert settings.audit_export_bucket is None
    assert settings.audit_export_kms_key_id is None


def test_audit_export_defaults_match_the_deployed_bucket() -> None:
    # GOVERNANCE, not COMPLIANCE — a deliberate, documented choice.
    settings = valid_settings()

    assert settings.audit_export_retention_mode == "GOVERNANCE"
    assert settings.audit_export_retention_days == 30


def test_audit_export_chain_must_be_named() -> None:
    with pytest.raises(ValidationError):
        valid_settings(
            audit_export_bucket="olympus-audit",
            audit_export_kms_key_id="arn:aws:kms:us-west-2:1:key/abc",
            audit_export_chain="   ",
        )
