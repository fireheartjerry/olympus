import json
from pathlib import Path

ROOT = Path(__file__).parents[2]
AWS = ROOT / "deploy" / "aws"
BACKUP = "arn:aws:s3:::olympus-audit-export-892077329800/backups/temporal/*"


def _policy(name: str) -> dict[str, object]:
    value = json.loads((AWS / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _statements(policy: dict[str, object]) -> list[dict[str, object]]:
    value = policy["Statement"]
    assert isinstance(value, list)
    assert all(isinstance(statement, dict) for statement in value)
    return value


def _actions(statement: dict[str, object]) -> set[str]:
    value = statement["Action"]
    return {value} if isinstance(value, str) else set(value)


def _resources(statement: dict[str, object]) -> set[str]:
    value = statement["Resource"]
    return {value} if isinstance(value, str) else set(value)


def test_temporal_writes_require_explicit_aes256() -> None:
    statements = _statements(_policy("olympus-audit-exporter-inline.json"))
    backup_writes = [
        statement
        for statement in statements
        if statement["Effect"] == "Allow"
        and "s3:PutObject" in _actions(statement)
        and BACKUP in _resources(statement)
    ]

    assert len(backup_writes) == 1
    assert backup_writes[0]["Condition"] == {
        "StringEquals": {"s3:x-amz-server-side-encryption": "AES256"}
    }


def test_temporal_read_surface_is_bounded_to_versions_and_lock_metadata() -> None:
    inline = _statements(_policy("olympus-audit-exporter-inline.json"))
    managed = _statements(_policy("olympus-audit-exporter-managed.json"))
    allowed = set().union(
        *(
            _actions(statement)
            for statement in inline + managed
            if statement["Effect"] == "Allow" and BACKUP in _resources(statement)
        )
    )

    assert allowed == {
        "s3:PutObject",
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectRetention",
        "s3:GetObjectLegalHold",
    }


def test_bucket_wide_denies_cover_destructive_backup_actions() -> None:
    policies = (
        _policy("olympus-audit-exporter-inline.json"),
        _policy("olympus-audit-exporter-managed.json"),
    )
    denied = set().union(
        *(
            _actions(statement)
            for policy in policies
            for statement in _statements(policy)
            if statement["Effect"] == "Deny"
        )
    )

    assert {
        "s3:DeleteObject",
        "s3:DeleteObjectVersion",
        "s3:PutObjectRetention",
        "s3:PutObjectLegalHold",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutLifecycleConfiguration",
        "s3:BypassGovernanceRetention",
    } <= denied


def test_policy_documents_fit_iam_quotas_without_wildcard_allows() -> None:
    inline = _policy("olympus-audit-exporter-inline.json")
    managed = _policy("olympus-audit-exporter-managed.json")

    assert len(json.dumps(inline, separators=(",", ":"))) <= 2048
    assert len(json.dumps(managed, separators=(",", ":"))) <= 6144
    for policy in (inline, managed):
        for statement in _statements(policy):
            if statement["Effect"] == "Allow":
                assert statement["Action"] != "*"
                assert statement["Resource"] != "*"
