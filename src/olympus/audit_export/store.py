import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


class ObjectAlreadyExists(Exception):
    """Raised when a write-once key is written a second time."""


class ObjectStoreError(Exception):
    """Raised when the backing object store refuses or fails a request."""


@dataclass(frozen=True)
class StoredObject:
    """Who a stored object actually is, as the store reports it.

    A signature that named only the key would still cover a rolled-back
    version of that key, so the version ID travels with every write and is
    bound into the attestation. The retention fields come back for the same
    reason: "this was sealed" is a claim worth signing, and a claim worth
    signing has to be observed rather than assumed.
    """

    key: str
    version_id: str
    retention_mode: str
    retention_until: str


class WriteOnceObjectStore(Protocol):
    """The narrow storage surface audit export needs.

    Deliberately smaller than S3: export must never gain the ability to
    delete, overwrite, or shorten retention, so those verbs have no method
    here to call.
    """

    async def put_once(self, key: str, body: bytes) -> StoredObject:
        """Store ``body`` at ``key``, refusing to replace an existing object."""
        ...

    async def get(self, key: str) -> bytes | None: ...

    async def head(self, key: str) -> StoredObject | None: ...

    async def list_keys(self, prefix: str) -> tuple[str, ...]: ...


@dataclass
class InMemoryWriteOnceStore:
    """A fake with Object Lock's one property that matters: no overwrite.

    Tests need to prove the exporter behaves correctly against immutability,
    and a fake that silently allows overwrite would let a regression pass.
    """

    objects: dict[str, bytes] = field(default_factory=dict)
    identities: dict[str, StoredObject] = field(default_factory=dict)
    retention_mode: str = "GOVERNANCE"
    retention_until: str = "2099-01-01T00:00:00+00:00"

    async def put_once(self, key: str, body: bytes) -> StoredObject:
        if key in self.objects:
            raise ObjectAlreadyExists(key)
        self.objects[key] = body
        # A stable, content-derived version id keeps the fake deterministic
        # while still being distinct per object, so a test that swaps two
        # objects' identities produces a real mismatch rather than a match.
        identity = StoredObject(
            key=key,
            version_id=hashlib.sha256(key.encode("utf-8") + body).hexdigest()[:32],
            retention_mode=self.retention_mode,
            retention_until=self.retention_until,
        )
        self.identities[key] = identity
        return identity

    async def get(self, key: str) -> bytes | None:
        return self.objects.get(key)

    async def head(self, key: str) -> StoredObject | None:
        return self.identities.get(key)

    async def list_keys(self, prefix: str) -> tuple[str, ...]:
        return tuple(sorted(key for key in self.objects if key.startswith(prefix)))


class S3ObjectLockStore:
    """S3 with Object Lock retention, used through a write-once surface.

    Retention comes from the bucket's default Object Lock rule, not from the
    write. Naming a retention on PutObject requires ``s3:PutObjectRetention``,
    and that is precisely the permission that lets a caller set a *shorter*
    retention. An exporter that can state its own retention can weaken it, so
    the exporter states none and holds no such permission.

    ``assert_retention_configured`` exists because relying on the bucket
    default makes a misconfigured bucket silently accept unprotected writes.
    Checking once at startup turns that into a loud failure.
    """

    def __init__(
        self,
        *,
        bucket: str,
        client: Any,
        expected_retention_days: int | None = None,
        expected_retention_mode: str | None = None,
    ) -> None:
        if expected_retention_days is not None and expected_retention_days < 1:
            raise ValueError("expected_retention_days must be at least one day")
        if expected_retention_mode is not None and expected_retention_mode not in {
            "COMPLIANCE",
            "GOVERNANCE",
        }:
            raise ValueError("expected_retention_mode must be COMPLIANCE or GOVERNANCE")
        self._bucket = bucket
        self._client = client
        self._expected_days = expected_retention_days
        self._expected_mode = expected_retention_mode

    async def assert_retention_configured(self) -> tuple[str, int]:
        """Confirm the bucket really does seal what this exporter writes."""
        import asyncio

        def _read() -> dict[str, Any]:
            response: dict[str, Any] = self._client.get_object_lock_configuration(
                Bucket=self._bucket
            )
            return response

        try:
            configuration = await asyncio.to_thread(_read)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            raise ObjectStoreError(
                f"{self._bucket} has no readable Object Lock configuration"
            ) from exc

        rule = configuration.get("ObjectLockConfiguration", {}).get("Rule", {})
        retention = rule.get("DefaultRetention", {})
        mode = retention.get("Mode")
        days = retention.get("Days")
        if not mode or not days:
            raise ObjectStoreError(
                f"{self._bucket} has no default Object Lock retention; "
                "exported audit segments would not be sealed"
            )
        if self._expected_mode is not None and mode != self._expected_mode:
            raise ObjectStoreError(
                f"{self._bucket} retention mode is {mode}, expected {self._expected_mode}"
            )
        if self._expected_days is not None and int(days) < self._expected_days:
            raise ObjectStoreError(
                f"{self._bucket} retains for {days} days, expected at least {self._expected_days}"
            )
        return str(mode), int(days)

    @property
    def bucket(self) -> str:
        return self._bucket

    async def head(self, key: str) -> StoredObject | None:
        import asyncio

        def _head() -> StoredObject | None:
            try:
                response = self._client.head_object(Bucket=self._bucket, Key=key)
            except Exception as exc:  # noqa: BLE001 - mapped below
                if _is_not_found(exc):
                    return None
                raise
            return _identity_from_response(key, response)

        try:
            return await asyncio.to_thread(_head)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            raise ObjectStoreError(f"failed to head {key}") from exc

    async def put_once(self, key: str, body: bytes) -> StoredObject:
        import asyncio

        if await self.get(key) is not None:
            raise ObjectAlreadyExists(key)
        checksum = hashlib.sha256(body).digest()
        import base64

        def _put() -> dict[str, Any]:
            response: dict[str, Any] = self._client.put_object(
                Bucket=self._bucket,
                Key=key,
                Body=body,
                # S3 verifies this itself, so a body corrupted in transit is
                # rejected by the store rather than sealed under retention.
                ChecksumSHA256=base64.b64encode(checksum).decode("ascii"),
                # No ObjectLock* arguments: the bucket default seals this
                # object, and asking for retention here would require the
                # permission that can also reduce it.
                IfNoneMatch="*",
            )
            return response

        try:
            response = await asyncio.to_thread(_put)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            if _is_precondition_failure(exc):
                raise ObjectAlreadyExists(key) from exc
            raise ObjectStoreError(f"failed to write {key}") from exc

        identity = _identity_from_response(key, response)
        if identity.retention_mode and identity.retention_until:
            return identity
        # PutObject does not echo the retention the bucket default applied, so
        # read it back. This is not bookkeeping: the attestation is about to
        # assert that this object is sealed, and asserting it without having
        # observed it would make the signature attest to a guess.
        observed = await self.head(key)
        if observed is None:
            raise ObjectStoreError(f"wrote {key} but cannot read back its identity")
        if not observed.retention_mode or not observed.retention_until:
            raise ObjectStoreError(
                f"{key} was stored without Object Lock retention; "
                "refusing to attest that an unsealed object is sealed"
            )
        return observed

    async def get(self, key: str) -> bytes | None:
        import asyncio

        def _get() -> bytes | None:
            try:
                response = self._client.get_object(Bucket=self._bucket, Key=key)
            except Exception as exc:  # noqa: BLE001 - mapped below
                if _is_not_found(exc):
                    return None
                raise
            body: bytes = response["Body"].read()
            return body

        try:
            return await asyncio.to_thread(_get)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            raise ObjectStoreError(f"failed to read {key}") from exc

    async def list_keys(self, prefix: str) -> tuple[str, ...]:
        import asyncio

        def _list() -> tuple[str, ...]:
            keys: list[str] = []
            token: str | None = None
            while True:
                kwargs: dict[str, Any] = {"Bucket": self._bucket, "Prefix": prefix}
                if token:
                    kwargs["ContinuationToken"] = token
                response = self._client.list_objects_v2(**kwargs)
                keys.extend(item["Key"] for item in response.get("Contents", ()))
                if not response.get("IsTruncated"):
                    break
                token = response.get("NextContinuationToken")
            return tuple(sorted(keys))

        try:
            return await asyncio.to_thread(_list)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            raise ObjectStoreError(f"failed to list {prefix}") from exc


def _identity_from_response(key: str, response: dict[str, Any]) -> StoredObject:
    # boto3 hands back a datetime here, but the attestation has to be a stable
    # string: ISO-8601 has one spelling, and repr() of a datetime does not.
    retain_until: Any = response.get("ObjectLockRetainUntilDate")
    if isinstance(retain_until, datetime):
        retention_until = retain_until.isoformat()
    else:
        retention_until = str(retain_until) if retain_until else ""
    return StoredObject(
        key=key,
        version_id=str(response.get("VersionId") or ""),
        retention_mode=str(response.get("ObjectLockMode") or ""),
        retention_until=retention_until,
    )


def _error_code(exc: Exception) -> str:
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = response.get("Error", {}).get("Code", "")
        return str(code)
    return ""


def _is_not_found(exc: Exception) -> bool:
    return _error_code(exc) in {"NoSuchKey", "404", "NotFound"}


def _is_precondition_failure(exc: Exception) -> bool:
    return _error_code(exc) in {"PreconditionFailed", "412"}
