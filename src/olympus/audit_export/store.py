import hashlib
from dataclasses import dataclass, field
from typing import Any, Protocol


class ObjectAlreadyExists(Exception):
    """Raised when a write-once key is written a second time."""


class ObjectStoreError(Exception):
    """Raised when the backing object store refuses or fails a request."""


class WriteOnceObjectStore(Protocol):
    """The narrow storage surface audit export needs.

    Deliberately smaller than S3: export must never gain the ability to
    delete, overwrite, or shorten retention, so those verbs have no method
    here to call.
    """

    async def put_once(self, key: str, body: bytes) -> None:
        """Store ``body`` at ``key``, refusing to replace an existing object."""
        ...

    async def get(self, key: str) -> bytes | None: ...

    async def list_keys(self, prefix: str) -> tuple[str, ...]: ...


@dataclass
class InMemoryWriteOnceStore:
    """A fake with Object Lock's one property that matters: no overwrite.

    Tests need to prove the exporter behaves correctly against immutability,
    and a fake that silently allows overwrite would let a regression pass.
    """

    objects: dict[str, bytes] = field(default_factory=dict)

    async def put_once(self, key: str, body: bytes) -> None:
        if key in self.objects:
            raise ObjectAlreadyExists(key)
        self.objects[key] = body

    async def get(self, key: str) -> bytes | None:
        return self.objects.get(key)

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

    async def put_once(self, key: str, body: bytes) -> None:
        import asyncio

        if await self.get(key) is not None:
            raise ObjectAlreadyExists(key)
        checksum = hashlib.sha256(body).digest()
        import base64

        def _put() -> None:
            self._client.put_object(
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

        try:
            await asyncio.to_thread(_put)
        except Exception as exc:  # noqa: BLE001 - surfaced as a typed failure
            if _is_precondition_failure(exc):
                raise ObjectAlreadyExists(key) from exc
            raise ObjectStoreError(f"failed to write {key}") from exc

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
