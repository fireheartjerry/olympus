import hashlib
import json
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Protocol


class UnknownCompletion(RuntimeError):
    pass


class EffectState(StrEnum):
    PENDING = "pending"
    CONFIRMED = "confirmed"
    UNCERTAIN = "uncertain"
    FAILED = "failed"
    COMPENSATED = "compensated"


@dataclass(frozen=True)
class EffectIntent:
    effect_id: str
    idempotency_key: str
    adapter: str
    operation: str
    payload: dict[str, object]
    compensatable: bool

    def __post_init__(self) -> None:
        values = (self.effect_id, self.idempotency_key, self.adapter, self.operation)
        if any(not value.strip() for value in values):
            raise ValueError("effect identity, dedupe key, adapter, and operation are required")

    def payload_digest(self) -> str:
        return hashlib.sha256(
            json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()


@dataclass(frozen=True)
class EffectReceipt:
    effect_id: str
    idempotency_key: str
    payload_digest: str
    adapter: str
    operation: str
    compensatable: bool
    state: EffectState
    provider_receipt: str | None = None


class EffectProvider(Protocol):
    def apply(self, intent: EffectIntent) -> str: ...

    def lookup(self, idempotency_key: str) -> str | None: ...

    def compensate(self, receipt: EffectReceipt) -> None: ...


class EffectLedger:
    def __init__(self) -> None:
        self._by_id: dict[str, EffectReceipt] = {}
        self._by_key: dict[str, str] = {}

    def reserve(self, intent: EffectIntent) -> tuple[EffectReceipt, bool]:
        digest = intent.payload_digest()
        existing_id = self._by_key.get(intent.idempotency_key)
        if existing_id is not None:
            existing = self._by_id[existing_id]
            if existing.payload_digest != digest:
                raise ValueError("idempotency key was reused with a different payload")
            return existing, False
        if intent.effect_id in self._by_id:
            raise ValueError("effect identity was reused")
        receipt = EffectReceipt(
            effect_id=intent.effect_id,
            idempotency_key=intent.idempotency_key,
            payload_digest=digest,
            adapter=intent.adapter,
            operation=intent.operation,
            compensatable=intent.compensatable,
            state=EffectState.PENDING,
        )
        self._by_id[receipt.effect_id] = receipt
        self._by_key[receipt.idempotency_key] = receipt.effect_id
        return receipt, True

    def get(self, effect_id: str) -> EffectReceipt:
        try:
            return self._by_id[effect_id]
        except KeyError as exc:
            raise ValueError("effect does not exist") from exc

    def transition(
        self,
        effect_id: str,
        state: EffectState,
        *,
        provider_receipt: str | None = None,
    ) -> EffectReceipt:
        current = self.get(effect_id)
        updated = replace(
            current,
            state=state,
            provider_receipt=provider_receipt or current.provider_receipt,
        )
        self._by_id[effect_id] = updated
        return updated


class EffectExecutor:
    def __init__(
        self,
        ledger: EffectLedger,
        providers: dict[str, EffectProvider],
    ) -> None:
        self._ledger = ledger
        self._providers = dict(providers)

    def execute(self, intent: EffectIntent) -> EffectReceipt:
        receipt, created = self._ledger.reserve(intent)
        if not created:
            if receipt.state is EffectState.UNCERTAIN:
                raise UnknownCompletion("effect must be reconciled before retry")
            return receipt
        provider = self._provider(intent.adapter)
        try:
            provider_receipt = provider.apply(intent)
        except UnknownCompletion:
            self._ledger.transition(intent.effect_id, EffectState.UNCERTAIN)
            raise
        return self._ledger.transition(
            intent.effect_id,
            EffectState.CONFIRMED,
            provider_receipt=provider_receipt,
        )

    def reconcile(self, effect_id: str) -> EffectReceipt:
        receipt = self._ledger.get(effect_id)
        if receipt.state is not EffectState.UNCERTAIN:
            return receipt
        provider_receipt = self._provider(receipt.adapter).lookup(receipt.idempotency_key)
        if provider_receipt is None:
            return self._ledger.transition(effect_id, EffectState.FAILED)
        return self._ledger.transition(
            effect_id,
            EffectState.CONFIRMED,
            provider_receipt=provider_receipt,
        )

    def compensate(self, effect_id: str) -> EffectReceipt:
        receipt = self._ledger.get(effect_id)
        if receipt.state is EffectState.COMPENSATED:
            return receipt
        if receipt.state is not EffectState.CONFIRMED or not receipt.compensatable:
            raise ValueError("effect is not compensatable in its current state")
        self._provider(receipt.adapter).compensate(receipt)
        return self._ledger.transition(effect_id, EffectState.COMPENSATED)

    def _provider(self, adapter: str) -> EffectProvider:
        try:
            return self._providers[adapter]
        except KeyError as exc:
            raise ValueError("effect adapter is not registered") from exc


class FakeEffectProvider:
    def __init__(self, *, raise_after_apply: bool = False) -> None:
        self._raise_after_apply = raise_after_apply
        self._effects: dict[str, str] = {}
        self.apply_count = 0
        self.compensation_count = 0

    def apply(self, intent: EffectIntent) -> str:
        existing = self._effects.get(intent.idempotency_key)
        if existing is not None:
            return existing
        self.apply_count += 1
        receipt = f"provider-{intent.effect_id}"
        self._effects[intent.idempotency_key] = receipt
        if self._raise_after_apply:
            raise UnknownCompletion("provider response was lost after applying effect")
        return receipt

    def lookup(self, idempotency_key: str) -> str | None:
        return self._effects.get(idempotency_key)

    def compensate(self, receipt: EffectReceipt) -> None:
        self.compensation_count += 1
