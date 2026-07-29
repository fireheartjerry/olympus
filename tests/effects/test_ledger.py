import pytest

from olympus.effects.ledger import (
    EffectExecutor,
    EffectIntent,
    EffectLedger,
    EffectState,
    FakeEffectProvider,
    UnknownCompletion,
)


def intent(**overrides: object) -> EffectIntent:
    values: dict[str, object] = {
        "effect_id": "effect-1",
        "idempotency_key": "job-1:gmail.send:message-1",
        "adapter": "gmail",
        "operation": "send",
        "payload": {"to": "person@example.com", "body": "hello"},
        "compensatable": True,
    }
    values.update(overrides)
    return EffectIntent(**values)  # type: ignore[arg-type]


def test_confirmed_retry_returns_receipt_without_duplicate_provider_effect() -> None:
    provider = FakeEffectProvider()
    executor = EffectExecutor(EffectLedger(), {"gmail": provider})
    candidate = intent()

    first = executor.execute(candidate)
    second = executor.execute(candidate)

    assert first == second
    assert first.state is EffectState.CONFIRMED
    assert provider.apply_count == 1


def test_uncertain_completion_reconciles_before_any_retry() -> None:
    provider = FakeEffectProvider(raise_after_apply=True)
    executor = EffectExecutor(EffectLedger(), {"gmail": provider})
    candidate = intent()

    with pytest.raises(UnknownCompletion):
        executor.execute(candidate)
    receipt = executor.reconcile(candidate.effect_id)

    assert receipt.state is EffectState.CONFIRMED
    assert provider.apply_count == 1
    assert executor.execute(candidate) == receipt
    assert provider.apply_count == 1


def test_idempotency_key_payload_mismatch_is_denied() -> None:
    executor = EffectExecutor(EffectLedger(), {"gmail": FakeEffectProvider()})
    executor.execute(intent())

    with pytest.raises(ValueError, match="different payload"):
        executor.execute(intent(effect_id="effect-2", payload={"body": "altered"}))


def test_compensation_is_recorded_and_idempotent() -> None:
    provider = FakeEffectProvider()
    executor = EffectExecutor(EffectLedger(), {"gmail": provider})
    receipt = executor.execute(intent())

    compensated = executor.compensate(receipt.effect_id)
    repeated = executor.compensate(receipt.effect_id)

    assert compensated.state is EffectState.COMPENSATED
    assert repeated == compensated
    assert provider.compensation_count == 1
