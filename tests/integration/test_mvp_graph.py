from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from nacl.signing import SigningKey

from olympus.broker.root import (
    BrokerRequest,
    FakeHostExecutor,
    SignedBrokerRequest,
    TypedRootBroker,
)
from olympus.contracts.commands import TrustLabel as CommandTrustLabel
from olympus.effects.ledger import EffectExecutor, EffectIntent, EffectLedger, FakeEffectProvider
from olympus.governance.authorization import (
    Action,
    ActionClass,
    AuthorizationEngine,
    BudgetGovernor,
    TaintedValue,
    TrustLabel,
)
from olympus.governance.policy import PolicyBundle, PolicyKernel, SignedPolicyRelease
from olympus.graphs.compiler import compile_execution_graph
from olympus.graphs.models import GraphNode
from olympus.integrations.shadow import FakeReadOnlyAdapter, IntegrationRequest, ShadowModeRunner
from olympus.persistence.ownership import InMemoryArtifactPlane
from olympus.workers.admission import (
    AdmissionController,
    ResourceEnvelope,
    SystemMode,
    WorkerClass,
    WorkerRequest,
    WorkPriority,
)
from olympus.workers.local_autonomy import LocalAutonomyRunner, LocalTask, ScriptedLocalBackend

NOW = datetime(2026, 7, 29, tzinfo=UTC)


def test_governed_mvp_path_reaches_fake_effects_with_complete_boundaries() -> None:
    policy_key = SigningKey.generate()
    bundle = PolicyBundle(
        release_id="mvp-policy-1",
        sequence=1,
        issued_at=NOW,
        expires_at=NOW + timedelta(days=30),
        policies={
            "authorization": {"default": "deny"},
            "trust": {"transitive": True},
            "approval": {"literal_payload_binding": True},
            "budget": {"monthly_variable_usd": 50},
            "root_broker": {"typed_only": True},
        },
    )
    payload = bundle.canonical_bytes()
    active_policy = PolicyKernel(
        verification_keys={"offline-root": bytes(policy_key.verify_key)},
        activation_principal="policy-release-service",
        activation_approval_verifier=lambda _: True,
    ).verify_and_activate(
        SignedPolicyRelease(
            "offline-root",
            payload,
            policy_key.sign(payload).signature,
        ),
        principal="policy-release-service",
        now=NOW,
    )
    assert active_policy.release_id == "mvp-policy-1"

    authorization = AuthorizationEngine(BudgetGovernor(monthly_ceiling_usd=Decimal("50")))
    local_action = Action(
        action_id="action-local-code",
        kind="code.generate",
        classification=ActionClass.AUTONOMOUS,
        payload={"job_id": "job-mvp"},
        variable_cost_usd=Decimal("0"),
        inputs=(TaintedValue("operator command", frozenset({TrustLabel.OPERATOR})),),
    )
    assert authorization.authorize(local_action, now=NOW).allowed

    graph = compile_execution_graph(
        job_id="job-mvp",
        nodes=(
            GraphNode(
                "reason",
                "langgraph.activity.reason",
                (),
                False,
                (CommandTrustLabel.USER_AUTHORIZED,),
            ),
            GraphNode(
                "code",
                "worker.codex",
                ("reason",),
                False,
                (CommandTrustLabel.USER_AUTHORIZED,),
            ),
            GraphNode(
                "verify",
                "worker.verifier",
                ("code",),
                False,
                (CommandTrustLabel.USER_AUTHORIZED,),
            ),
        ),
        maximum_nodes=8,
        maximum_fan_out=2,
    )
    assert len(graph.nodes) == 3

    admission = AdmissionController(
        capacity=ResourceEnvelope(3500, 8704),
        mode=SystemMode.NORMAL,
        concurrency={worker: 2 for worker in WorkerClass},
    )
    worker = admission.admit(
        WorkerRequest(
            "worker-request-1",
            "job-mvp",
            WorkerClass.CODEX,
            "worktree-job-mvp",
            "artifacts/job-mvp/",
            500,
            1024,
            WorkPriority.NORMAL,
        )
    )
    local = LocalAutonomyRunner(
        workspace_root=Path("/workspace"),
        backend=ScriptedLocalBackend(outputs=[b"verified implementation"], verdicts=[True]),
        maximum_revisions=2,
    ).run(
        LocalTask(
            "task-code",
            "job-mvp",
            "code.generate",
            "worktrees/job-mvp",
            "implement the plan",
        )
    )
    artifact = InMemoryArtifactPlane().put(
        "job-mvp",
        "implementation.txt",
        local.artifact,
        "text/plain",
    )
    admission.release(worker.isolation_token)
    assert len(artifact.digest) == 64

    shadow_adapter = FakeReadOnlyAdapter("github", {"repository": "olympus"})
    projection = ShadowModeRunner({"github": shadow_adapter}).run(
        IntegrationRequest(
            "project-pr",
            "github",
            "open_pull_request",
            {"repository": "olympus"},
            True,
        )
    )
    assert projection.effect == "projected-only"
    assert shadow_adapter.mutation_count == 0

    provider = FakeEffectProvider()
    effect = EffectExecutor(EffectLedger(), {"github": provider}).execute(
        EffectIntent(
            "effect-pr",
            "job-mvp:github.pr",
            "github",
            "open_pull_request",
            {"artifact_digest": artifact.digest},
            True,
        )
    )
    assert effect.provider_receipt == "provider-effect-pr"

    broker_key = SigningKey.generate()
    host = FakeHostExecutor()
    broker = TypedRootBroker(
        verification_key=bytes(broker_key.verify_key),
        orchestrator_uid=1001,
        executor=host,
        allowed_services=frozenset({"olympus-worker"}),
    )
    broker_request = BrokerRequest(
        "broker-1",
        "nonce-1",
        "service.restart",
        {"service": "olympus-worker"},
        NOW,
        NOW + timedelta(minutes=1),
    )
    broker.execute(
        SignedBrokerRequest(
            broker_request,
            broker_key.sign(broker_request.canonical_bytes()).signature,
        ),
        peer_uid=1001,
        now=NOW,
    )
    assert host.calls == [("service.restart", {"service": "olympus-worker"})]
    assert authorization.audit.verify()
