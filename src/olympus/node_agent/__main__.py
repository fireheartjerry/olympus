import argparse
import asyncio
import json
import platform
import secrets
import sys
from pathlib import Path

from olympus.node_agent.agent import AGENT_VERSION, AgentIdentity, NodeAgent
from olympus.node_agent.capabilities import SystemInspectProvider
from olympus.node_agent.config import (
    CONFIG_VERSION,
    NodeAgentConfig,
    NodeAgentConfigError,
    load_config,
    save_config,
)
from olympus.node_agent.enroll import EnrollmentError, enroll
from olympus.node_agent.transport import open_session_channel
from olympus.nodes.capabilities import FILE_LIST, FILE_READ, FILE_WRITE, SYSTEM_INSPECT
from olympus.nodes.channel import ChannelClosed
from olympus.nodes.crypto import generate_node_keypair
from olympus.nodes.errors import NodeMeshError

# What this agent is *able* to serve. It is not what it may do: the control
# plane intersects this with the grant, and the scoped providers only come into
# existence when a scope arrives over the authenticated session. Declaring a
# capability with no grant behind it therefore gains the node nothing.
DEFAULT_CAPABILITIES: tuple[str, ...] = (
    SYSTEM_INSPECT.name,
    FILE_READ.name,
    FILE_LIST.name,
    FILE_WRITE.name,
)
MIN_BACKOFF_SECONDS = 2
MAX_BACKOFF_SECONDS = 60


def _detect_platform() -> str:
    system = platform.system().lower()
    return system if system in {"linux", "windows", "darwin"} else "unknown"


def _normalized_platform() -> str:
    detected = _detect_platform()
    return "macos" if detected == "darwin" else detected


def _providers(config: NodeAgentConfig, state_directory: Path) -> list[SystemInspectProvider]:
    return [
        SystemInspectProvider(
            state_directory=state_directory,
            agent_version=AGENT_VERSION,
        )
    ]


def _read_enrollment_credential(arguments: argparse.Namespace) -> str:
    """Prefer stdin so the credential never appears in the process argument list."""
    if arguments.enrollment_token_stdin:
        return sys.stdin.readline().strip()
    return str(arguments.enrollment_token or "")


def command_enroll(arguments: argparse.Namespace) -> int:
    """Redeem a single-use enrollment token and write the node's own key material."""
    config_path = Path(arguments.config)
    if config_path.exists() and not arguments.force:
        print(f"configuration already exists at {config_path}; pass --force to re-enroll")
        return 2
    credential = _read_enrollment_credential(arguments)
    if not credential:
        print("no enrollment token supplied")
        return 2
    keys = generate_node_keypair()
    try:
        outcome = enroll(
            control_plane_url=arguments.control_plane_url,
            enrollment_token=credential,
            public_key=keys.public_key,
            node_name=arguments.node_name,
            kind=arguments.kind,
            node_platform=_normalized_platform(),
            architecture=platform.machine() or "unknown",
            agent_version=AGENT_VERSION,
            declared_capabilities=DEFAULT_CAPABILITIES,
        )
    except EnrollmentError as exc:
        print(f"enrollment failed: {exc}")
        return 1
    save_config(
        config_path,
        NodeAgentConfig(
            version=CONFIG_VERSION,
            control_plane_url=arguments.control_plane_url,
            node_id=outcome.node_id,
            node_name=outcome.node_name,
            private_key=keys.private_key,
            control_plane_public_key=outcome.control_plane_public_key,
            control_plane_key_id=outcome.control_plane_key_id,
            session_path=outcome.session_path,
            capabilities=outcome.granted_capabilities,
        ),
    )
    print(f"enrolled {outcome.node_name} as {outcome.node_id}")
    print(f"granted capabilities: {', '.join(outcome.granted_capabilities) or 'none'}")
    return 0


def command_status(arguments: argparse.Namespace) -> int:
    """Print the local configuration with the private key redacted."""
    try:
        config = load_config(Path(arguments.config))
    except NodeAgentConfigError as exc:
        print(f"{exc}")
        return 1
    print(json.dumps(config.redacted(), indent=2, sort_keys=True))
    return 0


async def _serve(config: NodeAgentConfig, *, state_directory: Path, once: bool) -> int:
    identity = AgentIdentity(
        node_id=config.node_id,
        node_name=config.node_name,
        private_key=config.private_key,
        control_plane_public_key=config.control_plane_public_key,
        control_plane_key_id=config.control_plane_key_id,
    )
    # One agent for the lifetime of the process: its dedupe ledger is what makes
    # a job replay after a reconnect instead of running a second time, so
    # rebuilding it per attempt would silently discard exactly that guarantee.
    agent = NodeAgent(
        identity=identity,
        providers=_providers(config, state_directory),
        # fs.read and fs.write have no provider until the session delivers their
        # scope, so they are declared here rather than derived from providers.
        serves=(FILE_READ.name, FILE_LIST.name, FILE_WRITE.name),
        node_platform=_normalized_platform(),
        architecture=platform.machine() or "unknown",
    )
    backoff = MIN_BACKOFF_SECONDS
    while True:
        try:
            async with open_session_channel(config.session_url) as channel:
                print(f"connected to {config.session_url}")
                backoff = MIN_BACKOFF_SECONDS
                await agent.run(channel)
            print("control plane closed the session")
        except (ChannelClosed, NodeMeshError) as exc:
            print(f"session ended: {exc}")
        if once:
            return 0
        # Bounded exponential backoff with jitter so a restarting control plane
        # is not stampeded by every node at once.
        delay = min(backoff, MAX_BACKOFF_SECONDS) + secrets.randbelow(1000) / 1000
        print(f"reconnecting in {delay:.1f}s")
        await asyncio.sleep(delay)
        backoff = min(backoff * 2, MAX_BACKOFF_SECONDS)


def command_run(arguments: argparse.Namespace) -> int:
    """Maintain an outbound session and serve capability jobs until stopped."""
    try:
        config = load_config(Path(arguments.config))
    except NodeAgentConfigError as exc:
        print(f"{exc}")
        return 1
    state_directory = Path(arguments.state_directory or Path(arguments.config).parent)
    try:
        return asyncio.run(_serve(config, state_directory=state_directory, once=arguments.once))
    except KeyboardInterrupt:
        return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="olympus-node",
        description="Olympus execution-node agent. Connects outbound only.",
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    enrollment = subcommands.add_parser("enroll", help="redeem a single-use enrollment token")
    enrollment.add_argument("--control-plane-url", required=True)
    credential = enrollment.add_mutually_exclusive_group(required=True)
    credential.add_argument("--enrollment-token")
    credential.add_argument(
        "--enrollment-token-stdin",
        action="store_true",
        help="read the single-use enrollment token from the first line of stdin",
    )
    enrollment.add_argument("--node-name", required=True)
    enrollment.add_argument("--kind", default="workstation")
    enrollment.add_argument("--config", required=True)
    enrollment.add_argument("--force", action="store_true")
    enrollment.set_defaults(handler=command_enroll)

    run = subcommands.add_parser("run", help="serve capability jobs")
    run.add_argument("--config", required=True)
    run.add_argument("--state-directory", default=None)
    run.add_argument("--once", action="store_true")
    run.set_defaults(handler=command_run)

    status = subcommands.add_parser("status", help="print redacted local configuration")
    status.add_argument("--config", required=True)
    status.set_defaults(handler=command_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    handler = arguments.handler
    result: int = handler(arguments)
    return result


if __name__ == "__main__":
    sys.exit(main())
