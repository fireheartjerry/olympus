"""Operator command line for the node mesh.

Everything the mesh can do was reachable only by hand-crafting HTTP with three
authority headers and a JSON body. That is not an operator surface; it is a
reason to write the request wrong at the moment it matters most — revoking a
node you believe is compromised.

Built on the standard library. An operator tool that cannot run because a
dependency is missing is worse than no tool, and this one has to work on a host
where something has already gone wrong.

**It grants nothing by itself.** Every command carries the commander id and
authority lease the gateway already requires, and the gateway is what decides.
This only makes the request well-formed.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class OperatorError(Exception):
    """Raised when a command cannot be completed as asked."""


def _headers(args: argparse.Namespace) -> dict[str, str]:
    token = args.token or os.environ.get("OLYMPUS_COMMAND_TOKEN", "")
    if not token:
        raise OperatorError(
            "no command token: pass --token or set OLYMPUS_COMMAND_TOKEN. "
            "Refusing to send an unauthenticated request rather than letting the "
            "gateway reject it and look like the mesh is down."
        )
    return {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "X-Olympus-Commander": args.commander,
        "X-Olympus-Authority-Lease": args.lease,
    }


def _call(args: argparse.Namespace, method: str, path: str, body: Any = None) -> Any:
    request = urllib.request.Request(  # noqa: S310 - operator-supplied base URL
        url=f"{args.base_url.rstrip('/')}{path}",
        method=method,
        headers=_headers(args),
        data=json.dumps(body).encode("utf-8") if body is not None else None,
    )
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:  # noqa: S310
            payload = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise OperatorError(f"{exc.code} {exc.reason}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise OperatorError(f"cannot reach {args.base_url}: {exc.reason}") from exc
    return json.loads(payload) if payload else None


def _parse_scope(values: list[str] | None) -> dict[str, dict[str, Any]]:
    """Turn ``fs.read@1=/srv/data,/var/log:65536`` into a scope object.

    A scope is the difference between granting a capability and handing over a
    machine, so it is expressible on the command line rather than requiring a
    JSON file nobody will write under pressure.
    """
    scopes: dict[str, dict[str, Any]] = {}
    for raw in values or []:
        capability, _, rest = raw.partition("=")
        if not capability or not rest:
            raise OperatorError(
                f"malformed --scope {raw!r}; expected CAPABILITY=ROOT[,ROOT][:BYTES]"
            )
        # Split off a trailing byte ceiling only when it is actually digits.
        # A Windows root carries a colon in its drive letter, so splitting on
        # the last colon unconditionally turns C:\olympus\share into the root
        # "C" with a nonsense ceiling — on the very platform these nodes run.
        head, separator, tail = rest.rpartition(":")
        if separator and tail.isdigit():
            roots_part, max_bytes = head, tail
        else:
            roots_part, max_bytes = rest, ""

        roots = [root.strip() for root in roots_part.split(",") if root.strip()]
        if not roots:
            raise OperatorError(f"--scope {raw!r} names no root")
        scope: dict[str, Any] = {"roots": roots}
        if max_bytes:
            scope["max_bytes"] = int(max_bytes)
        scopes[capability] = scope
    return scopes


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def command_list(args: argparse.Namespace) -> int:
    body = _call(args, "GET", "/v1/nodes")
    nodes = body.get("nodes", []) if isinstance(body, dict) else []
    if args.json:
        _print(body)
        return 0
    if not nodes:
        print("no nodes enrolled")
        return 0
    for node in nodes:
        print(f"{node['node_name']}  {node['node_id']}")
        print(f"  state      : {node['state']}  connected={node['connected']}")
        print(f"  granted    : {', '.join(node['granted_capabilities']) or '(none)'}")
        # Printed with the grant, not separately: a capability name without its
        # bound tells an operator the least useful half of what a node can do.
        for capability, scope in (node.get("capability_scopes") or {}).items():
            roots = ", ".join(scope.get("roots", []))
            print(f"    {capability} -> {roots} (max_bytes={scope.get('max_bytes')})")
    return 0


def command_grant(args: argparse.Namespace) -> int:
    scopes = _parse_scope(args.scope)
    body = _call(
        args,
        "POST",
        "/v1/nodes/enrollments",
        {
            "node_name": args.node_name,
            "kind": args.kind,
            "platform": args.platform,
            "capabilities": args.capability,
            "capability_scopes": scopes,
            **({"ttl_seconds": args.ttl} if args.ttl else {}),
        },
    )
    if args.json:
        _print(body)
        return 0
    print(f"enrollment token for {body['node_name']} (expires {body['expires_at']}):")
    print(f"  {body['enrollment_token']}")
    print("  granted:", ", ".join(body["granted_capabilities"]))
    for capability, scope in (body.get("capability_scopes") or {}).items():
        print(f"    {capability} -> {', '.join(scope.get('roots', []))}")
    # Said plainly because the operator is about to paste it somewhere.
    print("\nThis token is single use and is shown once. It is not stored.")
    return 0


def command_revoke(args: argparse.Namespace) -> int:
    _call(args, "POST", f"/v1/nodes/{args.node_id}/revoke", {"reason": args.reason})
    print(f"revoked {args.node_id}: in-flight work cancelled and the session closed")
    return 0


def command_quarantine(args: argparse.Namespace) -> int:
    _call(args, "POST", f"/v1/nodes/{args.node_id}/quarantine", {"reason": args.reason})
    print(f"quarantined {args.node_id}: in-flight work cancelled and the session closed")
    return 0


def command_freeze(args: argparse.Namespace) -> int:
    body = _call(args, "POST", "/v1/nodes/control/freeze", {"reason": args.reason})
    print(f"dispatch frozen at epoch {body.get('freeze_epoch')}; every job in flight was stopped")
    return 0


def command_audit(args: argparse.Namespace) -> int:
    body = _call(args, "GET", "/v1/nodes/audit")
    _print(body)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m olympus.operations.nodes_cli",
        description="Operator commands for the Olympus node mesh.",
    )
    parser.add_argument("--base-url", default=os.environ.get("OLYMPUS_GATEWAY", DEFAULT_BASE_URL))
    parser.add_argument("--commander", default=os.environ.get("OLYMPUS_COMMANDER", ""))
    parser.add_argument("--lease", default=os.environ.get("OLYMPUS_AUTHORITY_LEASE", ""))
    parser.add_argument("--token", default=None, help="defaults to OLYMPUS_COMMAND_TOKEN")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--json", action="store_true", help="print raw responses")

    sub = parser.add_subparsers(dest="command", required=True)

    listing = sub.add_parser("list", help="show every node, its state, and what it is bounded to")
    listing.set_defaults(handler=command_list)

    grant = sub.add_parser("grant", help="mint a single-use enrollment token")
    grant.add_argument("node_name")
    grant.add_argument("--capability", action="append", required=True)
    grant.add_argument(
        "--scope",
        action="append",
        help="CAPABILITY=ROOT[,ROOT][:MAX_BYTES], e.g. fs.read@1=/srv/data:65536",
    )
    grant.add_argument("--kind", default="workstation")
    grant.add_argument("--platform", default="windows")
    grant.add_argument("--ttl", type=int, default=None)
    grant.set_defaults(handler=command_grant)

    revoke = sub.add_parser("revoke", help="revoke a node and stop what it is doing")
    revoke.add_argument("node_id")
    revoke.add_argument("--reason", required=True)
    revoke.set_defaults(handler=command_revoke)

    quarantine = sub.add_parser("quarantine", help="quarantine a node and stop what it is doing")
    quarantine.add_argument("node_id")
    quarantine.add_argument("--reason", required=True)
    quarantine.set_defaults(handler=command_quarantine)

    freeze = sub.add_parser("freeze", help="stop all dispatch across the mesh")
    freeze.add_argument("--reason", required=True)
    freeze.set_defaults(handler=command_freeze)

    audit = sub.add_parser("audit", help="print the node-mesh audit chain")
    audit.set_defaults(handler=command_audit)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.commander or not args.lease:
        print(
            "commander id and authority lease are required (--commander/--lease or "
            "OLYMPUS_COMMANDER/OLYMPUS_AUTHORITY_LEASE)",
            file=sys.stderr,
        )
        return 2
    try:
        result: int = args.handler(args)
        return result
    except OperatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
