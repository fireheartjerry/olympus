import json
import os
import stat
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

CONFIG_VERSION = 1
_SECRET_FILE_MODE = stat.S_IRUSR | stat.S_IWUSR


class NodeAgentConfigError(ValueError):
    """Raised when on-disk agent configuration is missing or unusable."""


@dataclass(frozen=True)
class NodeAgentConfig:
    """On-disk agent identity and connection settings.

    The private key lives only in this file, only on the node, with owner-only
    permissions. It is never transmitted and never written to the repository.
    """

    version: int
    control_plane_url: str
    node_id: str
    node_name: str
    private_key: str
    control_plane_public_key: str
    control_plane_key_id: str
    session_path: str = "/v1/nodes/session"
    capabilities: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.version != CONFIG_VERSION:
            raise NodeAgentConfigError("unsupported node agent configuration version")
        parts = urlsplit(self.control_plane_url)
        if parts.scheme not in {"http", "https"} or not parts.netloc:
            raise NodeAgentConfigError("control_plane_url must be an absolute http(s) URL")
        for name, value in (
            ("node_id", self.node_id),
            ("private_key", self.private_key),
            ("control_plane_public_key", self.control_plane_public_key),
        ):
            if not value.strip():
                raise NodeAgentConfigError(f"node agent configuration requires {name}")

    @property
    def session_url(self) -> str:
        """Return the outbound WebSocket URL this agent dials."""
        parts = urlsplit(self.control_plane_url)
        scheme = "wss" if parts.scheme == "https" else "ws"
        return f"{scheme}://{parts.netloc}{self.session_path}"

    def redacted(self) -> dict[str, object]:
        """Return a summary safe to print, log, or paste into a support thread."""
        summary = asdict(self)
        summary["private_key"] = "[redacted]"
        summary["capabilities"] = list(self.capabilities)
        return summary


def load_config(path: Path) -> NodeAgentConfig:
    """Read agent configuration, failing closed on anything unexpected."""
    if not path.exists():
        raise NodeAgentConfigError(f"no node agent configuration at {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise NodeAgentConfigError("node agent configuration is unreadable") from exc
    if not isinstance(raw, dict):
        raise NodeAgentConfigError("node agent configuration must be a JSON object")
    known = {field for field in NodeAgentConfig.__dataclass_fields__}
    unknown = set(raw) - known
    if unknown:
        raise NodeAgentConfigError(f"unknown configuration keys: {', '.join(sorted(unknown))}")
    capabilities = tuple(str(name) for name in raw.pop("capabilities", ()))
    return NodeAgentConfig(**raw, capabilities=capabilities)


def save_config(path: Path, config: NodeAgentConfig) -> None:
    """Write agent configuration atomically with owner-only permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(f"{path.suffix}.tmp")
    payload = asdict(config)
    payload["capabilities"] = list(config.capabilities)
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.chmod(temporary, _SECRET_FILE_MODE)
    temporary.replace(path)
